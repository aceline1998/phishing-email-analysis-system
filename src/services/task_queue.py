import threading
import time
import uuid
import json
from datetime import datetime
from enum import Enum
from concurrent.futures import ThreadPoolExecutor
from src.services.redis_service import redis_cache, get_redis


class TaskStatus(Enum):
    PENDING = 'pending'
    RUNNING = 'running'
    COMPLETED = 'completed'
    FAILED = 'failed'
    CANCELLED = 'cancelled'


class TaskPriority(Enum):
    HIGH = 0
    NORMAL = 1
    LOW = 2


TASK_PREFIX = 'phishing:task:'
TASK_QUEUE_ANALYSIS = 'phishing:queue:analysis'
TASK_QUEUE_REPLY = 'phishing:queue:reply'
TASK_STATUS_KEY = 'phishing:task:status'
TASK_LIST_KEY = 'phishing:task:list'


class Task:
    def __init__(self, task_type, payload, priority=TaskPriority.NORMAL, callback=None):
        self.id = str(uuid.uuid4())
        self.task_type = task_type
        self.payload = payload
        self.priority = priority
        self.status = TaskStatus.PENDING
        self.result = None
        self.error = None
        self.created_at = datetime.now()
        self.started_at = None
        self.completed_at = None
        self.callback = callback
        self.retry_count = 0
        self.max_retries = 3

    def to_dict(self):
        return {
            'id': self.id,
            'task_type': self.task_type,
            'status': self.status.value,
            'priority': self.priority.name,
            'retry_count': self.retry_count,
            'error': self.error,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None,
            'started_at': self.started_at.strftime('%Y-%m-%d %H:%M:%S') if self.started_at else None,
            'completed_at': self.completed_at.strftime('%Y-%m-%d %H:%M:%S') if self.completed_at else None
        }

    def to_storage(self):
        return json.dumps({
            'id': self.id,
            'task_type': self.task_type,
            'payload': self.payload,
            'priority': self.priority.value,
            'priority_name': self.priority.name,
            'status': self.status.value,
            'result': self.result,
            'error': self.error,
            'retry_count': self.retry_count,
            'max_retries': self.max_retries,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None,
            'started_at': self.started_at.strftime('%Y-%m-%d %H:%M:%S') if self.started_at else None,
            'completed_at': self.completed_at.strftime('%Y-%m-%d %H:%M:%S') if self.completed_at else None
        }, ensure_ascii=False)

    @classmethod
    def from_storage(cls, data_str):
        data = json.loads(data_str)
        task = cls.__new__(cls)
        task.id = data['id']
        task.task_type = data['task_type']
        task.payload = data['payload']
        task.priority = TaskPriority(data['priority'])
        task.status = TaskStatus(data['status'])
        task.result = data.get('result')
        task.error = data.get('error')
        task.retry_count = data.get('retry_count', 0)
        task.max_retries = data.get('max_retries', 3)
        task.callback = None
        task.created_at = datetime.strptime(data['created_at'], '%Y-%m-%d %H:%M:%S') if data.get('created_at') else None
        task.started_at = datetime.strptime(data['started_at'], '%Y-%m-%d %H:%M:%S') if data.get('started_at') else None
        task.completed_at = datetime.strptime(data['completed_at'], '%Y-%m-%d %H:%M:%S') if data.get('completed_at') else None
        return task


class TaskQueue:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, analysis_workers=3, reply_workers=2):
        if hasattr(self, '_initialized') and self._initialized:
            return
        self._initialized = True

        self.analysis_workers = analysis_workers
        self.reply_workers = reply_workers

        self._analysis_executor = ThreadPoolExecutor(max_workers=analysis_workers, thread_name_prefix='analysis')
        self._reply_executor = ThreadPoolExecutor(max_workers=reply_workers, thread_name_prefix='reply')

        self._running = True
        self._handlers = {}
        self._app = None

        self._start_workers()

    def set_app(self, app):
        self._app = app

    def _start_workers(self):
        for i in range(self.analysis_workers):
            t = threading.Thread(target=self._analysis_worker, daemon=True, name=f'analysis-worker-{i}')
            t.start()
        for i in range(self.reply_workers):
            t = threading.Thread(target=self._reply_worker, daemon=True, name=f'reply-worker-{i}')
            t.start()

    def register_handler(self, task_type, handler):
        self._handlers[task_type] = handler

    def submit_analysis(self, payload, priority=TaskPriority.NORMAL, callback=None):
        task = Task('analysis', payload, priority, callback)
        self._store_task(task)
        self._enqueue_task(TASK_QUEUE_ANALYSIS, task, priority)
        return task

    def submit_reply(self, payload, priority=TaskPriority.NORMAL, callback=None):
        task = Task('reply', payload, priority, callback)
        self._store_task(task)
        self._enqueue_task(TASK_QUEUE_REPLY, task, priority)
        return task

    def _store_task(self, task):
        redis_cache.set(f'{TASK_PREFIX}{task.id}', task.to_storage(), expire=86400)
        r = get_redis()
        r.lpush(TASK_LIST_KEY, task.id)
        r.ltrim(TASK_LIST_KEY, 0, 499)

    def _enqueue_task(self, queue_name, task, priority):
        score = priority.value + time.time() / 1e10
        r = get_redis()
        r.zadd(queue_name, {task.id: score})

    def _dequeue_task(self, queue_name):
        r = get_redis()
        result = r.zpopmin(queue_name, 1)
        if not result:
            return None
        task_id = result[0][0]
        data = redis_cache.get(f'{TASK_PREFIX}{task_id}')
        if not data:
            return None
        if isinstance(data, str):
            return Task.from_storage(data)
        return Task.from_storage(json.dumps(data, ensure_ascii=False))

    def _update_task(self, task):
        redis_cache.set(f'{TASK_PREFIX}{task.id}', task.to_storage(), expire=86400)

    def _analysis_worker(self):
        while self._running:
            try:
                task = self._dequeue_task(TASK_QUEUE_ANALYSIS)
                if not task:
                    time.sleep(0.5)
                    continue

                handler = self._handlers.get('analysis')
                if not handler:
                    task.status = TaskStatus.FAILED
                    task.error = 'No analysis handler registered'
                    task.completed_at = datetime.now()
                    self._update_task(task)
                    continue

                task.status = TaskStatus.RUNNING
                task.started_at = datetime.now()
                self._update_task(task)

                try:
                    if self._app:
                        with self._app.app_context():
                            result = handler(task.payload)
                    else:
                        result = handler(task.payload)
                    task.result = result
                    task.status = TaskStatus.COMPLETED
                except Exception as e:
                    import traceback
                    print(f"[TaskQueue] Analysis task {task.id} failed (attempt {task.retry_count + 1}): {e}")
                    traceback.print_exc()
                    task.retry_count += 1
                    if task.retry_count < task.max_retries:
                        task.status = TaskStatus.PENDING
                        self._update_task(task)
                        time.sleep(1)
                        self._enqueue_task(TASK_QUEUE_ANALYSIS, task, task.priority)
                        continue
                    task.status = TaskStatus.FAILED
                    task.error = str(e)

                task.completed_at = datetime.now()
                self._update_task(task)

                if task.callback:
                    try:
                        if self._app:
                            with self._app.app_context():
                                task.callback(task)
                        else:
                            task.callback(task)
                    except Exception:
                        pass

            except Exception:
                time.sleep(1)

    def _reply_worker(self):
        while self._running:
            try:
                task = self._dequeue_task(TASK_QUEUE_REPLY)
                if not task:
                    time.sleep(0.5)
                    continue

                handler = self._handlers.get('reply')
                if not handler:
                    task.status = TaskStatus.FAILED
                    task.error = 'No reply handler registered'
                    task.completed_at = datetime.now()
                    self._update_task(task)
                    continue

                task.status = TaskStatus.RUNNING
                task.started_at = datetime.now()
                self._update_task(task)

                try:
                    if self._app:
                        with self._app.app_context():
                            result = handler(task.payload)
                    else:
                        result = handler(task.payload)
                    task.result = result
                    task.status = TaskStatus.COMPLETED
                except Exception as e:
                    import traceback
                    print(f"[TaskQueue] Reply task {task.id} failed (attempt {task.retry_count + 1}): {e}")
                    traceback.print_exc()
                    task.retry_count += 1
                    if task.retry_count < task.max_retries:
                        task.status = TaskStatus.PENDING
                        self._update_task(task)
                        time.sleep(1)
                        self._enqueue_task(TASK_QUEUE_REPLY, task, task.priority)
                        continue
                    task.status = TaskStatus.FAILED
                    task.error = str(e)

                task.completed_at = datetime.now()
                self._update_task(task)

                if task.callback:
                    try:
                        if self._app:
                            with self._app.app_context():
                                task.callback(task)
                        else:
                            task.callback(task)
                    except Exception:
                        pass

            except Exception:
                time.sleep(1)

    def get_task(self, task_id):
        data = redis_cache.get(f'{TASK_PREFIX}{task_id}')
        if not data:
            return None
        if isinstance(data, str):
            return Task.from_storage(data)
        return Task.from_storage(json.dumps(data, ensure_ascii=False))

    def get_status(self):
        r = get_redis()
        analysis_queue_size = r.zcard(TASK_QUEUE_ANALYSIS)
        reply_queue_size = r.zcard(TASK_QUEUE_REPLY)

        task_ids = r.lrange(TASK_LIST_KEY, 0, 499)
        pending = 0
        running = 0
        completed = 0
        failed = 0

        for tid in task_ids:
            data = redis_cache.get(f'{TASK_PREFIX}{tid}')
            if not data:
                continue
            try:
                if isinstance(data, str):
                    d = json.loads(data)
                else:
                    d = data
                status = d.get('status', '')
                if status == 'pending':
                    pending += 1
                elif status == 'running':
                    running += 1
                elif status == 'completed':
                    completed += 1
                elif status == 'failed':
                    failed += 1
            except Exception:
                continue

        return {
            'analysis_workers': self.analysis_workers,
            'reply_workers': self.reply_workers,
            'analysis_queue_size': analysis_queue_size,
            'reply_queue_size': reply_queue_size,
            'total_tasks': len(task_ids),
            'pending': pending,
            'running': running,
            'completed': completed,
            'failed': failed
        }

    def get_recent_tasks(self, limit=20):
        r = get_redis()
        task_ids = r.lrange(TASK_LIST_KEY, 0, limit - 1)
        tasks = []
        for tid in task_ids:
            data = redis_cache.get(f'{TASK_PREFIX}{tid}')
            if not data:
                continue
            try:
                if isinstance(data, str):
                    d = json.loads(data)
                else:
                    d = data
                tasks.append({
                    'id': d.get('id', tid),
                    'task_type': d.get('task_type', ''),
                    'status': d.get('status', ''),
                    'priority': TaskPriority(d.get('priority', 1)).name,
                    'retry_count': d.get('retry_count', 0),
                    'error': d.get('error'),
                    'created_at': d.get('created_at', ''),
                    'started_at': d.get('started_at'),
                    'completed_at': d.get('completed_at')
                })
            except Exception:
                continue
        return tasks

    def _task_to_dict(self, task):
        return task.to_dict()

    def update_worker_count(self, analysis_workers=None, reply_workers=None):
        if analysis_workers is not None:
            self.analysis_workers = analysis_workers
        if reply_workers is not None:
            self.reply_workers = reply_workers

    def shutdown(self):
        self._running = False
        self._analysis_executor.shutdown(wait=False)
        self._reply_executor.shutdown(wait=False)


task_queue = TaskQueue()
