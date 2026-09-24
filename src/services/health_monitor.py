import threading
import time
import socket
import psutil
import os
from datetime import datetime
from src.services.redis_service import redis_cache, test_redis_connection
from src.utils.config_manager import MYSQL_CONFIG


MONITOR_KEY = 'phishing:monitor:status'
MONITOR_HISTORY = 'phishing:monitor:history'


class HealthMonitor:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if hasattr(self, '_initialized') and self._initialized:
            return
        self._initialized = True
        self._running = True
        self._monitor_thread = None
        self._start_monitor()

    def _start_monitor(self):
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True, name='health-monitor')
        self._monitor_thread.start()

    def _monitor_loop(self):
        while self._running:
            try:
                status = self._collect_status()
                redis_cache.set(MONITOR_KEY, status, expire=120)
                self._save_history(status)
            except Exception:
                pass
            time.sleep(30)

    def _save_history(self, status):
        from src.services.redis_service import get_redis
        r = get_redis()
        r.lpush(MONITOR_HISTORY, status)
        r.ltrim(MONITOR_HISTORY, 0, 143)

    def _collect_status(self):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        backend_status = self._check_backend()
        nginx_status = self._check_nginx()
        db_status = self._check_database()
        redis_status = self._check_redis()
        mail_status = self._check_mail_server()
        llm_status = self._check_llm()

        all_healthy = all([
            backend_status['status'] == 'online',
            nginx_status['status'] == 'online',
            db_status['status'] == 'online',
            redis_status['status'] == 'online'
        ])

        return {
            'timestamp': timestamp,
            'overall': 'healthy' if all_healthy else 'warning',
            'components': {
                'backend': backend_status,
                'nginx': nginx_status,
                'database': db_status,
                'redis': redis_status,
                'mail_server': mail_status,
                'llm': llm_status
            },
            'system': self._get_system_info()
        }

    def _check_backend(self):
        try:
            process_count = 0
            for proc in psutil.process_iter(['name', 'cmdline']):
                try:
                    cmdline = ' '.join(proc.info.get('cmdline') or [])
                    if 'python' in (proc.info.get('name') or '').lower() and 'main.py' in cmdline:
                        process_count += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            if process_count > 0:
                return {
                    'status': 'online',
                    'name': 'Flask Backend',
                    'detail': f'运行中 (PID进程数: {process_count})',
                    'port': 8080
                }
            return {
                'status': 'offline',
                'name': 'Flask Backend',
                'detail': '未检测到运行进程',
                'port': 8080
            }
        except Exception as e:
            return {
                'status': 'offline',
                'name': 'Flask Backend',
                'detail': f'检测失败: {str(e)}',
                'port': 8080
            }

    def _check_nginx(self):
        try:
            process_count = 0
            for proc in psutil.process_iter(['name']):
                try:
                    if 'nginx' in (proc.info.get('name') or '').lower():
                        process_count += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            if process_count > 0:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex(('127.0.0.1', 80))
                sock.close()
                
                if result == 0:
                    return {
                        'status': 'online',
                        'name': 'Nginx Proxy',
                        'detail': f'运行中 (进程数: {process_count}) | 监听端口: 80',
                        'port': 80
                    }
                return {
                    'status': 'online',
                    'name': 'Nginx Proxy',
                    'detail': f'运行中 (进程数: {process_count}) | 端口80未监听',
                    'port': 80
                }
            return {
                'status': 'offline',
                'name': 'Nginx Proxy',
                'detail': '未检测到运行进程',
                'port': 80
            }
        except Exception as e:
            return {
                'status': 'offline',
                'name': 'Nginx Proxy',
                'detail': f'检测失败: {str(e)}',
                'port': 80
            }

    def _check_database(self):
        try:
            import pymysql
            conn = pymysql.connect(
                host=MYSQL_CONFIG['host'],
                port=MYSQL_CONFIG['port'],
                user=MYSQL_CONFIG['username'],
                password=MYSQL_CONFIG['password'],
                database=MYSQL_CONFIG['database_name'],
                connect_timeout=5
            )
            with conn.cursor() as cursor:
                cursor.execute('SELECT 1')
                result = cursor.fetchone()
            conn.close()
            if result:
                return {
                    'status': 'online',
                    'name': 'MySQL Database',
                    'detail': 'phishing_agent@localhost:3306',
                    'type': 'MySQL 8.0'
                }
            return {
                'status': 'offline',
                'name': 'MySQL Database',
                'detail': '无法获取数据库连接'
            }
        except Exception as e:
            return {
                'status': 'offline',
                'name': 'MySQL Database',
                'detail': f'连接失败: {str(e)[:100]}'
            }

    def _check_redis(self):
        result = test_redis_connection()
        result['name'] = 'Redis Cache'
        if result['status'] == 'online':
            result['detail'] = f"v{result.get('version', '?')} | 内存: {result.get('used_memory_human', '?')} | 连接数: {result.get('connected_clients', '?')}"
        else:
            result['detail'] = result.get('error', '连接失败')
        return result

    def _check_mail_server(self):
        try:
            import pymysql
            conn = pymysql.connect(
                host=MYSQL_CONFIG['host'],
                port=MYSQL_CONFIG['port'],
                user=MYSQL_CONFIG['username'],
                password=MYSQL_CONFIG['password'],
                database=MYSQL_CONFIG['database_name'],
                connect_timeout=5
            )
            with conn.cursor(pymysql.cursors.DictCursor) as cursor:
                cursor.execute('SELECT email, imap_server, imap_port, imap_ssl, password FROM mail_server_config WHERE is_active = 1 LIMIT 1')
                server = cursor.fetchone()
            conn.close()

            if not server:
                return {
                    'status': 'unknown',
                    'name': 'Mail Server',
                    'detail': '未配置邮件服务器'
                }

            import imaplib
            try:
                if server['imap_ssl']:
                    imap = imaplib.IMAP4_SSL(server['imap_server'], server['imap_port'])
                else:
                    imap = imaplib.IMAP4(server['imap_server'], server['imap_port'])
                imap.login(server['email'], server['password'])
                imap.logout()
                return {
                    'status': 'online',
                    'name': 'Mail Server (IMAP)',
                    'detail': f'{server["email"]}@{server["imap_server"]}:{server["imap_port"]}'
                }
            except Exception as e:
                return {
                    'status': 'offline',
                    'name': 'Mail Server (IMAP)',
                    'detail': f'{server["email"]} - 连接失败: {str(e)[:80]}'
                }
        except Exception as e:
            return {
                'status': 'unknown',
                'name': 'Mail Server',
                'detail': f'检测异常: {str(e)[:80]}'
            }

    def _check_llm(self):
        try:
            import pymysql
            conn = pymysql.connect(
                host=MYSQL_CONFIG['host'],
                port=MYSQL_CONFIG['port'],
                user=MYSQL_CONFIG['username'],
                password=MYSQL_CONFIG['password'],
                database=MYSQL_CONFIG['database_name'],
                connect_timeout=5
            )
            with conn.cursor(pymysql.cursors.DictCursor) as cursor:
                cursor.execute('SELECT name, model_name FROM llm_config WHERE is_active = 1 LIMIT 1')
                config = cursor.fetchone()
            conn.close()

            if not config:
                return {
                    'status': 'unknown',
                    'name': 'LLM API',
                    'detail': '未配置大模型'
                }
            return {
                'status': 'online',
                'name': 'LLM API',
                'detail': f"{config['name']} ({config['model_name']})"
            }
        except Exception as e:
            return {
                'status': 'unknown',
                'name': 'LLM API',
                'detail': f'检测异常: {str(e)[:80]}'
            }

    def _get_system_info(self):
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')

            return {
                'cpu_percent': round(cpu_percent, 1),
                'cpu_count': psutil.cpu_count(),
                'memory_total': round(memory.total / 1024 / 1024 / 1024, 1),
                'memory_used': round(memory.used / 1024 / 1024 / 1024, 1),
                'memory_percent': round(memory.percent, 1),
                'disk_total': round(disk.total / 1024 / 1024 / 1024, 1),
                'disk_used': round(disk.used / 1024 / 1024 / 1024, 1),
                'disk_percent': round(disk.used / disk.total * 100, 1)
            }
        except Exception:
            return {}

    def get_status(self):
        cached = redis_cache.get(MONITOR_KEY)
        if cached:
            if isinstance(cached, str):
                import json
                return json.loads(cached)
            return cached
        return self._collect_status()

    def get_history(self):
        from src.services.redis_service import get_redis
        import json
        r = get_redis()
        data = r.lrange(MONITOR_HISTORY, 0, 23)
        result = []
        for item in reversed(data):
            try:
                if isinstance(item, str):
                    result.append(json.loads(item))
                else:
                    result.append(item)
            except Exception:
                continue
        return result

    def stop(self):
        self._running = False


health_monitor = HealthMonitor()
