import redis
import json
import os
import threading
from datetime import datetime

# 加载 .env 环境变量（部署时用于覆盖Redis配置）
try:
    from dotenv import load_dotenv
    _base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    load_dotenv(os.path.join(_base_dir, '.env'))
except ImportError:
    pass

REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD", "1qaz@WSX") or None
REDIS_DB = int(os.environ.get("REDIS_DB", "0"))

_pool = None
_pool_lock = threading.Lock()


def get_redis_pool():
    global _pool
    if _pool is None:
        with _pool_lock:
            if _pool is None:
                _pool = redis.ConnectionPool(
                    host=REDIS_HOST,
                    port=REDIS_PORT,
                    password=REDIS_PASSWORD,
                    db=REDIS_DB,
                    decode_responses=True,
                    max_connections=50
                )
    return _pool


def get_redis():
    return redis.Redis(connection_pool=get_redis_pool())


def test_redis_connection():
    try:
        r = get_redis()
        r.ping()
        info = r.info()
        return {
            'status': 'online',
            'version': info.get('redis_version', 'unknown'),
            'used_memory_human': info.get('used_memory_human', 'unknown'),
            'connected_clients': info.get('connected_clients', 0),
            'uptime_days': info.get('uptime_in_days', 0)
        }
    except Exception as e:
        return {
            'status': 'offline',
            'error': str(e)
        }


class RedisCache:
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
        self._r = get_redis()

    def set(self, key, value, expire=None):
        if isinstance(value, (dict, list)):
            value = json.dumps(value, ensure_ascii=False, default=str)
        self._r.set(key, value, ex=expire)

    def get(self, key, default=None):
        val = self._r.get(key)
        if val is None:
            return default
        try:
            return json.loads(val)
        except (json.JSONDecodeError, TypeError):
            return val

    def delete(self, key):
        self._r.delete(key)

    def exists(self, key):
        return self._r.exists(key)

    def incr(self, key, amount=1):
        return self._r.incr(key, amount)

    def expire(self, key, seconds):
        self._r.expire(key, seconds)

    def hset(self, name, key, value):
        if isinstance(value, (dict, list)):
            value = json.dumps(value, ensure_ascii=False, default=str)
        self._r.hset(name, key, value)

    def hget(self, name, key, default=None):
        val = self._r.hget(name, key)
        if val is None:
            return default
        try:
            return json.loads(val)
        except (json.JSONDecodeError, TypeError):
            return val

    def hgetall(self, name):
        return self._r.hgetall(name)

    def hdel(self, name, *keys):
        self._r.hdel(name, *keys)

    def lpush(self, name, *values):
        for i, v in enumerate(values):
            if isinstance(v, (dict, list)):
                values = list(values)
                values[i] = json.dumps(v, ensure_ascii=False, default=str)
        return self._r.lpush(name, *values)

    def rpop(self, name):
        val = self._r.rpop(name)
        if val is None:
            return None
        try:
            return json.loads(val)
        except (json.JSONDecodeError, TypeError):
            return val

    def llen(self, name):
        return self._r.llen(name)

    def zadd(self, name, mapping):
        self._r.zadd(name, mapping)

    def zpopmin(self, name, count=1):
        return self._r.zpopmin(name, count)

    def zcard(self, name):
        return self._r.zcard(name)

    def keys(self, pattern='*'):
        return self._r.keys(pattern)


redis_cache = RedisCache()
