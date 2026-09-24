import json
import os
from urllib.parse import quote

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CONFIG_FILE = os.path.join(BASE_DIR, 'data', 'sys_config.json')

# 加载 .env 环境变量（部署时用于覆盖数据库/Redis配置，未设置时使用默认值）
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(BASE_DIR, '.env'))
except ImportError:
    pass

# MySQL数据库配置（可通过环境变量覆盖，默认值保持不变）
MYSQL_CONFIG = {
    "host": os.environ.get("MYSQL_HOST", "localhost"),
    "port": int(os.environ.get("MYSQL_PORT", "3306")),
    "username": os.environ.get("MYSQL_USER", "root"),
    "password": os.environ.get("MYSQL_PASSWORD", "1qaz@WSX"),
    "database_name": os.environ.get("MYSQL_DATABASE", "phishing_agent"),
    "charset": os.environ.get("MYSQL_CHARSET", "utf8mb4")
}

DEFAULT_CONFIG = {
    "database": {
        "type": "mysql",
        "host": MYSQL_CONFIG["host"],
        "port": MYSQL_CONFIG["port"],
        "username": MYSQL_CONFIG["username"],
        "password": MYSQL_CONFIG["password"],
        "database_name": MYSQL_CONFIG["database_name"],
        "charset": MYSQL_CONFIG["charset"]
    },
    "app": {
            "secret_key": "phishing-agent-secret-key-change-me",
            "auto_check_interval": 60
        }
}


def load_config():
    # 始终返回硬编码的MySQL配置
    config = DEFAULT_CONFIG.copy()
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                saved_config = json.load(f)
            # 只合并app配置，数据库配置使用硬编码
            if 'app' in saved_config:
                config['app'] = saved_config['app']
        except Exception:
            pass
    return config


def save_config(config):
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    # 保存时保持数据库配置为硬编码值
    config['database'] = DEFAULT_CONFIG['database'].copy()
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    return True


def get_db_uri():
    # 使用硬编码的MySQL配置
    host = MYSQL_CONFIG["host"]
    port = MYSQL_CONFIG["port"]
    username = MYSQL_CONFIG["username"]
    password = quote(MYSQL_CONFIG["password"], safe='')  # URL编码密码
    db_name = MYSQL_CONFIG["database_name"]
    charset = MYSQL_CONFIG["charset"]
    return f"mysql+pymysql://{username}:{password}@{host}:{port}/{db_name}?charset={charset}"


def is_db_configured():
    return True