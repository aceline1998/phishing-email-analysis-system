import os
from dotenv import load_dotenv
from src.utils.config_manager import load_config

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
LOG_DIR = os.path.join(BASE_DIR, 'logs')

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

sys_config = load_config()

SECRET_KEY = sys_config.get('app', {}).get('secret_key', 'phishing-agent-secret-key')
SQLALCHEMY_TRACK_MODIFICATIONS = False

DEEPSEEK_API_BASE_URL = 'https://api.deepseek.com/v1'
DEEPSEEK_DEFAULT_MODEL = 'deepseek-chat'

IMAP_DEFAULT_PORT = 993
SMTP_DEFAULT_PORT = 465

AUTO_CHECK_INTERVAL = sys_config.get('app', {}).get('auto_check_interval', 300)