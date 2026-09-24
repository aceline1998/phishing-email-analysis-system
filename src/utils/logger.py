import logging
import os
from datetime import datetime

from config import LOG_DIR


def setup_logger(name='phishing_agent'):
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)

    log_file = os.path.join(LOG_DIR, f'{name}_{datetime.now().strftime("%Y%m%d")}.log')

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    if logger.handlers:
        return logger

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger