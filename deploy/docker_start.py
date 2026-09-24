# -*- coding: utf-8 -*-
"""Docker 容器启动入口：绑定 0.0.0.0:8080（容器内 IPv6 可能不可用）"""
from src.api.app import create_app, start_scheduler
from werkzeug.serving import make_server

app = create_app()
start_scheduler(app)

server = make_server('0.0.0.0', 8080, app, threaded=True)
server.serve_forever()
