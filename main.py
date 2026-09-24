from src.api.app import create_app, start_scheduler
import socket
import threading
import time

app = create_app()

def run_server():
    from werkzeug.serving import make_server
    server = make_server('::', 8080, app, threaded=True)
    print('Server listening on both IPv4 and IPv6 at port 8080')
    server.serve_forever()

if __name__ == '__main__':
    start_scheduler(app)
    run_server()