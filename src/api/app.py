from flask import Flask, jsonify, request, render_template
from flask_cors import CORS
from src.models.db import db
from src.utils.config_manager import get_db_uri, load_config
from src.services.db_migration_service import check_and_migrate, auto_migrate_columns, auto_migrate_column_types
import os
import threading
import time
import signal
import sys
import json
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

scheduler_running = False
scheduler_thread = None
current_interval = 600
# 用于通知 scheduler 间隔变更（无需等待当前 sleep 结束）
scheduler_event = None


def create_app():
    app = Flask(__name__,
                template_folder=os.path.join(BASE_DIR, 'src', 'templates'),
                static_folder=os.path.join(BASE_DIR, 'src', 'static'))

    app.config['SQLALCHEMY_DATABASE_URI'] = get_db_uri()
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    secret_key_file = os.path.join(BASE_DIR, '.secret_key')
    if os.path.exists(secret_key_file):
        with open(secret_key_file, 'rb') as f:
            secret_key = f.read()
    else:
        secret_key = os.urandom(24)
        with open(secret_key_file, 'wb') as f:
            f.write(secret_key)
    app.config['SECRET_KEY'] = secret_key

    CORS(app)
    db.init_app(app)

    from src.services.task_queue import task_queue
    task_queue.set_app(app)

    with app.app_context():
        from src.models.db import ThreatIntelConfig, ThreatIntelRecord, ChatConversation, ChatMessage, VersionInfo, AuditLog, EmailRecord, MailServerConfig, AnalysisResult, ReplyTemplate, ReplyRecord, PipelineConfig, FoxmailConfig, AnalysisCorrection, EmailSignature
        db.create_all()
        auto_migrate_columns(app)
        auto_migrate_column_types(app)
        _init_default_data()
        migration_result = check_and_migrate(app)
        if migration_result:
            print(f"Database migration result: {migration_result}")

    from src.api.routes import api_bp
    app.register_blueprint(api_bp, url_prefix='/api')

    @app.errorhandler(404)
    def not_found(error):
        if request.path.startswith('/api/'):
            return jsonify({'error': '接口不存在'}), 404
        return render_template('login.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        if request.path.startswith('/api/'):
            return jsonify({'error': '服务器内部错误: ' + str(error)}), 500
        return render_template('login.html'), 500

    @app.errorhandler(403)
    def forbidden(error):
        if request.path.startswith('/api/'):
            return jsonify({'error': '权限不足'}), 403
        return render_template('login.html'), 403

    @app.errorhandler(400)
    def bad_request(error):
        if request.path.startswith('/api/'):
            return jsonify({'error': '请求参数错误'}), 400
        return render_template('login.html'), 400

    @app.route('/login')
    def login_page():
        from flask import render_template
        return render_template('login.html')

    @app.route('/')
    def index():
        from flask import render_template
        return render_template('index.html')

    @app.route('/config')
    def config_page():
        from flask import render_template, session, redirect, url_for
        if 'role' not in session or session['role'] != 'admin':
            return redirect(url_for('index'))
        import socket
        ipv4_addresses = []
        ipv6_addresses = []
        try:
            for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_UNSPEC):
                family, _, _, _, sockaddr = info
                ip = sockaddr[0]
                if family == socket.AF_INET and ip not in ipv4_addresses:
                    ipv4_addresses.append(ip)
                elif family == socket.AF_INET6 and ip not in ipv6_addresses:
                    ipv6_addresses.append(ip)
        except Exception:
            pass
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.connect(('8.8.8.8', 80))
            local_ip = sock.getsockname()[0]
            sock.close()
            if local_ip not in ipv4_addresses:
                ipv4_addresses.insert(0, local_ip)
        except Exception:
            pass
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.connect(('2001:4860:4860::8888', 80))
            local_ip6 = sock.getsockname()[0]
            sock.close()
            if local_ip6 not in ipv6_addresses:
                ipv6_addresses.insert(0, local_ip6)
        except Exception:
            pass
        hostname = socket.gethostname()
        ipv4_addresses = sorted(set(ipv4_addresses))
        ipv6_addresses = sorted(set(ipv6_addresses))
        return render_template('config.html',
            server_hostname=hostname,
            server_ipv4=ipv4_addresses,
            server_ipv6=ipv6_addresses)

    @app.route('/emails')
    def emails_page():
        from flask import render_template
        return render_template('emails.html')

    @app.route('/email/<int:id>')
    def email_detail_page(id):
        from flask import render_template
        return render_template('email_detail.html')

    @app.route('/templates')
    def templates_page():
        from flask import render_template
        return render_template('templates.html')

    @app.route('/situation')
    def situation_page():
        from flask import render_template
        return render_template('situation.html')

    @app.route('/statistics')
    def statistics_page():
        from flask import render_template
        return render_template('statistics.html')

    @app.route('/analysis-records')
    def analysis_records_page():
        from flask import render_template
        return render_template('analysis_records.html')

    @app.route('/threat-intel')
    def threat_intel_page():
        from flask import render_template
        return render_template('threat_intel.html')

    @app.route('/version')
    def version_page():
        from flask import render_template
        return render_template('version.html')

    @app.route('/audit')
    def audit_page():
        from flask import render_template
        return render_template('audit.html')

    @app.route('/chat')
    def chat_page():
        from flask import render_template
        return render_template('chat.html')

    @app.route('/task-queue')
    def task_queue_page():
        from flask import render_template
        return render_template('task_queue.html')

    @app.route('/restart')
    def restart_page():
        def do_restart():
            time.sleep(1)
            os.kill(os.getpid(), signal.SIGINT)
        thread = threading.Thread(target=do_restart)
        thread.daemon = True
        thread.start()
        return "服务正在重启..."

    return app


def start_scheduler(app):
    global scheduler_running, scheduler_thread, current_interval, scheduler_event
    if scheduler_running:
        return

    import threading
    scheduler_event = threading.Event()

    def scheduler_loop():
        global scheduler_running, current_interval, scheduler_event
        scheduler_running = True
        # 启动时立即执行一次（不等满间隔）
        try:
            with app.app_context():
                _auto_fetch_emails()
        except Exception as e:
            print(f"Scheduler initial fetch error: {e}")

        while scheduler_running:
            try:
                config = load_config()
                new_interval = config.get('app', {}).get('auto_check_interval', 300)
                if new_interval != current_interval:
                    current_interval = new_interval

                # 0 表示禁用自动收取
                if current_interval <= 0:
                    print("Auto fetch is disabled (interval=0)")
                    if scheduler_event.wait(timeout=10):
                        scheduler_event.clear()
                    continue

                # 使用可中断的等待（最多 1 秒粒度）
                elapsed = 0
                while elapsed < current_interval and scheduler_running:
                    remaining = min(1, current_interval - elapsed)
                    if scheduler_event.wait(timeout=remaining):
                        # 收到变更事件，退出等待循环
                        scheduler_event.clear()
                        break
                    elapsed += 1

                if not scheduler_running:
                    break

                with app.app_context():
                    _auto_fetch_emails()
            except Exception as e:
                print(f"Scheduler error: {e}")
                # 出错后等待 10 秒再试
                if scheduler_event.wait(timeout=10):
                    scheduler_event.clear()

    scheduler_thread = threading.Thread(target=scheduler_loop)
    scheduler_thread.daemon = True
    scheduler_thread.start()


def notify_scheduler_interval_change():
    """外部调用此函数通知 scheduler 间隔已变更，立即生效"""
    global scheduler_event
    if scheduler_event is not None:
        scheduler_event.set()


def stop_scheduler():
    global scheduler_running, scheduler_thread
    scheduler_running = False
    if scheduler_event:
        scheduler_event.set()  # 唤醒 sleep
    if scheduler_thread:
        scheduler_thread.join(timeout=5)
        scheduler_thread = None


def _auto_fetch_emails():
    """自动同步邮件服务器（IMAP/POP3）的收件箱，并自动分析所有待处理邮件"""
    import traceback
    try:
        from src.models.db import MailServerConfig, EmailRecord
        from src.services.email_service import EmailService
        from src.services.email_pipeline import email_pipeline

        before_ids = set(e.id for e in EmailRecord.query.with_entities(EmailRecord.id).all())
        new_ids = []

        server = MailServerConfig.query.filter_by(is_active=True).first()
        if server:

            service = EmailService(server)
            result = service.fetch_new_emails()
            after_ids = set(e.id for e in EmailRecord.query.with_entities(EmailRecord.id).all())
            new_ids.extend(list(after_ids - before_ids))
            if result.get('success') and len(new_ids) > 0:
                print(f"Auto fetch: {result.get('message', 'no message')}")
        else:
            print("Auto fetch skipped: no active mail server configured")

        # 自动分析：新邮件 + 所有待处理邮件
        try:
            pipeline_config = email_pipeline.get_config()
            if pipeline_config.get('auto_analyze', False):
                pending_emails = EmailRecord.query.filter_by(status='pending').with_entities(EmailRecord.id).all()
                analyze_ids = list(set(e.id for e in pending_emails))
                if analyze_ids:
                    tasks = email_pipeline.auto_process_new_emails(analyze_ids)
                    print(f"Auto analyze: {len(analyze_ids)} emails submitted")
            else:
                print("Auto analyze is disabled in pipeline config")
        except Exception as pipe_err:
            print(f"Auto analyze error: {pipe_err}")
            traceback.print_exc()
    except Exception as e:
        print(f"Auto fetch emails error: {e}")
        traceback.print_exc()


def _init_default_data():
    from src.services.auth_service import init_admin
    init_admin()
    from src.models.db import ReplyTemplate, PipelineConfig, SecurityAdviceConfig
    
    # 初始化安全处置建议配置
    advice_config = SecurityAdviceConfig.query.filter_by(name='default').first()
    if not advice_config:
        db.session.add(SecurityAdviceConfig(
            name='default',
            phishing_advice='''1. 该邮件存在恶意链接/附件，可能造成信息泄露或财产损失。
2. 请立即删除该邮件及其所有附件。
3. 请勿将该邮件转发给其他同事，避免风险扩散。

【请您确认】
请确认您是否已经点击了该钓鱼邮件中的附件或链接：
- 若未点击：请立即删除该邮件即可，无需其他操作。
- 若已点击：请立即下载邮件附件中的应急处置工具，以管理员身份运行，等待日志收集完成并自动断网。''',
            normal_advice='''1. 核对发件人身份及内容合理性。
2. 如邮件中索要敏感信息（如密码、银行账号）或要求转账等操作，请通过其他渠道（如电话、内部IM）与发件人二次确认。
3. 保持基础安全警惕，避免完全放松防范意识。'''
        ))
    
    # 保留一个通用回复模板用于手动回复
    if not ReplyTemplate.query.filter_by(name='general_reply').first():
        db.session.add(ReplyTemplate(
            name='general_reply',
            type='general',
            subject_template='【邮件安全检测结果】您上报的邮件已被判定为{{result}}',
            body_template='''尊敬的同事：

钓鱼邮件智能分析系统已对您上报的邮件进行了深度研判分析。

【判定结果】
该邮件已被判定为{{result}}，{{action}}。

【安全风险提示】
{{advice}}

感谢您的配合！

安全室'''
        ))
    
    pipeline_config = PipelineConfig.query.filter_by(name='default').first()
    if pipeline_config:
        pipeline_config.auto_analyze = True
        pipeline_config.auto_reply = True
    else:
        db.session.add(PipelineConfig(name='default', auto_analyze=True, auto_reply=True))
    
    db.session.commit()