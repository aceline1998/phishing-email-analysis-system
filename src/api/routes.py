from flask import Blueprint, request, jsonify, render_template, session, send_file, make_response, current_app
from src.models.db import db, MailServerConfig, LLMConfig, EmailRecord, AnalysisResult, ReplyTemplate, ReplyRecord, User, SecurityAdviceConfig, ThreatIntelConfig, ThreatIntelRecord, AuditLog, VersionInfo, ChatConversation, ChatMessage, AnalysisCorrection, EmailSignature
from src.utils.config_manager import load_config, save_config, get_db_uri, is_db_configured
from src.services.email_service import EmailService, generate_analysis_reply_email
from src.services.llm_service import LLMService
from src.services.db_migration_service import migrate_data, get_migration_status
from src.services.task_queue import task_queue, TaskPriority
from src.services.email_pipeline import email_pipeline
from src.services.redis_service import redis_cache, test_redis_connection
from src.services.health_monitor import health_monitor
from src.services.foxmail_service import foxmail_service
from src.services.auth_service import (
    verify_password, create_user, get_user, get_all_users, update_user, delete_user,
    change_password, create_reset_token, reset_password, init_admin
)
from datetime import datetime, timedelta
import threading
import os
import json

api_bp = Blueprint('api', __name__)


def login_required(f):
    def login_decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': '请先登录'}), 401
        return f(*args, **kwargs)
    login_decorated.__name__ = f.__name__
    return login_decorated


def admin_required(f):
    def admin_decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': '请先登录'}), 401
        user = User.query.get(session['user_id'])
        if not user or user.role != 'admin':
            return jsonify({'error': '权限不足'}), 403
        return f(*args, **kwargs)
    admin_decorated.__name__ = f.__name__
    return admin_decorated


@api_bp.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'db_configured': is_db_configured(), 'logged_in': 'user_id' in session})


import io
import random
import string
from PIL import Image, ImageDraw, ImageFont

captcha_storage = {}


@api_bp.route('/captcha', methods=['GET'])
def get_captcha():
    width, height = 120, 40
    image = Image.new('RGB', (width, height), (255, 255, 255))
    draw = ImageDraw.Draw(image)
    
    chars = string.digits + string.ascii_uppercase
    captcha_text = ''.join(random.choices(chars, k=4))
    
    try:
        font = ImageFont.truetype('arial.ttf', 28)
    except Exception:
        font = ImageFont.load_default()
    
    for i, char in enumerate(captcha_text):
        x = 10 + i * 28
        y = random.randint(5, 10)
        draw.text((x, y), char, font=font, fill=(random.randint(0, 100), random.randint(0, 100), random.randint(0, 100)))
    
    for _ in range(50):
        x = random.randint(0, width)
        y = random.randint(0, height)
        draw.point((x, y), fill=(random.randint(100, 200), random.randint(100, 200), random.randint(100, 200)))
    
    for _ in range(3):
        x1 = random.randint(0, width)
        y1 = random.randint(0, height)
        x2 = random.randint(0, width)
        y2 = random.randint(0, height)
        draw.line((x1, y1, x2, y2), fill=(random.randint(150, 200), random.randint(150, 200), random.randint(150, 200)), width=1)
    
    import uuid
    captcha_id = str(uuid.uuid4())
    captcha_storage[captcha_id] = captcha_text
    
    output = io.BytesIO()
    image.save(output, format='PNG')
    output.seek(0)
    
    import base64
    image_base64 = base64.b64encode(output.read()).decode()
    
    return jsonify({
        'captcha_id': captcha_id,
        'image': 'data:image/png;base64,' + image_base64
    })


@api_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    captcha_id = data.get('captcha_id')
    captcha = data.get('captcha')
    
    if not captcha_id or not captcha:
        return jsonify({'error': '请输入验证码'}), 400
    
    stored_captcha = captcha_storage.get(captcha_id)
    if not stored_captcha or stored_captcha.upper() != captcha.upper():
        return jsonify({'error': '验证码错误'}), 401
    
    del captcha_storage[captcha_id]
    
    user = get_user(username)
    if not user or not user.is_active:
        return jsonify({'error': '用户名或密码错误'}), 401
    if not verify_password(password, user.password_hash):
        return jsonify({'error': '用户名或密码错误'}), 401
    session['user_id'] = user.id
    session['username'] = user.username
    session['role'] = user.role
    
    log_audit('用户登录成功', 'login', 'user', f'用户名: {user.username}, 角色: {user.role}')
    
    return jsonify({
        'success': True,
        'user': {
            'id': user.id,
            'username': user.username,
            'role': user.role,
            'email': user.email
        }
    })


@api_bp.route('/logout', methods=['POST'])
def logout():
    username = session.get('username')
    log_audit('用户退出登录', 'logout', 'user', f'用户名: {username}')
    session.clear()
    return jsonify({'success': True})


@api_bp.route('/current-user', methods=['GET'])
def current_user():
    if 'user_id' not in session:
        return jsonify({'error': '未登录'}), 401
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        return jsonify({'error': '用户不存在'}), 401
    return jsonify({
        'id': user.id,
        'username': user.username,
        'role': user.role,
        'email': user.email
    })


@api_bp.route('/users', methods=['GET'])
@admin_required
def get_users():
    users = get_all_users()
    return jsonify([u.to_dict() for u in users])


@api_bp.route('/users', methods=['POST'])
@admin_required
def create_new_user():
    data = request.get_json()
    result = create_user(data['username'], data['password'], data.get('email'), data.get('role', 'user'))
    if result['success']:
        return jsonify(result['user']), 201
    return jsonify(result), 400


@api_bp.route('/users/<int:id>', methods=['PUT'])
@admin_required
def update_user_info(id):
    data = request.get_json()
    result = update_user(id, data)
    if result['success']:
        return jsonify(result['user'])
    return jsonify(result), 400


@api_bp.route('/users/<int:id>', methods=['DELETE'])
@admin_required
def delete_user_account(id):
    result = delete_user(id)
    if result['success']:
        return jsonify({'message': '已删除'})
    return jsonify(result), 400


@api_bp.route('/change-password', methods=['POST'])
@login_required
def change_user_password():
    data = request.get_json()
    result = change_password(session['user_id'], data['old_password'], data['new_password'])
    return jsonify(result)


@api_bp.route('/update-email', methods=['POST'])
@login_required
def update_user_email():
    data = request.get_json()
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'success': False, 'message': '用户不存在'}), 400
    user.email = data.get('email', '')
    db.session.commit()
    return jsonify({'success': True, 'message': '邮箱已更新'})


@api_bp.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    user = get_user(data.get('username'))
    if not user or not user.email:
        return jsonify({'success': True, 'message': '如果该账号已绑定邮箱，验证码已发送', 'token': ''})
    reset = create_reset_token(user.id)
    try:
        server = MailServerConfig.query.filter_by(is_active=True).first()
        if server:
            service = EmailService(server)
            body = f'''您的密码重置验证码为：{reset['code']}
有效期30分钟，请在登录页面输入验证码完成密码重置。'''
            service.send_reply(user.email, '密码重置验证码', body)
    except Exception:
        pass
    return jsonify({'success': True, 'message': '如果该账号已绑定邮箱，验证码已发送', 'token': reset['token']})


@api_bp.route('/reset-password', methods=['POST'])
def reset_user_password():
    data = request.get_json()
    result = reset_password(data.get('token', ''), data['code'], data['new_password'])
    return jsonify(result)


@api_bp.route('/system/config', methods=['GET'])
@login_required
def get_system_config():
    config = load_config()
    db_cfg = config.get('database', {})
    app_cfg = config.get('app', {})
    return jsonify({
        'database': {
            'type': db_cfg.get('type', 'sqlite'),
            'host': db_cfg.get('host', ''),
            'port': db_cfg.get('port', 3306),
            'username': db_cfg.get('username', ''),
            'database_name': db_cfg.get('database_name', ''),
            'charset': db_cfg.get('charset', 'utf8mb4')
        },
        'app': {
            'auto_check_interval': app_cfg.get('auto_check_interval', 300)
        }
    })


@api_bp.route('/system/config', methods=['POST'])
@admin_required
def update_system_config():
    data = request.get_json()
    config = load_config()
    if 'database' in data:
        config['database'] = data['database']
    if 'app' in data:
        config['app'] = data['app']
    save_config(config)
    # 通知 scheduler 间隔已变更，立即生效
    try:
        from src.api.app import notify_scheduler_interval_change
        notify_scheduler_interval_change()
    except Exception as e:
        print(f"Notify scheduler error: {e}")
    return jsonify({'message': '应用配置已保存，间隔变更立即生效'})


@api_bp.route('/system/restart', methods=['POST'])
@admin_required
def restart_service():
    import signal
    def do_restart():
        import time
        time.sleep(1)
        os.kill(os.getpid(), signal.SIGINT)
    thread = threading.Thread(target=do_restart)
    thread.daemon = True
    thread.start()
    return jsonify({'message': '服务正在重启，请稍后刷新页面'})


@api_bp.route('/system/migration-status', methods=['GET'])
@admin_required
def get_migration_info():
    return jsonify(get_migration_status())


@api_bp.route('/system/migrate-db', methods=['POST'])
@admin_required
def manual_migrate_db():
    from flask import current_app
    config = load_config()
    db_cfg = config.get('database', {})
    
    if db_cfg.get('type') != 'mysql':
        return jsonify({'error': '请先配置MySQL数据库'}), 400
    
    source_uri = f"sqlite:///{os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'data', 'phishing.db')}"
    target_uri = f"mysql+pymysql://{db_cfg['username']}:{db_cfg['password']}@{db_cfg['host']}:{db_cfg['port']}/{db_cfg['database_name']}?charset={db_cfg.get('charset', 'utf8mb4')}"
    
    try:
        result = migrate_data(current_app, source_uri, target_uri)
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@api_bp.route('/mail-servers', methods=['GET'])
@login_required
def get_mail_servers():
    servers = MailServerConfig.query.all()
    return jsonify([s.to_dict() for s in servers])


@api_bp.route('/mail-servers', methods=['POST'])
@admin_required
def create_mail_server():
    data = request.get_json()
    server = MailServerConfig(
        name=data['name'],
        imap_server=data['imap_server'],
        imap_port=data.get('imap_port', 993),
        imap_ssl=data.get('imap_ssl', True),
        smtp_server=data['smtp_server'],
        smtp_port=data.get('smtp_port', 465),
        smtp_ssl=data.get('smtp_ssl', True),
        email=data['email'],
        password=data['password'],
        is_active=data.get('is_active', True)
    )
    db.session.add(server)
    db.session.commit()
    return jsonify(server.to_dict())


@api_bp.route('/mail-servers/<int:id>', methods=['PUT'])
@admin_required
def update_mail_server(id):
    server = MailServerConfig.query.get_or_404(id)
    data = request.get_json()
    server.name = data.get('name', server.name)
    server.imap_server = data.get('imap_server', server.imap_server)
    server.imap_port = data.get('imap_port', server.imap_port)
    server.imap_ssl = data.get('imap_ssl', server.imap_ssl)
    server.smtp_server = data.get('smtp_server', server.smtp_server)
    server.smtp_port = data.get('smtp_port', server.smtp_port)
    server.smtp_ssl = data.get('smtp_ssl', server.smtp_ssl)
    server.email = data.get('email', server.email)
    if data.get('password'):
        server.password = data['password']
    server.is_active = data.get('is_active', server.is_active)
    db.session.commit()
    return jsonify(server.to_dict())


@api_bp.route('/mail-servers/<int:id>', methods=['DELETE'])
@admin_required
def delete_mail_server(id):
    server = MailServerConfig.query.get_or_404(id)
    db.session.delete(server)
    db.session.commit()
    return jsonify({'message': '已删除'})


@api_bp.route('/mail-servers/<int:id>/test', methods=['POST'])
@admin_required
def test_mail_server(id):
    server = MailServerConfig.query.get_or_404(id)
    service = EmailService(server)
    result = service.test_connection()
    return jsonify(result)


@api_bp.route('/llm-configs', methods=['GET'])
@login_required
def get_llm_configs():
    configs = LLMConfig.query.all()
    return jsonify([c.to_dict() for c in configs])


@api_bp.route('/llm-configs', methods=['POST'])
@admin_required
def create_llm_config():
    data = request.get_json()
    config = LLMConfig(
        name=data['name'],
        api_base_url=data.get('api_base_url', 'https://api.deepseek.com/v1'),
        api_key=data['api_key'],
        model_name=data.get('model_name', 'deepseek-chat'),
        is_active=data.get('is_active', True)
    )
    db.session.add(config)
    db.session.commit()
    return jsonify(config.to_dict())


@api_bp.route('/llm-configs/<int:id>', methods=['PUT'])
@admin_required
def update_llm_config(id):
    config = LLMConfig.query.get_or_404(id)
    data = request.get_json()
    config.name = data.get('name', config.name)
    config.api_base_url = data.get('api_base_url', config.api_base_url)
    if data.get('api_key'):
        config.api_key = data['api_key']
    config.model_name = data.get('model_name', config.model_name)
    config.is_active = data.get('is_active', config.is_active)
    db.session.commit()
    return jsonify(config.to_dict())


@api_bp.route('/llm-configs/<int:id>', methods=['DELETE'])
@admin_required
def delete_llm_config(id):
    config = LLMConfig.query.get_or_404(id)
    db.session.delete(config)
    db.session.commit()
    return jsonify({'message': '已删除'})


@api_bp.route('/llm-configs/<int:id>/test', methods=['POST'])
@admin_required
def test_llm_config(id):
    config = LLMConfig.query.get_or_404(id)
    service = LLMService(config)
    result = service.test_connection()
    return jsonify(result)


@api_bp.route('/emails', methods=['GET'])
@login_required
def get_emails():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    status = request.args.get('status')
    is_phishing = request.args.get('is_phishing')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    query = EmailRecord.query.options(db.joinedload(EmailRecord.analysis))
    if status:
        query = query.filter_by(status=status)
    if is_phishing is not None:
        query = query.join(AnalysisResult, EmailRecord.id == AnalysisResult.email_id)
        query = query.filter(AnalysisResult.is_phishing == (is_phishing == 'true'))
    if start_date:
        query = query.filter(EmailRecord.received_at >= datetime.strptime(start_date, '%Y-%m-%d'))
    if end_date:
        query = query.filter(EmailRecord.received_at <= datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1))
    pagination = query.order_by(EmailRecord.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    return jsonify({
        'items': [e.to_dict() for e in pagination.items],
        'total': pagination.total,
        'pages': pagination.pages,
        'page': page
    })


@api_bp.route('/emails/export', methods=['GET'])
@admin_required
def export_emails():
    import csv
    from io import StringIO
    from flask import Response

    status = request.args.get('status')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    limit = request.args.get('limit', type=int)

    query = EmailRecord.query.options(db.joinedload(EmailRecord.analysis))
    if status:
        query = query.filter_by(status=status)
    if start_date:
        query = query.filter(EmailRecord.received_at >= datetime.strptime(start_date, '%Y-%m-%d'))
    if end_date:
        query = query.filter(EmailRecord.received_at <= datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1))

    query = query.order_by(EmailRecord.created_at.desc())
    if limit:
        query = query.limit(limit)

    emails = query.all()

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['来源', '发件人', '主题', '状态', '分析结果', '风险等级', '收到时间'])

    for email in emails:
        source = '在线收取' if email.source == 'mail_server' else ('离线导入' if email.source == 'import' else ('Foxmail' if email.source == 'foxmail' else email.source or ''))
        
        status_text = '待处理'
        if email.status == 'analyzed':
            status_text = '已分析'
        elif email.status == 'replied':
            status_text = '已回复'
        elif email.status == 'analyzing':
            status_text = '分析中'
        
        result_text = '-'
        risk_level = '-'
        if email.analysis:
            result_text = '钓鱼邮件' if email.analysis.is_phishing else '正常邮件'
            risk_level = {'high': '高危', 'medium': '中危', 'low': '低危'}.get(email.analysis.risk_level, email.analysis.risk_level or '-')

        writer.writerow([
            source,
            email.from_email or '',
            email.subject or '(无主题)',
            status_text,
            result_text,
            risk_level,
            email.received_at.strftime('%Y-%m-%d %H:%M:%S') if email.received_at else ''
        ])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv; charset=utf-8',
        headers={
            'Content-Disposition': f'attachment; filename=emails_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv',
            'Content-Type': 'text/csv; charset=utf-8'
        }
    )


@api_bp.route('/emails/<int:id>', methods=['GET'])
@login_required
def get_email(id):
    email = EmailRecord.query.get_or_404(id)
    result = email.to_dict()
    if email.analysis:
        result['analysis'] = email.analysis.to_dict()
    if email.replies:
        result['replies'] = [r.to_dict() for r in email.replies]
    return jsonify(result)


@api_bp.route('/emails/<int:id>/analyze', methods=['POST'])
@admin_required
def analyze_email(id):
    email = EmailRecord.query.get_or_404(id)
    llm_config = LLMConfig.query.filter_by(is_active=True).first()
    if not llm_config:
        return jsonify({'error': '未配置活跃的大模型'}), 400

    service = LLMService(llm_config)
    result = service.analyze_email(email)

    existing = AnalysisResult.query.filter_by(email_id=email.id).first()
    if existing:
        existing.is_phishing = result['is_phishing']
        existing.confidence = result['confidence']
        existing.risk_level = result['risk_level']
        existing.analysis_report = result['analysis_report']
        existing.phishing_type = result['phishing_type']
        existing.indicators = result['indicators']
        existing.llm_config_id = llm_config.id
    else:
        analysis = AnalysisResult(
            email_id=email.id,
            is_phishing=result['is_phishing'],
            confidence=result['confidence'],
            risk_level=result['risk_level'],
            analysis_report=result['analysis_report'],
            phishing_type=result['phishing_type'],
            indicators=result['indicators'],
            llm_config_id=llm_config.id
        )
        db.session.add(analysis)

    email.status = 'analyzed'
    db.session.commit()
    return jsonify(result)


@api_bp.route('/emails/<int:id>/reply', methods=['POST'])
@admin_required
def reply_email(id):
    email = EmailRecord.query.get_or_404(id)
    data = request.get_json() or {}
    use_analysis_template = data.get('use_analysis_template', False)
    send_method = data.get('send_method', 'smtp')

    mail_server = MailServerConfig.query.filter_by(is_active=True).first()

    if use_analysis_template:
        analysis = AnalysisResult.query.filter_by(email_id=email.id).first()
        if not analysis:
            return jsonify({'error': '请先分析邮件'}), 400

        security_config = SecurityAdviceConfig.query.filter_by(is_active=True).first()
        if not security_config:
            security_config = {
                'phishing_advice': '''1. 该邮件存在恶意链接/附件，可能造成信息泄露或财产损失。
2. 请立即删除该邮件及其所有附件。
3. 请勿将该邮件转发给其他同事，避免风险扩散。

【请您确认】
请确认您是否已经点击了该钓鱼邮件中的附件或链接：
- 若未点击：请立即删除该邮件即可，无需其他操作。
- 若已点击：请立即下载邮件附件中的应急处置工具，以管理员身份运行，等待日志收集完成并自动断网。''',
                'normal_advice': '''1. 核对发件人身份及内容合理性。
2. 如邮件中索要敏感信息（如密码、银行账号）或要求转账等操作，请通过其他渠道（如电话、内部IM）与发件人二次确认。
3. 保持基础安全警惕，避免完全放松防范意识。'''
            }
        else:
            security_config = security_config.to_dict()

        analysis_result = {
            'is_phishing': analysis.is_phishing,
            'analysis_report': analysis.analysis_report,
            'confidence': analysis.confidence,
            'risk_level': analysis.risk_level,
            'phishing_type': analysis.phishing_type,
            'indicators': analysis.indicators
        }

        email_content = generate_analysis_reply_email(email, analysis_result, security_config)
        subject = email_content['subject']
        plain_body = email_content['plain_body']
        html_body = email_content['html_body']
    else:
        template_id = data.get('template_id')
        custom_subject = data.get('subject')
        custom_body = data.get('body')

        if template_id:
            tpl = ReplyTemplate.query.get(template_id)
            if tpl:
                subject = tpl.subject_template
                plain_body = tpl.body_template
                html_body = None
            else:
                return jsonify({'error': '模板不存在'}), 404
        else:
            subject = custom_subject or 'Re: ' + (email.subject or '')
            plain_body = custom_body or ''
            html_body = None

    if send_method == 'foxmail':
        success, msg = foxmail_service.send_email_via_mapi(email.from_email, subject, plain_body)
        result = {'success': success, 'message': msg}
        from_email = 'Foxmail客户端'
    else:
        if not mail_server:
            return jsonify({'error': '未配置活跃的邮件服务器'}), 400

        service = EmailService(mail_server)
        sender_name = email_pipeline.get_config().get('sender_display_name', '安全室')
        result = service.send_reply(email.from_email, subject, plain_body, html_body, sender_display_name=sender_name)
        from_email = mail_server.email

    import base64
    raw_content_str = result.get('raw_content')
    raw_content = base64.b64encode(raw_content_str.encode('utf-8')).decode('utf-8') if raw_content_str else None

    reply = ReplyRecord(
        email_id=email.id,
        reply_to=email.from_email,
        from_email=from_email,
        subject=subject,
        body=plain_body,
        raw_content=raw_content,
        status='sent' if result['success'] else 'failed'
    )
    db.session.add(reply)
    email.status = 'replied'
    db.session.commit()
    return jsonify(result)


@api_bp.route('/security-advice', methods=['GET'])
@admin_required
def get_security_advice():
    config = SecurityAdviceConfig.query.filter_by(is_active=True).first()
    if not config:
        return jsonify({
            'phishing_advice': '1. 请勿点击邮件中的任何链接或下载附件。\n2. 建议立即删除该邮件。\n3. 如已点击链接或下载附件，请立即联系安全团队进行应急处置。',
            'normal_advice': '1. 建议接收人确认附件内容是否为实际业务所需报告。\n2. 建议对类似包含压缩包的邮件建立附件内容校验机制。\n3. 建议加强员工安全意识培训。'
        })
    return jsonify(config.to_dict())


@api_bp.route('/security-advice', methods=['POST'])
@admin_required
def save_security_advice():
    data = request.get_json()
    phishing_advice = data.get('phishing_advice', '')
    normal_advice = data.get('normal_advice', '')

    config = SecurityAdviceConfig.query.filter_by(is_active=True).first()
    if config:
        config.phishing_advice = phishing_advice
        config.normal_advice = normal_advice
    else:
        config = SecurityAdviceConfig(
            name='default',
            phishing_advice=phishing_advice,
            normal_advice=normal_advice,
            is_active=True
        )
        db.session.add(config)

    db.session.commit()
    return jsonify({'success': True, 'message': '安全处置建议保存成功'})


@api_bp.route('/reply-templates', methods=['GET'])
@login_required
def get_templates():
    templates = ReplyTemplate.query.all()
    return jsonify([t.to_dict() for t in templates])


@api_bp.route('/reply-templates', methods=['POST'])
@admin_required
def create_template():
    data = request.get_json()
    tpl = ReplyTemplate(
        name=data['name'],
        type=data['type'],
        subject_template=data['subject_template'],
        body_template=data['body_template'],
        is_active=data.get('is_active', True)
    )
    db.session.add(tpl)
    db.session.commit()
    return jsonify(tpl.to_dict())


@api_bp.route('/reply-templates/<int:id>', methods=['PUT'])
@admin_required
def update_template(id):
    tpl = ReplyTemplate.query.get_or_404(id)
    data = request.get_json()
    tpl.name = data.get('name', tpl.name)
    tpl.type = data.get('type', tpl.type)
    tpl.subject_template = data.get('subject_template', tpl.subject_template)
    tpl.body_template = data.get('body_template', tpl.body_template)
    tpl.is_active = data.get('is_active', tpl.is_active)
    db.session.commit()
    return jsonify(tpl.to_dict())


@api_bp.route('/reply-templates/<int:id>', methods=['DELETE'])
@admin_required
def delete_template(id):
    tpl = ReplyTemplate.query.get_or_404(id)
    db.session.delete(tpl)
    db.session.commit()
    return jsonify({'message': '已删除'})


@api_bp.route('/fetch-emails', methods=['POST'])
@admin_required
def fetch_emails():
    data = request.get_json() or {}
    server_id = data.get('server_id')
    limit = data.get('limit', 0)
    auto_analyze = data.get('auto_analyze', False)

    if server_id:
        server = MailServerConfig.query.get(server_id)
    else:
        server = MailServerConfig.query.filter_by(is_active=True).first()

    if not server:
        return jsonify({'error': '未找到邮件服务器配置，请先在系统配置中添加邮件服务器'}), 400

    try:
        service = EmailService(server)
        before_ids = set(e.id for e in EmailRecord.query.with_entities(EmailRecord.id).all())
        result = service.fetch_new_emails(limit=limit)
        after_ids = set(e.id for e in EmailRecord.query.with_entities(EmailRecord.id).all())
        new_ids = list(after_ids - before_ids)

        if result['success']:
            if new_ids and auto_analyze:
                email_pipeline.auto_process_new_emails(new_ids)
            return jsonify({
                'message': result['message'],
                'new_count': len(new_ids)
            })
        else:
            return jsonify({'error': result['message']}), 400
    except Exception as e:
        return jsonify({'error': f'获取邮件失败: {str(e)}'}), 400


@api_bp.route('/statistics', methods=['GET'])
@login_required
def get_statistics():
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    query = EmailRecord.query
    if start_date:
        query = query.filter(EmailRecord.received_at >= datetime.strptime(start_date, '%Y-%m-%d'))
    if end_date:
        query = query.filter(EmailRecord.received_at <= datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1))

    total = query.count()
    email_ids = [e.id for e in query.all()]

    analysis_query = AnalysisResult.query.filter(AnalysisResult.email_id.in_(email_ids))
    phishing = analysis_query.filter_by(is_phishing=True).count()
    normal = analysis_query.filter_by(is_phishing=False).count()

    pending = EmailRecord.query.filter(EmailRecord.id.in_(email_ids), EmailRecord.status == 'pending').count()
    analyzed = EmailRecord.query.filter(EmailRecord.id.in_(email_ids), EmailRecord.status == 'analyzed').count()
    replied = EmailRecord.query.filter(EmailRecord.id.in_(email_ids), EmailRecord.status == 'replied').count()

    phishing_types = {}
    for r in analysis_query.filter(AnalysisResult.phishing_type.isnot(None)).all():
        t = r.phishing_type
        phishing_types[t] = phishing_types.get(t, 0) + 1

    risk_levels = {}
    for r in analysis_query.filter(AnalysisResult.risk_level.isnot(None)).all():
        l = r.risk_level
        risk_levels[l] = risk_levels.get(l, 0) + 1

    top_senders = {}
    top_sender_emails = {}
    for e in query.all():
        domain = e.from_email.split('@')[-1] if '@' in e.from_email else e.from_email
        top_senders[domain] = top_senders.get(domain, 0) + 1
        top_sender_emails[e.from_email] = top_sender_emails.get(e.from_email, 0) + 1
    top_senders = dict(sorted(top_senders.items(), key=lambda x: x[1], reverse=True)[:10])
    top_sender_emails = dict(sorted(top_sender_emails.items(), key=lambda x: x[1], reverse=True)[:10])

    daily_trend = {}
    for e in query.all():
        date_key = e.received_at.strftime('%Y-%m-%d') if e.received_at else 'unknown'
        daily_trend[date_key] = daily_trend.get(date_key, {'total': 0, 'phishing': 0})
        daily_trend[date_key]['total'] += 1
    for ar in analysis_query.filter_by(is_phishing=True).all():
        date_key = ar.email.received_at.strftime('%Y-%m-%d') if ar.email.received_at else 'unknown'
        if date_key in daily_trend:
            daily_trend[date_key]['phishing'] += 1

    reply_count = ReplyRecord.query.filter(ReplyRecord.email_id.in_(email_ids)).count()

    avg_confidence = 0
    if phishing + normal > 0:
        avg_confidence = analysis_query.with_entities(db.func.avg(AnalysisResult.confidence)).scalar() or 0

    return jsonify({
        'total_emails': total,
        'phishing_count': phishing,
        'normal_count': normal,
        'pending_count': pending,
        'analyzed_count': analyzed,
        'replied_count': replied,
        'reply_record_count': reply_count,
        'phishing_rate': phishing / total * 100 if total > 0 else 0,
        'avg_confidence': avg_confidence,
        'phishing_types': phishing_types,
        'risk_levels': risk_levels,
        'top_senders': top_senders,
        'top_sender_emails': top_sender_emails,
        'daily_trend': daily_trend,
        'source_stats': {
            'mail_server': EmailRecord.query.filter(EmailRecord.id.in_(email_ids), EmailRecord.source == 'mail_server').count(),
            'import': EmailRecord.query.filter(EmailRecord.id.in_(email_ids), EmailRecord.source == 'import').count()
        },
        'time_range': {
            'start_date': start_date,
            'end_date': end_date
        }
    })


@api_bp.route('/export-report', methods=['GET'])
@login_required
def export_report():
    try:
        from docx import Document
        from docx.shared import Pt, Inches, Cm, RGBColor
        from docx.enum.text import WD_ALIGN_PARAGRAPH
        from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
        from docx.oxml.ns import qn
        
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        report_type = request.args.get('type', 'summary')
        
        query = EmailRecord.query
        if start_date:
            query = query.filter(EmailRecord.received_at >= datetime.strptime(start_date, '%Y-%m-%d'))
        if end_date:
            query = query.filter(EmailRecord.received_at <= datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1))
        
        all_emails = query.order_by(EmailRecord.received_at.desc()).all()
        email_ids = [e.id for e in all_emails]
        
        analysis_query = AnalysisResult.query.filter(AnalysisResult.email_id.in_(email_ids))
        all_analyses = analysis_query.all()
        
        total = len(all_emails)
        phishing = analysis_query.filter_by(is_phishing=True).count()
        normal = analysis_query.filter_by(is_phishing=False).count()
        pending = EmailRecord.query.filter(EmailRecord.id.in_(email_ids), EmailRecord.status == 'pending').count()
        analyzed = EmailRecord.query.filter(EmailRecord.id.in_(email_ids), EmailRecord.status == 'analyzed').count()
        replied = EmailRecord.query.filter(EmailRecord.id.in_(email_ids), EmailRecord.status == 'replied').count()
        
        phishing_types = {}
        for r in analysis_query.filter(AnalysisResult.phishing_type.isnot(None)).all():
            t = r.phishing_type
            phishing_types[t] = phishing_types.get(t, 0) + 1
        
        risk_levels = {}
        for r in analysis_query.filter(AnalysisResult.risk_level.isnot(None)).all():
            l = r.risk_level
            risk_levels[l] = risk_levels.get(l, 0) + 1
        
        top_senders = {}
        for e in all_emails:
            domain = e.from_email.split('@')[-1] if '@' in e.from_email else e.from_email
            top_senders[domain] = top_senders.get(domain, 0) + 1
        top_senders = dict(sorted(top_senders.items(), key=lambda x: x[1], reverse=True)[:10])
        
        daily_trend = {}
        for e in all_emails:
            date_key = e.received_at.strftime('%Y-%m-%d') if e.received_at else 'unknown'
            daily_trend[date_key] = daily_trend.get(date_key, {'total': 0, 'phishing': 0})
            daily_trend[date_key]['total'] += 1
        for ar in analysis_query.filter_by(is_phishing=True).all():
            date_key = ar.email.received_at.strftime('%Y-%m-%d') if ar.email.received_at else 'unknown'
            if date_key in daily_trend:
                daily_trend[date_key]['phishing'] += 1
        
        doc = Document()
        
        def set_font_for_run(run, font_name='宋体', size=None):
            run.font.name = font_name
            if run._element.rPr is not None:
                run._element.rPr.rFonts.set(qn('w:eastAsia'), font_name)
            if size is not None:
                run.font.size = size
        
        def set_font_for_paragraph(para, font_name='宋体', size=None):
            for run in para.runs:
                set_font_for_run(run, font_name, size)
        
        style = doc.styles['Normal']
        style.font.name = '宋体'
        style._element.rPr.rFonts.set(qn('w:eastAsia'), '宋体')
        style.font.size = Pt(11)
        
        for i in range(1, 5):
            heading_style = doc.styles[f'Heading {i}']
            heading_style.font.name = '宋体'
            heading_style._element.rPr.rFonts.set(qn('w:eastAsia'), '宋体')
        
        title = doc.add_heading('钓鱼邮件智能分析系统报告', level=1)
        title.alignment = WD_ALIGN_PARAGRAPH.CENTER
        for run in title.runs:
            run.font.size = Pt(24)
            set_font_for_run(run, '宋体', Pt(24))
        
        subtitle = doc.add_paragraph()
        subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = subtitle.add_run('报告生成时间：' + datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        run.font.size = Pt(10)
        run.font.color.rgb = RGBColor(100, 100, 100)
        set_font_for_run(run, '宋体', Pt(10))
        
        if start_date or end_date:
            subtitle2 = doc.add_paragraph()
            subtitle2.alignment = WD_ALIGN_PARAGRAPH.CENTER
            run2 = subtitle2.add_run(f'时间范围：{start_date or "不限"} 至 {end_date or "不限"}')
            run2.font.size = Pt(10)
            run2.font.color.rgb = RGBColor(100, 100, 100)
            set_font_for_run(run2, '宋体', Pt(10))
        
        doc.add_paragraph()
        
        doc.add_heading('一、执行摘要', level=1)
        
        p = doc.add_paragraph()
        p.add_run('本次报告涵盖了系统在指定时间范围内对钓鱼邮件的分析情况。')
        p.add_run('\n\n')
        p.add_run(f'共收到邮件 ')
        p.add_run(f'{total}').bold = True
        p.add_run(f' 封，其中判定为钓鱼邮件 ')
        p.add_run(f'{phishing}').bold = True
        p.add_run(f' 封，正常邮件 ')
        p.add_run(f'{normal}').bold = True
        p.add_run(f' 封，钓鱼邮件占比 ')
        p.add_run(f'{(phishing/total*100 if total>0 else 0):.1f}%').bold = True
        p.add_run(f'。')
        p.add_run('\n\n')
        p.add_run(f'当前系统状态：待处理 ')
        p.add_run(f'{pending}').bold = True
        p.add_run(f' 封，已分析 ')
        p.add_run(f'{analyzed}').bold = True
        p.add_run(f' 封，已回复 ')
        p.add_run(f'{replied}').bold = True
        p.add_run(f' 封。')
        
        doc.add_heading('二、统计概览', level=1)
        
        table = doc.add_table(rows=1, cols=6)
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        hdr_cells = table.rows[0].cells
        hdr_cells[0].text = '统计项'
        hdr_cells[1].text = '邮件总量'
        hdr_cells[2].text = '钓鱼邮件'
        hdr_cells[3].text = '正常邮件'
        hdr_cells[4].text = '钓鱼占比'
        hdr_cells[5].text = '处理状态'
        
        row_cells = table.add_row().cells
        row_cells[0].text = '数值'
        row_cells[1].text = str(total)
        row_cells[2].text = str(phishing)
        row_cells[3].text = str(normal)
        row_cells[4].text = f'{(phishing/total*100 if total>0 else 0):.1f}%'
        row_cells[5].text = f'待处理{pending}/已分析{analyzed}/已回复{replied}'
        
        for row in table.rows:
            for cell in row.cells:
                cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
                paragraphs = cell.paragraphs
                for paragraph in paragraphs:
                    paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
                    set_font_for_paragraph(paragraph, '宋体', Pt(11))
                    set_font_for_paragraph(paragraph, '宋体', Pt(11))
        
        doc.add_heading('二、统计概览', level=1)
        
        if risk_levels:
            table = doc.add_table(rows=1, cols=4)
            table.alignment = WD_TABLE_ALIGNMENT.CENTER
            hdr_cells = table.rows[0].cells
            hdr_cells[0].text = '风险等级'
            hdr_cells[1].text = '数量'
            hdr_cells[2].text = '占比'
            hdr_cells[3].text = '说明'
            
            total_risk = sum(risk_levels.values())
            for level in ['high', 'medium', 'low']:
                count = risk_levels.get(level, 0)
                row_cells = table.add_row().cells
                row_cells[0].text = {'high': '高危', 'medium': '中危', 'low': '低危'}[level]
                row_cells[1].text = str(count)
                row_cells[2].text = f'{(count/total_risk*100 if total_risk>0 else 0):.1f}%'
                row_cells[3].text = {'high': '高度可疑，建议立即处理', 'medium': '有一定风险，建议关注', 'low': '风险较低'}[level]
            
            for row in table.rows:
                for cell in row.cells:
                    cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
                    paragraphs = cell.paragraphs
                    for paragraph in paragraphs:
                        paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
        else:
            doc.add_paragraph('暂无风险等级数据')
        
        doc.add_heading('四、钓鱼类型分析', level=1)
        
        if phishing_types:
            table = doc.add_table(rows=1, cols=3)
            table.alignment = WD_TABLE_ALIGNMENT.CENTER
            hdr_cells = table.rows[0].cells
            hdr_cells[0].text = '类型'
            hdr_cells[1].text = '数量'
            hdr_cells[2].text = '占比'
            
            total_types = sum(phishing_types.values())
            for t, count in sorted(phishing_types.items(), key=lambda x: x[1], reverse=True):
                row_cells = table.add_row().cells
                row_cells[0].text = t
                row_cells[1].text = str(count)
                row_cells[2].text = f'{(count/total_types*100):.1f}%'
            
            for row in table.rows:
                for cell in row.cells:
                    cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
                    paragraphs = cell.paragraphs
                    for paragraph in paragraphs:
                        paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
        else:
            doc.add_paragraph('暂无钓鱼类型数据')
        
        doc.add_heading('五、发件人域名排行', level=1)
        
        if top_senders:
            table = doc.add_table(rows=1, cols=3)
            table.alignment = WD_TABLE_ALIGNMENT.CENTER
            hdr_cells = table.rows[0].cells
            hdr_cells[0].text = '排名'
            hdr_cells[1].text = '域名'
            hdr_cells[2].text = '邮件数量'
            
            rank = 1
            for domain, count in top_senders.items():
                row_cells = table.add_row().cells
                row_cells[0].text = str(rank)
                row_cells[1].text = domain
                row_cells[2].text = str(count)
                rank += 1
            
            for row in table.rows:
                for cell in row.cells:
                    cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
                    paragraphs = cell.paragraphs
                    for paragraph in paragraphs:
                        paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
        else:
            doc.add_paragraph('暂无发件人数据')
        
        doc.add_heading('六、每日趋势', level=1)
        
        if daily_trend:
            table = doc.add_table(rows=1, cols=3)
            table.alignment = WD_TABLE_ALIGNMENT.CENTER
            hdr_cells = table.rows[0].cells
            hdr_cells[0].text = '日期'
            hdr_cells[1].text = '邮件总量'
            hdr_cells[2].text = '钓鱼邮件'
            
            for date in sorted(daily_trend.keys()):
                trend = daily_trend[date]
                row_cells = table.add_row().cells
                row_cells[0].text = date
                row_cells[1].text = str(trend['total'])
                row_cells[2].text = str(trend['phishing'])
            
            for row in table.rows:
                for cell in row.cells:
                    cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
                    paragraphs = cell.paragraphs
                    for paragraph in paragraphs:
                        paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
        else:
            doc.add_paragraph('暂无趋势数据')
        
        if report_type == 'detail':
            doc.add_heading('七、详细分析记录', level=1)
            
            if all_analyses:
                for ar in all_analyses:
                    e = ar.email
                    doc.add_heading(f'记录 {ar.id} - {e.subject[:30] if e.subject else "无主题"}', level=2)
                    
                    table = doc.add_table(rows=1, cols=2)
                    table.alignment = WD_TABLE_ALIGNMENT.CENTER
                    
                    row_cells = table.add_row().cells
                    row_cells[0].text = '发件人'
                    row_cells[1].text = e.from_email
                    
                    row_cells = table.add_row().cells
                    row_cells[0].text = '收件人'
                    row_cells[1].text = e.to_email or '-'
                    
                    row_cells = table.add_row().cells
                    row_cells[0].text = '主题'
                    row_cells[1].text = e.subject or '-'
                    
                    row_cells = table.add_row().cells
                    row_cells[0].text = '收到时间'
                    row_cells[1].text = e.received_at.strftime('%Y-%m-%d %H:%M:%S') if e.received_at else '-'
                    
                    row_cells = table.add_row().cells
                    row_cells[0].text = '判定结果'
                    row_cells[1].text = '钓鱼邮件' if ar.is_phishing else '正常邮件'
                    
                    row_cells = table.add_row().cells
                    row_cells[0].text = '风险等级'
                    row_cells[1].text = {'high': '高危', 'medium': '中危', 'low': '低危'}.get(ar.risk_level, '-')
                    
                    row_cells = table.add_row().cells
                    row_cells[0].text = '置信度'
                    row_cells[1].text = f'{(ar.confidence*100 if ar.confidence else 0):.1f}%'
                    
                    row_cells = table.add_row().cells
                    row_cells[0].text = '钓鱼类型'
                    row_cells[1].text = ar.phishing_type or '-'
                    
                    for row in table.rows:
                        for cell in row.cells:
                            cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
                    
                    if ar.analysis_report:
                        doc.add_paragraph('分析报告：', style='Heading 3')
                        p = doc.add_paragraph(ar.analysis_report)
                        p.paragraph_format.first_line_indent = Cm(0.74)
                    
                    doc.add_paragraph()
            else:
                doc.add_paragraph('暂无详细分析记录')
        
        doc.add_heading('八、附录', level=1)
        doc.add_paragraph('本报告由钓鱼邮件智能分析系统自动生成，包含系统分析的所有邮件数据。')
        doc.add_paragraph('报告生成时间：' + datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        doc.add_paragraph('系统版本：v1.0')
        
        for para in doc.paragraphs:
            set_font_for_paragraph(para, '宋体', Pt(11) if para.style.name == 'Normal' else None)
        
        for table in doc.tables:
            for row in table.rows:
                for cell in row.cells:
                    for para in cell.paragraphs:
                        set_font_for_paragraph(para, '宋体', Pt(11))
        
        import io
        output = io.BytesIO()
        doc.save(output)
        output.seek(0)
        
        from flask import send_file
        filename = f"phishing_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.docx"
        
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            as_attachment=True,
            download_name=filename,
            max_age=0
        )
    except Exception as e:
        import traceback
        print(f'Export report error: {str(e)}')
        print(traceback.format_exc())
        return jsonify({'error': f'导出失败: {str(e)}'}), 500


@api_bp.route('/analysis-records', methods=['GET'])
@login_required
def get_analysis_records():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    is_phishing = request.args.get('is_phishing')

    query = AnalysisResult.query.join(EmailRecord)
    if start_date:
        query = query.filter(EmailRecord.received_at >= datetime.strptime(start_date, '%Y-%m-%d'))
    if end_date:
        query = query.filter(EmailRecord.received_at <= datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1))
    if is_phishing is not None:
        query = query.filter_by(is_phishing=is_phishing == 'true')

    pagination = query.order_by(AnalysisResult.analyzed_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    records = []
    for ar in pagination.items:
        e = ar.email
        records.append({
            'id': ar.id,
            'email_id': e.id,
            'subject': e.subject,
            'from_email': e.from_email,
            'received_at': e.received_at.strftime('%Y-%m-%d %H:%M:%S') if e.received_at else None,
            'is_phishing': ar.is_phishing,
            'confidence': ar.confidence,
            'risk_level': ar.risk_level,
            'phishing_type': ar.phishing_type,
            'indicators': ar.indicators,
            'analyzed_at': ar.analyzed_at.strftime('%Y-%m-%d %H:%M:%S'),
            'status': e.status
        })

    return jsonify({
        'items': records,
        'total': pagination.total,
        'pages': pagination.pages,
        'page': page
    })


@api_bp.route('/emails/<int:id>/download', methods=['GET'])
@login_required
def download_email(id):
    email = EmailRecord.query.get_or_404(id)
    if not email.raw_content:
        return jsonify({'error': '该邮件没有原始内容'}), 404
    
    import io
    import base64
    filename = f"{email.message_id[:30] if email.message_id else email.id}.eml"
    filename = filename.replace('/', '_').replace('\\', '_').replace(':', '_')
    
    raw_bytes = base64.b64decode(email.raw_content)
    response = make_response(raw_bytes)
    response.headers['Content-Type'] = 'message/rfc822'
    response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response


@api_bp.route('/sent-emails', methods=['GET'])
@login_required
def get_sent_emails():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    query = ReplyRecord.query.order_by(ReplyRecord.sent_at.desc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    
    records = []
    for r in pagination.items:
        record = r.to_dict()
        if r.email:
            record['original_subject'] = r.email.subject
            record['original_from'] = r.email.from_email
        else:
            record['original_subject'] = None
            record['original_from'] = None
        records.append(record)
    
    return jsonify({
        'items': records,
        'total': pagination.total,
        'pages': pagination.pages,
        'page': page
    })


@api_bp.route('/sent-emails/sync', methods=['POST'])
@admin_required
def sync_sent_emails():
    """从邮件服务器同步已发送邮件到发件箱"""
    mail_server = MailServerConfig.query.filter_by(is_active=True).first()
    if not mail_server:
        return jsonify({'error': '未配置活跃的邮件服务器'}), 400
    
    service = EmailService(mail_server)
    result = service.fetch_sent_emails(limit=50)
    
    if not result['success']:
        return jsonify({'error': result['message']}), 500
    
    synced_count = 0
    for email_data in result['emails']:
        # 检查是否已存在
        existing = ReplyRecord.query.filter_by(message_id=email_data['message_id']).first()
        if existing:
            continue
        
        reply = ReplyRecord(
            email_id=None,
            reply_to=email_data['to_email'],
            from_email=email_data['from_email'],
            subject=email_data['subject'],
            body=email_data['body'],
            raw_content=email_data['raw_content'],
            sent_at=email_data['received_at'],
            status='sent'
        )
        db.session.add(reply)
        synced_count += 1
    
    db.session.commit()
    return jsonify({'message': f'成功同步 {synced_count} 封已发送邮件', 'synced': synced_count})


@api_bp.route('/sent-emails/<int:id>', methods=['GET'])
@login_required
def get_sent_email(id):
    reply = ReplyRecord.query.get_or_404(id)
    record = reply.to_dict()
    if reply.email:
        record['original_subject'] = reply.email.subject
        record['original_from'] = reply.email.from_email
    return jsonify(record)


@api_bp.route('/sent-emails/export', methods=['GET'])
@login_required
def export_sent_emails():
    from datetime import datetime
    import csv
    from io import StringIO
    from flask import make_response
    
    records = ReplyRecord.query.order_by(ReplyRecord.sent_at.desc()).all()
    
    output = StringIO()
    writer = csv.writer(output)
    
    writer.writerow(['发送时间', '发件人', '收件人', '主题', '状态', '原始邮件主题', '原始邮件发件人'])
    
    for r in records:
        original_subject = r.email.subject if r.email else ''
        original_from = r.email.from_email if r.email else ''
        writer.writerow([
            r.sent_at.strftime('%Y-%m-%d %H:%M:%S') if r.sent_at else '',
            r.from_email or '',
            r.reply_to or '',
            r.subject or '',
            r.status or '',
            original_subject,
            original_from
        ])
    
    output.seek(0)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = f'attachment; filename=sent_emails_{timestamp}.csv'
    response.headers['Content-Type'] = 'text/csv; charset=utf-8'
    return response


@api_bp.route('/sent-emails/<int:id>/download', methods=['GET'])
@login_required
def download_sent_email(id):
    reply = ReplyRecord.query.get_or_404(id)
    if not reply.raw_content:
        return jsonify({'error': '该邮件没有原始内容'}), 404
    
    import io
    import base64
    filename = f"sent_email_{reply.id}.eml"
    
    raw_bytes = base64.b64decode(reply.raw_content)
    response = make_response(raw_bytes)
    response.headers['Content-Type'] = 'message/rfc822'
    response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response


@api_bp.route('/send-test-email', methods=['POST'])
@admin_required
def send_test_email():
    data = request.get_json()
    to_email = data.get('to_email')
    subject = data.get('subject', '测试邮件')
    body = data.get('body', '这是一封测试邮件，用于验证邮件服务器配置是否正常。')

    if not to_email:
        return jsonify({'success': False, 'message': '请输入收件人邮箱'}), 400

    mail_server = MailServerConfig.query.filter_by(is_active=True).first()
    if not mail_server:
        return jsonify({'success': False, 'message': '未配置活跃的邮件服务器'}), 400

    service = EmailService(mail_server)
    result = service.send_reply(to_email, subject, body)
    return jsonify(result)


@api_bp.route('/import-eml', methods=['POST'])
@login_required
def import_eml():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': '未选择文件'}), 400
    
    file = request.files['file']
    if not file.filename:
        return jsonify({'success': False, 'message': '未选择文件'}), 400
    
    if not file.filename.lower().endswith('.eml'):
        return jsonify({'success': False, 'message': '只支持 .eml 格式文件'}), 400
    
    try:
        eml_content = file.read()
        
        from src.services.eml_parser_service import EmlParserService
        parsed = EmlParserService.parse_eml_file(eml_content)
        
        if not parsed.get('success'):
            return jsonify({'success': False, 'message': f'解析文件失败: {parsed.get("error", "未知错误")}'}), 400
        
        existing_email = EmailRecord.query.filter_by(message_id=parsed['message_id']).first()
        if existing_email:
            return jsonify({'success': False, 'message': f'邮件已存在 (ID: {existing_email.id})'}), 400
        
        email_record = EmailRecord(
            message_id=parsed['message_id'],
            subject=parsed['subject'],
            from_email=parsed['from_email'],
            to_email=parsed['to_email'],
            cc_email=parsed['cc_email'],
            body=parsed['body'],
            raw_content=parsed['raw_content'],
            attachments=parsed['attachments'],
            received_at=parsed['received_at'],
            status='pending',
            source='import'
        )
        db.session.add(email_record)
        db.session.commit()
        
        log_audit('导入离线邮件', 'email', 'email', f'主题: {parsed["subject"]}, 发件人: {parsed["from_email"]}')
        
        return jsonify({
            'success': True,
            'message': '邮件导入成功',
            'email_id': email_record.id,
            'subject': parsed['subject'],
            'from_email': parsed['from_email']
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'导入失败: {str(e)}'}), 500


@api_bp.route('/batch-import-eml', methods=['POST'])
@admin_required
def batch_import_eml():
    files = request.files.getlist('files')
    if not files:
        return jsonify({'success': False, 'message': '未选择文件'}), 400
    
    success_count = 0
    fail_count = 0
    duplicate_count = 0
    results = []
    
    from src.services.eml_parser_service import EmlParserService
    
    for file in files:
        if not file or not file.filename:
            continue
        
        if not file.filename.lower().endswith('.eml'):
            results.append({'filename': file.filename, 'success': False, 'message': '不是 .eml 格式'})
            fail_count += 1
            continue
        
        try:
            eml_content = file.read()
            parsed = EmlParserService.parse_eml_file(eml_content)
            
            if not parsed.get('success'):
                results.append({'filename': file.filename, 'success': False, 'message': parsed.get('error', '解析失败')})
                fail_count += 1
                continue
            
            existing_email = EmailRecord.query.filter_by(message_id=parsed['message_id']).first()
            if existing_email:
                results.append({'filename': file.filename, 'success': False, 'message': '邮件已存在', 'email_id': existing_email.id})
                duplicate_count += 1
                continue
            
            email_record = EmailRecord(
                message_id=parsed['message_id'],
                subject=parsed['subject'],
                from_email=parsed['from_email'],
                to_email=parsed['to_email'],
                cc_email=parsed['cc_email'],
                body=parsed['body'],
                raw_content=parsed['raw_content'],
                attachments=parsed['attachments'],
                received_at=parsed['received_at'],
                status='pending',
                source='import'
            )
            db.session.add(email_record)
            success_count += 1
            results.append({'filename': file.filename, 'success': True, 'message': '导入成功', 'email_id': email_record.id})
        except Exception as e:
            results.append({'filename': file.filename, 'success': False, 'message': str(e)})
            fail_count += 1
    
    db.session.commit()
    
    if success_count > 0:
        log_audit('批量导入离线邮件', 'email', 'email', f'成功: {success_count}, 重复: {duplicate_count}, 失败: {fail_count}')
    
    return jsonify({
        'success': True,
        'message': f'导入完成: 成功 {success_count} 封, 重复 {duplicate_count} 封, 失败 {fail_count} 封',
        'success_count': success_count,
        'duplicate_count': duplicate_count,
        'fail_count': fail_count,
        'results': results
    })


@api_bp.route('/threat-intel/configs', methods=['GET'])
@admin_required
def get_threat_intel_configs():
    configs = ThreatIntelConfig.query.order_by(ThreatIntelConfig.created_at.desc()).all()
    return jsonify([c.to_dict() for c in configs])


@api_bp.route('/threat-intel/configs', methods=['POST'])
@admin_required
def create_threat_intel_config():
    data = request.get_json()
    name = data.get('name')
    provider = data.get('provider')
    api_key = data.get('api_key')
    api_base_url = data.get('api_base_url')

    if not name or not provider or not api_key:
        return jsonify({'success': False, 'message': '名称、情报源类型和API Key必填'}), 400

    if ThreatIntelConfig.query.filter_by(name=name).first():
        return jsonify({'success': False, 'message': '配置名称已存在'}), 400

    config = ThreatIntelConfig(
        name=name,
        provider=provider,
        api_key=api_key,
        api_base_url=api_base_url
    )
    db.session.add(config)
    db.session.commit()
    return jsonify({'success': True, 'message': '配置创建成功', 'config': config.to_dict()})


@api_bp.route('/threat-intel/configs/<int:id>', methods=['PUT'])
@admin_required
def update_threat_intel_config(id):
    config = ThreatIntelConfig.query.get_or_404(id)
    data = request.get_json()

    if data.get('name'):
        config.name = data['name']
    if data.get('provider'):
        config.provider = data['provider']
    if data.get('api_key'):
        config.api_key = data['api_key']
    if 'api_base_url' in data:
        config.api_base_url = data['api_base_url']
    if 'is_active' in data:
        config.is_active = data['is_active']

    db.session.commit()
    return jsonify({'success': True, 'message': '配置更新成功', 'config': config.to_dict()})


@api_bp.route('/threat-intel/configs/<int:id>', methods=['DELETE'])
@admin_required
def delete_threat_intel_config(id):
    config = ThreatIntelConfig.query.get_or_404(id)
    db.session.delete(config)
    db.session.commit()
    return jsonify({'success': True, 'message': '配置删除成功'})


@api_bp.route('/threat-intel/query', methods=['POST'])
@login_required
def query_threat_intel():
    data = request.get_json()
    query_type = data.get('query_type')
    query_value = data.get('query_value')
    config_id = data.get('config_id')

    if not query_type or not query_value:
        return jsonify({'success': False, 'message': '查询类型和查询值必填'}), 400

    if config_id:
        config = ThreatIntelConfig.query.get(config_id)
        if not config:
            return jsonify({'success': False, 'message': '情报源配置不存在'}), 404
    else:
        config = ThreatIntelConfig.query.filter_by(is_active=True).first()
        if not config:
            return jsonify({'success': False, 'message': '未配置活跃的情报源'}), 400

    from src.services.threat_intel_service import ThreatIntelService
    service = ThreatIntelService(config)

    if query_type == 'ip':
        result = service.query_ip(query_value)
    elif query_type == 'domain':
        result = service.query_domain(query_value)
    elif query_type == 'url':
        result = service.query_url(query_value)
    elif query_type == 'file':
        result = service.query_file(query_value)
    else:
        return jsonify({'success': False, 'message': '不支持的查询类型'}), 400

    if result.get('success'):
        import json
        record = ThreatIntelRecord(
            query_type=query_type,
            query_value=query_value,
            provider=config.provider,
            is_malicious=result.get('is_malicious'),
            threat_type=result.get('threat_type'),
            confidence=result.get('confidence'),
            raw_result=json.dumps(result.get('raw_data'), ensure_ascii=False) if result.get('raw_data') else None
        )
        db.session.add(record)
        db.session.commit()
        result['record_id'] = record.id

    return jsonify(result)


@api_bp.route('/threat-intel/analyze', methods=['POST'])
@login_required
def analyze_threat_intel():
    data = request.get_json()
    query_type = data.get('query_type')
    query_value = data.get('query_value')
    intel_result = data.get('intel_result')

    if not query_type or not query_value or not intel_result:
        return jsonify({'success': False, 'message': '查询类型、查询值和情报结果必填'}), 400

    llm_config = LLMConfig.query.filter_by(is_active=True).first()
    if not llm_config:
        return jsonify({'success': False, 'message': '未配置大模型，请先在系统配置中添加LLM配置'}), 400

    import json as json_module
    import requests as req_lib

    type_labels = {'ip': 'IP地址', 'domain': '域名', 'url': 'URL', 'file': '文件哈希'}
    type_name = type_labels.get(query_type, query_type)

    details = intel_result.get('details', {})
    detail_lines = []
    for key, value in details.items():
        if isinstance(value, (list, dict)):
            value = json_module.dumps(value, ensure_ascii=False)
        detail_lines.append(f"  - {key}: {value}")

    is_malicious = intel_result.get('is_malicious', False)
    threat_type = intel_result.get('threat_type', '-')
    confidence = intel_result.get('confidence', 0)
    provider = intel_result.get('provider', '-')
    provider_names = {'threatbook': '微步在线', 'virustotal': 'VirusTotal', 'abuseipdb': 'AbuseIPDB'}
    provider_name = provider_names.get(provider, provider)

    prompt = f"""你是一位专业的网络安全威胁分析师。请根据以下威胁情报查询结果，对该{type_name}进行深入分析和评估。

【查询目标】
{type_name}: {query_value}

【情报来源】
{provider_name}

【检测结果】
- 是否恶意: {'是' if is_malicious else '否'}
- 威胁类型: {threat_type}
- 置信度: {confidence * 100:.1f}%

【详细信息】
{chr(10).join(detail_lines)}

请从以下几个方面进行分析：
1. 威胁级别评估：根据情报数据，评估该{type_name}的威胁等级（高危/中危/低危/安全），并说明理由
2. 风险分析：分析该{type_name}可能对企业网络和信息安全造成的潜在风险
3. 处置建议：给出具体的防护和处置建议（如封禁、监控、告警配置等）
4. 补充说明：其他需要注意的事项

请用清晰、专业的语言输出分析结果，分点陈述，便于阅读。"""

    try:
        headers = {
            'Authorization': f'Bearer {llm_config.get_api_key()}',
            'Content-Type': 'application/json'
        }
        payload = {
            'model': llm_config.model_name,
            'messages': [{'role': 'user', 'content': prompt}],
            'temperature': 0.7,
            'max_tokens': 2048
        }
        resp = req_lib.post(
            f'{llm_config.api_base_url.rstrip("/")}/chat/completions',
            headers=headers,
            json=payload,
            timeout=60
        )
        resp_data = resp.json()

        if 'choices' in resp_data and len(resp_data['choices']) > 0:
            content = resp_data['choices'][0]['message']['content']
            return jsonify({'success': True, 'analysis': content})
        else:
            return jsonify({'success': False, 'message': resp_data.get('error', {}).get('message', 'AI分析失败')})
    except Exception as e:
        return jsonify({'success': False, 'message': f'AI分析异常: {str(e)}'}), 500


@api_bp.route('/threat-intel/records', methods=['GET'])
@login_required
def get_threat_intel_records():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    query_type = request.args.get('query_type')
    is_malicious = request.args.get('is_malicious')

    query = ThreatIntelRecord.query

    if query_type:
        query = query.filter(ThreatIntelRecord.query_type == query_type)
    if is_malicious is not None and is_malicious != '':
        query = query.filter(ThreatIntelRecord.is_malicious == (is_malicious == 'true'))

    pagination = query.order_by(ThreatIntelRecord.queried_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    return jsonify({
        'items': [r.to_dict() for r in pagination.items],
        'total': pagination.total,
        'pages': pagination.pages,
        'page': page
    })


@api_bp.route('/threat-intel/export', methods=['GET'])
@admin_required
def export_threat_intel():
    import csv
    from io import StringIO
    from flask import Response

    query_type = request.args.get('query_type')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    limit = request.args.get('limit', type=int)

    query = ThreatIntelRecord.query
    if query_type:
        query = query.filter(ThreatIntelRecord.query_type == query_type)
    if start_date:
        query = query.filter(ThreatIntelRecord.queried_at >= datetime.strptime(start_date, '%Y-%m-%d'))
    if end_date:
        query = query.filter(ThreatIntelRecord.queried_at <= datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1))

    query = query.order_by(ThreatIntelRecord.queried_at.desc())
    if limit:
        query = query.limit(limit)

    records = query.all()

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['查询时间', '查询类型', '查询值', '情报源', '是否恶意', '威胁类型', '置信度'])

    for r in records:
        writer.writerow([
            r.queried_at.strftime('%Y-%m-%d %H:%M:%S') if r.queried_at else '',
            r.query_type or '',
            r.query_value or '',
            r.provider or '',
            '是' if r.is_malicious else ('否' if r.is_malicious is False else '未知'),
            r.threat_type or '',
            f'{r.confidence * 100:.1f}%' if r.confidence else '-'
        ])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv; charset=utf-8',
        headers={
            'Content-Disposition': f'attachment; filename=threat_intel_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv',
            'Content-Type': 'text/csv; charset=utf-8'
        }
    )


@api_bp.route('/threat-intel/overview', methods=['GET'])
@login_required
def get_threat_intel_overview():
    total_count = ThreatIntelRecord.query.count()
    malicious_count = ThreatIntelRecord.query.filter_by(is_malicious=True).count()
    safe_count = ThreatIntelRecord.query.filter_by(is_malicious=False).count()
    
    today = datetime.now().date()
    today_count = ThreatIntelRecord.query.filter(
        ThreatIntelRecord.queried_at >= datetime(today.year, today.month, today.day)
    ).count()
    
    recent_threats = ThreatIntelRecord.query \
        .filter_by(is_malicious=True) \
        .order_by(ThreatIntelRecord.queried_at.desc()) \
        .limit(10) \
        .all()
    
    return jsonify({
        'total_count': total_count,
        'malicious_count': malicious_count,
        'safe_count': safe_count,
        'today_count': today_count,
        'recent_threats': [{'query_value': r.query_value, 'threat_type': r.threat_type} for r in recent_threats]
    })


@api_bp.route('/audit-logs', methods=['GET'])
@admin_required
def get_audit_logs():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    username = request.args.get('username')
    action_type = request.args.get('action_type')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    query = AuditLog.query

    if username:
        query = query.filter(AuditLog.username.like(f'%{username}%'))
    if action_type:
        query = query.filter(AuditLog.action_type == action_type)
    if start_date:
        query = query.filter(AuditLog.created_at >= datetime.strptime(start_date, '%Y-%m-%d'))
    if end_date:
        query = query.filter(AuditLog.created_at <= datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1))

    pagination = query.order_by(AuditLog.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    return jsonify({
        'items': [r.to_dict() for r in pagination.items],
        'total': pagination.total,
        'pages': pagination.pages,
        'page': page
    })


@api_bp.route('/audit-logs/export', methods=['GET'])
@admin_required
def export_audit_logs():
    import csv
    from io import StringIO

    username = request.args.get('username')
    action_type = request.args.get('action_type')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    query = AuditLog.query

    if username:
        query = query.filter(AuditLog.username.like(f'%{username}%'))
    if action_type:
        query = query.filter(AuditLog.action_type == action_type)
    if start_date:
        query = query.filter(AuditLog.created_at >= datetime.strptime(start_date, '%Y-%m-%d'))
    if end_date:
        query = query.filter(AuditLog.created_at <= datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1))

    logs = query.order_by(AuditLog.created_at.desc()).all()

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['时间', '用户名', '操作类型', '操作描述', '资源', 'IP地址', '详情', 'User-Agent'])

    type_labels = {
        'login': '登录', 'logout': '退出', 'config': '配置管理',
        'email': '邮件操作', 'analysis': '分析操作', 'user': '用户管理',
        'intel': '情报查询', 'update': '更新', 'create': '创建', 'batch_update': '批量更新'
    }

    for log in logs:
        writer.writerow([
            log.created_at.strftime('%Y-%m-%d %H:%M:%S') if log.created_at else '',
            log.username or '',
            type_labels.get(log.action_type, log.action_type or ''),
            log.action or '',
            log.resource or '',
            log.ip_address or '',
            log.detail or '',
            log.user_agent or ''
        ])

    output.seek(0)
    from flask import Response
    return Response(
        output.getvalue(),
        mimetype='text/csv; charset=utf-8',
        headers={
            'Content-Disposition': f'attachment; filename=audit_logs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv',
            'Content-Type': 'text/csv; charset=utf-8'
        }
    )


@api_bp.route('/task-queue/status', methods=['GET'])
@login_required
def get_task_queue_status():
    pending_count = EmailRecord.query.filter_by(status='pending').count()
    processing_count = EmailRecord.query.filter_by(status='processing').count()
    analyzed_count = EmailRecord.query.filter_by(status='analyzed').count()
    replied_count = EmailRecord.query.filter_by(status='replied').count()
    
    return jsonify({
        'pending': pending_count,
        'processing': processing_count,
        'analyzed': analyzed_count,
        'replied': replied_count
    })


@api_bp.route('/task-queue/tasks', methods=['GET'])
@login_required
def get_task_queue_tasks():
    status = request.args.get('status')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    query = EmailRecord.query
    if status:
        query = query.filter_by(status=status)
    
    query = query.order_by(EmailRecord.created_at.desc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    
    tasks = []
    for email in pagination.items:
        tasks.append({
            'id': email.id,
            'subject': email.subject or '',
            'sender': email.sender or '',
            'status': email.status or '',
            'created_at': email.created_at.strftime('%Y-%m-%d %H:%M:%S') if email.created_at else '',
            'updated_at': email.updated_at.strftime('%Y-%m-%d %H:%M:%S') if email.updated_at else ''
        })
    
    return jsonify(tasks)


@api_bp.route('/task-queue/trend', methods=['GET'])
@login_required
def get_task_queue_trend():
    from datetime import timedelta
    
    trend = []
    now = datetime.now()
    for i in range(23, -1, -1):
        hour_start = (now - timedelta(hours=i)).replace(minute=0, second=0, microsecond=0)
        hour_end = hour_start + timedelta(hours=1)
        
        count = EmailRecord.query.filter(
            EmailRecord.created_at >= hour_start,
            EmailRecord.created_at < hour_end
        ).count()
        
        trend.append({
            'hour': f'{hour_start.hour:02d}:00',
            'count': count,
            'status': 'pending'
        })
    
    return jsonify(trend)


@api_bp.route('/foxmail/status', methods=['GET'])
@login_required
def foxmail_status():
    # 确保手动配置已加载
    foxmail_service._ensure_config_loaded()
    foxmail_service._detect_foxmail()
    info = foxmail_service.get_diagnostic_info()
    return jsonify({
        'installed': foxmail_service.is_installed(),
        'foxmail_path': foxmail_service.foxmail_path,
        'data_path': foxmail_service.foxmail_data_path,
        'mapi_available': info['mapi_available'],
        'manual_exe_path': info.get('manual_exe_path'),
        'manual_storage_path': info.get('manual_storage_path'),
        'accounts': info['accounts']
    })


@api_bp.route('/foxmail/accounts', methods=['GET'])
@login_required
def foxmail_accounts():
    foxmail_service._ensure_config_loaded()
    accounts = foxmail_service.get_accounts()
    result = []
    for acc in accounts:
        folders = foxmail_service.get_folders(acc['path'])
        acc_info = acc.copy()
        acc_info['folders'] = folders
        result.append(acc_info)
    return jsonify({'accounts': result})


@api_bp.route('/foxmail/sync', methods=['POST'])
@login_required
def foxmail_sync():
    from src.services.email_pipeline import email_pipeline

    data = request.json or {}
    account_id = data.get('account_id')
    sync_inbox = data.get('sync_inbox', True)
    sync_sent = data.get('sync_sent', True)
    limit = data.get('limit', 500)
    auto_analyze = data.get('auto_analyze', True)

    # 确保手动配置已加载
    foxmail_service._ensure_config_loaded()
    foxmail_service._detect_foxmail()

    accounts = foxmail_service.get_accounts()
    if account_id:
        account = next((a for a in accounts if a['id'] == account_id), None)
        if not account:
            return jsonify({'error': '账户不存在'}), 404
        accounts_to_sync = [account]
    else:
        accounts_to_sync = accounts

    if not accounts_to_sync:
        return jsonify({'error': '未找到Foxmail账户'}), 400

    total_imported = 0
    total_sent_imported = 0
    new_email_ids = []

    for account in accounts_to_sync:
        folders = foxmail_service.get_folders(account['path'])
        inbox = next((f for f in folders if f.get('is_inbox')), None)
        sent = next((f for f in folders if f.get('is_sent')), None)

        if sync_inbox and inbox:
            print(f'同步收件箱: {account["email"]} -> {inbox["path"]}')
            emails = foxmail_service.read_emails_from_folder(inbox['path'], limit)
            before_ids = set(e.id for e in EmailRecord.query.with_entities(EmailRecord.id).all())

            for email_data in emails:
                msg_id = email_data.get('message_id', '')
                if msg_id:
                    existing = EmailRecord.query.filter_by(message_id=msg_id).first()
                    if existing:
                        continue

                new_email = EmailRecord(
                    message_id=msg_id,
                    subject=email_data.get('subject', ''),
                    from_email=email_data.get('from_email', ''),
                    to_email=email_data.get('to_email', ''),
                    cc_email=email_data.get('cc_email', ''),
                    body=email_data.get('body', ''),
                    attachments=json.dumps(email_data.get('attachments', [])),
                    received_at=email_data.get('received_at') or datetime.now(),
                    status='pending',
                    source='foxmail',
                    raw_content=email_data.get('raw_content', '')
                )
                db.session.add(new_email)
                total_imported += 1

            db.session.flush()

            after_ids = set(e.id for e in EmailRecord.query.with_entities(EmailRecord.id).all())
            new_email_ids.extend(list(after_ids - before_ids))

        if sync_sent and sent:
            print(f'同步发件箱: {account["email"]} -> {sent["path"]}')
            emails = foxmail_service.read_emails_from_folder(sent['path'], limit)
            for email_data in emails:
                msg_id = email_data.get('message_id', '')
                if msg_id:
                    existing = ReplyRecord.query.filter_by(message_id=msg_id).first()
                    if existing:
                        continue

                new_record = ReplyRecord(
                    from_email=email_data.get('from_email', account['email']),
                    to_email=email_data.get('to_email', ''),
                    subject=email_data.get('subject', ''),
                    body=email_data.get('body', ''),
                    message_id=msg_id,
                    raw_content=email_data.get('raw_content', ''),
                    sent_at=email_data.get('received_at') or datetime.now(),
                    source='foxmail'
                )
                db.session.add(new_record)
                total_sent_imported += 1

    db.session.commit()

    if new_email_ids and auto_analyze:
        try:
            pipeline_config = email_pipeline.get_config()
            if pipeline_config.get('auto_analyze', False):
                tasks = email_pipeline.auto_process_new_emails(new_email_ids)
                print(f'Foxmail同步完成，已提交 {len(tasks)} 封邮件到分析队列')
        except Exception as e:
            print(f'自动分析失败: {e}')

    return jsonify({
        'success': True,
        'imported': total_imported,
        'sent_imported': total_sent_imported,
        'total': total_imported + total_sent_imported,
        'new_email_ids': new_email_ids[:100]
    })


@api_bp.route('/foxmail/send', methods=['POST'])
@login_required
def foxmail_send():
    data = request.json or {}
    to_email = data.get('to_email')
    subject = data.get('subject', '')
    body = data.get('body', '')
    cc_email = data.get('cc_email')

    if not to_email:
        return jsonify({'error': '收件人不能为空'}), 400

    success, msg = foxmail_service.send_email_via_mapi(to_email, subject, body, cc_email)
    return jsonify({'success': success, 'message': msg})


@api_bp.route('/foxmail/config', methods=['GET'])
@login_required
def get_foxmail_config():
    from src.models.db import FoxmailConfig
    config = FoxmailConfig.query.filter_by(name='default').first()
    if not config:
        config = FoxmailConfig(name='default')
        db.session.add(config)
        db.session.commit()
    return jsonify(config.to_dict())


@api_bp.route('/foxmail/config', methods=['POST'])
@login_required
def save_foxmail_config():
    from src.models.db import FoxmailConfig
    data = request.json or {}

    config = FoxmailConfig.query.filter_by(name='default').first()
    if not config:
        config = FoxmailConfig(name='default')
        db.session.add(config)

    exe_path = data.get('foxmail_exe_path', '').strip() or None
    storage_path = data.get('storage_path', '').strip() or None

    # 验证路径是否存在
    if exe_path and not os.path.exists(exe_path):
        return jsonify({'error': f'Foxmail.exe路径不存在: {exe_path}'}), 400
    if storage_path and not os.path.exists(storage_path):
        return jsonify({'error': f'存储目录路径不存在: {storage_path}'}), 400

    # 验证exe文件是否有效
    if exe_path and not exe_path.lower().endswith('foxmail.exe'):
        return jsonify({'error': '请选择Foxmail.exe文件'}), 400

    config.foxmail_exe_path = exe_path
    config.storage_path = storage_path
    config.auto_sync_enabled = data.get('auto_sync_enabled', True)
    config.sync_inbox = data.get('sync_inbox', True)
    config.sync_sent = data.get('sync_sent', True)
    config.sync_interval_minutes = int(data.get('sync_interval_minutes', 5))
    config.is_active = data.get('is_active', True)
    db.session.commit()

    # 重新加载Foxmail服务配置
    try:
        foxmail_service.reload_config()
    except Exception as e:
        print(f'重新加载Foxmail配置失败: {e}')

    return jsonify({'success': True, 'message': 'Foxmail配置已保存', 'config': config.to_dict()})


@api_bp.route('/foxmail/browse-path', methods=['POST'])
@login_required
def browse_foxmail_path():
    """返回路径浏览建议（Windows下常用Foxmail路径）"""
    common_paths = [
        r'D:\Foxmail 7.2\Foxmail.exe',
        r'D:\Foxmail\Foxmail.exe',
        r'C:\Program Files\Foxmail\Foxmail.exe',
        r'C:\Program Files (x86)\Foxmail\Foxmail.exe',
        r'C:\Foxmail\Foxmail.exe',
        r'E:\Foxmail 7.2\Foxmail.exe',
        r'E:\Foxmail\Foxmail.exe',
    ]
    data = request.json or {}
    browse_type = data.get('type', 'exe')  # 'exe' 或 'dir'
    if browse_type == 'exe':
        existing = [p for p in common_paths if os.path.exists(p)]
        return jsonify({'paths': existing, 'common_paths': common_paths})
    else:
        # 存储目录建议
        suggestions = []
        appdata = os.environ.get('APPDATA', '')
        localappdata = os.environ.get('LOCALAPPDATA', '')
        if appdata:
            suggestions.append(os.path.join(appdata, 'Foxmail'))
        if localappdata:
            suggestions.append(os.path.join(localappdata, 'Foxmail'))
        if foxmail_service.foxmail_path:
            d = os.path.dirname(foxmail_service.foxmail_path)
            suggestions.extend([os.path.join(d, 'Data'), os.path.join(d, 'Storage'), os.path.join(d, 'mail')])
        return jsonify({'suggestions': suggestions})


@api_bp.route('/foxmail/validate-path', methods=['POST'])
@login_required
def validate_foxmail_path():
    """验证路径并显示检测结果"""
    data = request.json or {}
    path = data.get('path', '').strip()
    path_type = data.get('type', 'storage')  # 'exe' 或 'storage'

    if not path:
        return jsonify({'valid': False, 'message': '路径不能为空'}), 400
    if not os.path.exists(path):
        return jsonify({'valid': False, 'message': '路径不存在'}), 400

    if path_type == 'exe':
        if not os.path.isfile(path):
            return jsonify({'valid': False, 'message': '请选择文件而不是目录'}), 400
        if not path.lower().endswith('foxmail.exe'):
            return jsonify({'valid': False, 'message': '请选择Foxmail.exe文件'}), 400
        return jsonify({'valid': True, 'message': 'Foxmail.exe有效', 'path': path})

    # 存储目录验证
    if not os.path.isdir(path):
        return jsonify({'valid': False, 'message': '请选择目录而不是文件'}), 400

    # 检查是否包含账户目录
    foxmail_service._ensure_config_loaded()
    accounts_found = []

    # 1. 检查 Accounts 目录
    accounts_path = os.path.join(path, 'Accounts')
    if os.path.exists(accounts_path):
        for item in os.listdir(accounts_path):
            item_path = os.path.join(accounts_path, item)
            if os.path.isdir(item_path) and foxmail_service._is_account_dir(item_path):
                accounts_found.append(item)
        if accounts_found:
            return jsonify({
                'valid': True,
                'message': f'检测到 {len(accounts_found)} 个账户（Accounts目录）',
                'path': path,
                'accounts': accounts_found,
                'structure': 'Accounts'
            })

    # 2. 检查 Storage 目录
    storage_path = os.path.join(path, 'Storage')
    if os.path.exists(storage_path):
        for item in os.listdir(storage_path):
            item_path = os.path.join(storage_path, item)
            if os.path.isdir(item_path) and foxmail_service._is_account_dir(item_path):
                accounts_found.append(item)
        if accounts_found:
            return jsonify({
                'valid': True,
                'message': f'检测到 {len(accounts_found)} 个账户（Storage目录）',
                'path': path,
                'accounts': accounts_found,
                'structure': 'Storage'
            })

    # 3. 检查是否就是账户目录
    if foxmail_service._is_account_dir(path):
        return jsonify({
            'valid': True,
            'message': f'检测到账户目录: {os.path.basename(path)}',
            'path': path,
            'accounts': [os.path.basename(path)],
            'structure': 'account_dir'
        })

    # 4. 检查path本身直接存放账户目录（没有Accounts/Storage包裹）
    sub_accounts = []
    try:
        for item in os.listdir(path):
            item_path = os.path.join(path, item)
            if os.path.isdir(item_path) and foxmail_service._is_account_dir(item_path):
                sub_accounts.append(item)
    except Exception:
        pass

    if sub_accounts:
        return jsonify({
            'valid': True,
            'message': f'检测到 {len(sub_accounts)} 个账户',
            'path': path,
            'accounts': sub_accounts,
            'structure': 'direct'
        })

    return jsonify({
        'valid': False,
        'message': '该目录下未检测到任何Foxmail账户（需要包含Account.stg或含.box文件的文件夹）',
        'path': path,
        'accounts': []
    })


@api_bp.route('/system/ip-info', methods=['GET'])
@login_required
def get_ip_info():
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
    
    return jsonify({
        'hostname': hostname,
        'ipv4_addresses': ipv4_addresses,
        'ipv6_addresses': ipv6_addresses,
        'port': 80
    })


@api_bp.route('/version', methods=['GET'])
def get_version():
    version = VersionInfo.query.filter_by(is_active=True).order_by(VersionInfo.id.desc()).first()
    if not version:
        version = VersionInfo(
            version='V1.0',
            update_content='初始版本',
            is_active=True
        )
        db.session.add(version)
        db.session.commit()
    return jsonify(version.to_dict())


@api_bp.route('/versions', methods=['GET'])
@admin_required
def get_versions():
    versions = VersionInfo.query.order_by(VersionInfo.id.desc()).all()
    return jsonify([v.to_dict() for v in versions])


@api_bp.route('/versions/<int:id>', methods=['PUT'])
@admin_required
def update_version(id):
    version = VersionInfo.query.get_or_404(id)
    data = request.get_json()
    version.version = data.get('version', version.version)
    version.update_content = data.get('update_content', version.update_content)
    version.release_date = data.get('release_date', version.release_date)
    version.is_active = data.get('is_active', version.is_active)
    db.session.commit()
    log_audit('更新版本信息', 'update', 'version', f'版本号: {version.version}')
    return jsonify(version.to_dict())


@api_bp.route('/versions', methods=['POST'])
@admin_required
def create_version():
    data = request.get_json()
    version = VersionInfo(
        version=data['version'],
        update_content=data.get('update_content', ''),
        is_active=data.get('is_active', True)
    )
    db.session.add(version)
    db.session.commit()
    log_audit('创建版本信息', 'create', 'version', f'版本号: {version.version}')
    return jsonify(version.to_dict()), 201


@api_bp.route('/chat/conversations', methods=['GET'])
@login_required
def get_chat_conversations():
    conversations = ChatConversation.query.filter_by(user_id=session['user_id']).order_by(ChatConversation.updated_at.desc()).all()
    return jsonify([c.to_dict() for c in conversations])


@api_bp.route('/chat/conversations', methods=['POST'])
@login_required
def create_chat_conversation():
    data = request.get_json() or {}
    conversation = ChatConversation(
        user_id=session['user_id'],
        title=data.get('title', '新对话'),
        llm_config_id=data.get('llm_config_id')
    )
    db.session.add(conversation)
    db.session.commit()
    return jsonify(conversation.to_dict()), 201


@api_bp.route('/chat/conversations/<int:id>', methods=['DELETE'])
@login_required
def delete_chat_conversation(id):
    conv = ChatConversation.query.get_or_404(id)
    if conv.user_id != session['user_id']:
        return jsonify({'error': '无权操作'}), 403
    ChatMessage.query.filter_by(conversation_id=id).delete()
    db.session.delete(conv)
    db.session.commit()
    return jsonify({'message': '已删除'})


@api_bp.route('/chat/conversations/<int:id>/messages', methods=['GET'])
@login_required
def get_chat_messages(id):
    conv = ChatConversation.query.get_or_404(id)
    if conv.user_id != session['user_id']:
        return jsonify({'error': '无权操作'}), 403
    messages = ChatMessage.query.filter_by(conversation_id=id).order_by(ChatMessage.id).all()
    return jsonify([m.to_dict() for m in messages])


@api_bp.route('/chat/conversations/<int:id>/title', methods=['PUT'])
@login_required
def update_chat_title(id):
    conv = ChatConversation.query.get_or_404(id)
    if conv.user_id != session['user_id']:
        return jsonify({'error': '无权操作'}), 403
    data = request.get_json()
    conv.title = data.get('title', conv.title)
    db.session.commit()
    return jsonify(conv.to_dict())


@api_bp.route('/chat/stream', methods=['POST'])
@login_required
def chat_stream():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': '请求体不能为空'}), 400
        
        message = data.get('message', '').strip()
        conversation_id = data.get('conversation_id')
        llm_config_id = data.get('llm_config_id')

        if not message:
            return jsonify({'error': '消息不能为空'}), 400

        llm_config = None
        if llm_config_id:
            llm_config = LLMConfig.query.get(llm_config_id)
        if not llm_config:
            llm_config = LLMConfig.query.filter_by(is_active=True).first()
        if not llm_config:
            return jsonify({'error': '未配置大模型，请先在系统配置中添加LLM配置'}), 400

        if not conversation_id:
            conv_title = message[:50] if message else '[新对话]'
            conv = ChatConversation(
                user_id=session['user_id'],
                title=conv_title,
                llm_config_id=llm_config.id
            )
            db.session.add(conv)
            db.session.commit()
            conversation_id = conv.id
        else:
            conv = ChatConversation.query.get(conversation_id)
            if not conv or conv.user_id != session['user_id']:
                return jsonify({'error': '对话不存在'}), 404

        user_msg = ChatMessage(
            conversation_id=conversation_id,
            role='user',
            content=message
        )
        db.session.add(user_msg)
        db.session.commit()

        history = ChatMessage.query.filter_by(conversation_id=conversation_id).order_by(ChatMessage.id).all()

        api_messages = []
        for m in history:
            api_messages.append({'role': m.role, 'content': m.content})

        llm_api_key = llm_config.get_api_key()
        llm_model_name = llm_config.model_name
        llm_api_base_url = llm_config.api_base_url

        system_prompt = """你是一个专业的网络安全智能助手，专注于邮件安全分析、威胁情报查询和安全策略建议。

你的职责包括：
1. **邮件安全分析**：帮助用户分析可疑邮件的特征，包括发件人信息、邮件内容、链接安全性、附件风险等
2. **钓鱼邮件识别**：识别钓鱼邮件的常见特征和社会工程学手法，提供防范建议
3. **威胁情报分析**：分析邮件威胁类型，提供威胁情报收集和分析方法
4. **安全策略建议**：为企业和个人提供邮件安全最佳实践和防护体系建设建议
5. **安全工具开发**：帮助编写安全检测脚本和工具

请用专业、准确的语言回答，提供清晰的分析框架和实用的建议。"""

        api_messages.insert(0, {'role': 'system', 'content': system_prompt})

        import requests as req_lib

        app = current_app._get_current_object()

        def generate():
            full_content = ''
            try:
                headers = {
                    'Authorization': f'Bearer {llm_api_key}',
                    'Content-Type': 'application/json'
                }
                payload = {
                    'model': llm_model_name,
                    'messages': api_messages,
                    'stream': True,
                    'temperature': 0.5,
                    'max_tokens': 4096,
                    'top_p': 0.9,
                    'frequency_penalty': 0,
                    'presence_penalty': 0
                }
                
                resp = req_lib.post(
                    f'{llm_api_base_url.rstrip("/")}/chat/completions',
                    headers=headers,
                    json=payload,
                    stream=True,
                    timeout=60
                )

                if not resp.ok:
                    err_text = resp.text[:500]
                    yield f"data: {json.dumps({'error': f'LLM API错误 ({resp.status_code}): {err_text}'}, ensure_ascii=False)}\n\n"
                    return

                for line in resp.iter_lines():
                    if line:
                        line = line.decode('utf-8')
                        if line.startswith('data: '):
                            data_str = line[6:]
                            if data_str.strip() == '[DONE]':
                                break
                            try:
                                chunk = json.loads(data_str)
                                if chunk.get('error'):
                                    err_msg = chunk['error']['message'] if isinstance(chunk['error'], dict) else str(chunk['error'])
                                    yield f"data: {json.dumps({'error': err_msg}, ensure_ascii=False)}\n\n"
                                    return
                                delta = chunk.get('choices', [{}])[0].get('delta', {})
                                content = delta.get('content', '')
                                if content:
                                    full_content += content
                                    yield f"data: {json.dumps({'content': content, 'conversation_id': conversation_id}, ensure_ascii=False)}\n\n"
                            except json.JSONDecodeError:
                                continue
                
                with app.app_context():
                    assistant_msg = ChatMessage(
                        conversation_id=conversation_id,
                        role='assistant',
                        content=full_content
                    )
                    db.session.add(assistant_msg)
                    conv = ChatConversation.query.get(conversation_id)
                    if conv:
                        conv.updated_at = datetime.now()
                    db.session.commit()

                yield f"data: {json.dumps({'done': True, 'conversation_id': conversation_id}, ensure_ascii=False)}\n\n"

            except Exception as e:
                import traceback
                print(f"[Chat] Stream error: {e}")
                traceback.print_exc()
                yield f"data: {json.dumps({'error': str(e)}, ensure_ascii=False)}\n\n"

        response = current_app.response_class(generate(), mimetype='text/event-stream')
        response.headers['Cache-Control'] = 'no-cache'
        response.headers['X-Accel-Buffering'] = 'no'
        return response

    except Exception as e:
        import traceback
        print(f"[Chat] Setup error: {e}")
        traceback.print_exc()
        return jsonify({'error': f'服务器内部错误: {str(e)}'}), 500


@api_bp.route('/emails/batch-analyze', methods=['POST'])
@admin_required
def batch_analyze_emails():
    data = request.get_json() or {}
    email_ids = data.get('email_ids', [])
    auto_reply_after = data.get('auto_reply_after', False)

    if not email_ids:
        return jsonify({'error': '请选择要分析的邮件'}), 400

    llm_config = LLMConfig.query.filter_by(is_active=True).first()
    if not llm_config:
        return jsonify({'error': '未配置活跃的大模型'}), 400

    valid_ids = []
    for eid in email_ids:
        email = EmailRecord.query.get(eid)
        if email and email.status != 'analyzing':
            email.status = 'analyzing'
            valid_ids.append(eid)
    db.session.commit()

    tasks = email_pipeline.batch_analyze(valid_ids, TaskPriority.NORMAL, auto_reply_after)

    log_audit('批量分析邮件', 'batch_update', 'email', f'数量: {len(valid_ids)}')
    return jsonify({
        'message': f'已提交 {len(valid_ids)} 封邮件到分析队列',
        'task_count': len(valid_ids),
        'task_ids': [t.id for t in tasks]
    })


@api_bp.route('/emails/batch-reply', methods=['POST'])
@admin_required
def batch_reply_emails():
    data = request.get_json() or {}
    email_ids = data.get('email_ids', [])
    use_analysis_template = data.get('use_analysis_template', True)
    template_id = data.get('template_id')

    if not email_ids:
        return jsonify({'error': '请选择要回复的邮件'}), 400

    mail_server = MailServerConfig.query.filter_by(is_active=True).first()
    if not mail_server:
        return jsonify({'error': '未配置活跃的邮件服务器'}), 400

    if use_analysis_template:
        valid_ids = []
        for eid in email_ids:
            analysis = AnalysisResult.query.filter_by(email_id=eid).first()
            if analysis:
                valid_ids.append(eid)
    else:
        valid_ids = email_ids

    if not valid_ids:
        return jsonify({'error': '没有可回复的邮件（请先分析邮件或检查模板）'}), 400

    tasks = email_pipeline.batch_reply(valid_ids, use_analysis_template=use_analysis_template)

    log_audit('批量回复邮件', 'batch_update', 'email', f'数量: {len(valid_ids)}')
    return jsonify({
        'message': f'已提交 {len(valid_ids)} 封邮件到回复队列',
        'task_count': len(valid_ids),
        'task_ids': [t.id for t in tasks]
    })


@api_bp.route('/queue/status', methods=['GET'])
@login_required
def get_queue_status():
    status = task_queue.get_status()
    pipeline_config = email_pipeline.get_config()
    status.update(pipeline_config)
    return jsonify(status)


@api_bp.route('/queue/tasks', methods=['GET'])
@login_required
def get_queue_tasks():
    limit = int(request.args.get('limit', 20))
    tasks = task_queue.get_recent_tasks(limit)
    return jsonify(tasks)


@api_bp.route('/queue/tasks/<task_id>', methods=['GET'])
@login_required
def get_task_detail(task_id):
    task = task_queue.get_task(task_id)
    if not task:
        return jsonify({'error': '任务不存在'}), 404
    return jsonify(task_queue._task_to_dict(task))


@api_bp.route('/pipeline/config', methods=['GET'])
@admin_required
def get_pipeline_config():
    from src.utils.config_manager import load_config
    config = email_pipeline.get_config()
    config['auto_check_interval'] = load_config().get('app', {}).get('auto_check_interval', 60)
    return jsonify(config)


@api_bp.route('/pipeline/config', methods=['PUT'])
@admin_required
def update_pipeline_config():
    data = request.get_json() or {}
    email_pipeline.update_config(
        auto_analyze=data.get('auto_analyze'),
        auto_reply=data.get('auto_reply'),
        analysis_workers=data.get('analysis_workers'),
        reply_workers=data.get('reply_workers'),
        reply_rate_limit_per_min=data.get('reply_rate_limit_per_min'),
        sender_display_name=data.get('sender_display_name')
    )
    # 更新自动检查间隔
    auto_check_interval = data.get('auto_check_interval')
    if auto_check_interval is not None:
        from src.utils.config_manager import load_config, save_config
        cfg = load_config()
        cfg['app']['auto_check_interval'] = int(auto_check_interval)
        save_config(cfg)
        # 通知 scheduler 间隔变更
        from src.api.app import notify_scheduler_interval_change
        notify_scheduler_interval_change()
    log_audit('更新流水线配置', 'update', 'pipeline', str(data))
    return jsonify(email_pipeline.get_config())


@api_bp.route('/emails/<int:id>/analyze-async', methods=['POST'])
@admin_required
def analyze_email_async(id):
    email = EmailRecord.query.get_or_404(id)
    llm_config = LLMConfig.query.filter_by(is_active=True).first()
    if not llm_config:
        return jsonify({'error': '未配置活跃的大模型'}), 400

    email.status = 'analyzing'
    db.session.commit()

    task = email_pipeline.analyze_email(id, TaskPriority.HIGH)

    log_audit('异步分析邮件', 'update', 'email', f'邮件ID: {id}')
    return jsonify({
        'message': '已提交分析任务',
        'task_id': task.id
    })


@api_bp.route('/emails/<int:id>/reply-async', methods=['POST'])
@admin_required
def reply_email_async(id):
    email = EmailRecord.query.get_or_404(id)
    data = request.get_json() or {}
    use_analysis_template = data.get('use_analysis_template', False)

    mail_server = MailServerConfig.query.filter_by(is_active=True).first()
    if not mail_server:
        return jsonify({'error': '未配置活跃的邮件服务器'}), 400

    task = email_pipeline.reply_email(
        id,
        use_analysis_template=use_analysis_template,
        template_id=data.get('template_id'),
        subject=data.get('subject'),
        body=data.get('body'),
        priority=TaskPriority.HIGH
    )

    log_audit('异步回复邮件', 'update', 'email', f'邮件ID: {id}')
    return jsonify({
        'message': '已提交回复任务',
        'task_id': task.id
    })


@api_bp.route('/emails/<int:id>/correct', methods=['POST'])
@admin_required
def correct_analysis(id):
    email = EmailRecord.query.get_or_404(id)
    analysis = AnalysisResult.query.filter_by(email_id=id).first()
    
    if not analysis:
        return jsonify({'error': '该邮件尚未分析，无法纠错'}), 400
    
    data = request.get_json() or {}
    corrected_is_phishing = data.get('is_phishing')
    corrected_risk_level = data.get('risk_level')
    corrected_phishing_type = data.get('phishing_type')
    corrected_analysis_report = data.get('analysis_report')
    reason = data.get('reason', '')
    
    if corrected_is_phishing is None:
        return jsonify({'error': '请指定正确的判定结果（is_phishing）'}), 400
    
    existing_correction = AnalysisCorrection.query.filter_by(email_id=id).first()
    if existing_correction:
        return jsonify({'error': '该邮件已存在纠错记录，如需修改请删除后重新纠错'}), 400
    
    correction = AnalysisCorrection(
        email_id=id,
        user_id=session['user_id'],
        original_is_phishing=analysis.is_phishing,
        original_risk_level=analysis.risk_level,
        corrected_is_phishing=corrected_is_phishing,
        corrected_risk_level=corrected_risk_level,
        corrected_phishing_type=corrected_phishing_type,
        corrected_analysis_report=corrected_analysis_report,
        reason=reason
    )
    db.session.add(correction)
    
    analysis.is_phishing = corrected_is_phishing
    analysis.confidence = 1.0
    analysis.risk_level = corrected_risk_level
    analysis.phishing_type = corrected_phishing_type
    if corrected_analysis_report:
        analysis.analysis_report = corrected_analysis_report
    
    email.status = 'analyzed'
    
    _generate_email_signatures(email, correction)
    
    db.session.commit()
    
    log_audit('人工纠错分析结果', 'update', 'email', f'邮件ID: {id}, 原结果: {existing_correction.is_phishing if existing_correction else analysis.is_phishing}, 新结果: {corrected_is_phishing}')
    
    return jsonify({
        'success': True,
        'message': '纠错成功，分析结果已更新，特征签名已生成',
        'correction': correction.to_dict()
    })


def _generate_email_signatures(email, correction):
    signatures = []
    
    from_email = email.from_email or ''
    if '@' in from_email:
        domain = from_email.split('@')[-1]
        signatures.append({
            'signature_type': 'domain',
            'signature_value': domain,
            'expected_is_phishing': correction.corrected_is_phishing,
            'expected_risk_level': correction.corrected_risk_level,
            'expected_phishing_type': correction.corrected_phishing_type
        })
        
        full_email = from_email.strip()
        if full_email:
            signatures.append({
                'signature_type': 'from_email',
                'signature_value': full_email,
                'expected_is_phishing': correction.corrected_is_phishing,
                'expected_risk_level': correction.corrected_risk_level,
                'expected_phishing_type': correction.corrected_phishing_type
            })
    
    subject = email.subject or ''
    if len(subject) > 5:
        normalized_subject = subject.strip().lower()
        signatures.append({
            'signature_type': 'subject_pattern',
            'signature_value': normalized_subject[:200],
            'expected_is_phishing': correction.corrected_is_phishing,
            'expected_risk_level': correction.corrected_risk_level,
            'expected_phishing_type': correction.corrected_phishing_type
        })
    
    body = email.body or ''
    if len(body) > 20:
        body_hash = str(hash(body[:500]))[:32]
        signatures.append({
            'signature_type': 'body_hash',
            'signature_value': body_hash,
            'expected_is_phishing': correction.corrected_is_phishing,
            'expected_risk_level': correction.corrected_risk_level,
            'expected_phishing_type': correction.corrected_phishing_type
        })
    
    for sig in signatures:
        existing = EmailSignature.query.filter_by(
            signature_type=sig['signature_type'],
            signature_value=sig['signature_value']
        ).first()
        if not existing:
            email_sig = EmailSignature(
                signature_type=sig['signature_type'],
                signature_value=sig['signature_value'],
                expected_is_phishing=sig['expected_is_phishing'],
                expected_risk_level=sig['expected_risk_level'],
                expected_phishing_type=sig['expected_phishing_type'],
                correction_id=correction.id
            )
            db.session.add(email_sig)


@api_bp.route('/emails/<int:id>/correction', methods=['GET'])
@login_required
def get_email_correction(id):
    correction = AnalysisCorrection.query.filter_by(email_id=id).first()
    if not correction:
        return jsonify({'error': '该邮件没有纠错记录'}), 404
    return jsonify(correction.to_dict())


@api_bp.route('/corrections', methods=['GET'])
@admin_required
def get_corrections():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    query = AnalysisCorrection.query.order_by(AnalysisCorrection.created_at.desc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    
    records = []
    for c in pagination.items:
        record = c.to_dict()
        if c.email:
            record['email_subject'] = c.email.subject
            record['email_from'] = c.email.from_email
        records.append(record)
    
    return jsonify({
        'items': records,
        'total': pagination.total,
        'pages': pagination.pages,
        'page': page
    })


@api_bp.route('/corrections/<int:id>', methods=['DELETE'])
@admin_required
def delete_correction(id):
    correction = AnalysisCorrection.query.get_or_404(id)
    
    EmailSignature.query.filter_by(correction_id=id).delete()
    
    email = EmailRecord.query.get(correction.email_id)
    if email and email.analysis:
        email.analysis.is_phishing = correction.original_is_phishing
        email.analysis.confidence = 0.5
        email.analysis.risk_level = correction.original_risk_level
    
    db.session.delete(correction)
    db.session.commit()
    
    log_audit('删除纠错记录', 'delete', 'correction', f'纠错ID: {id}, 邮件ID: {correction.email_id}')
    
    return jsonify({'message': '纠错记录已删除，分析结果已恢复'})


@api_bp.route('/signatures', methods=['GET'])
@admin_required
def get_signatures():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    query = EmailSignature.query.filter_by(is_active=True).order_by(EmailSignature.match_count.desc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        'items': [s.to_dict() for s in pagination.items],
        'total': pagination.total,
        'pages': pagination.pages,
        'page': page
    })


@api_bp.route('/signatures/<int:id>', methods=['PUT'])
@admin_required
def update_signature(id):
    signature = EmailSignature.query.get_or_404(id)
    data = request.get_json() or {}
    
    if 'is_active' in data:
        signature.is_active = data['is_active']
    if 'confidence' in data:
        signature.confidence = data['confidence']
    if 'expected_is_phishing' in data:
        signature.expected_is_phishing = data['expected_is_phishing']
    if 'expected_risk_level' in data:
        signature.expected_risk_level = data['expected_risk_level']
    if 'expected_phishing_type' in data:
        signature.expected_phishing_type = data['expected_phishing_type']
    
    db.session.commit()
    
    return jsonify(signature.to_dict())


@api_bp.route('/signatures/<int:id>', methods=['DELETE'])
@admin_required
def delete_signature(id):
    signature = EmailSignature.query.get_or_404(id)
    db.session.delete(signature)
    db.session.commit()
    
    log_audit('删除特征签名', 'delete', 'signature', f'签名ID: {id}, 类型: {signature.signature_type}')
    
    return jsonify({'message': '特征签名已删除'})


@api_bp.route('/monitor/status', methods=['GET'])
@login_required
def get_monitor_status():
    status = health_monitor.get_status()
    return jsonify(status)


@api_bp.route('/monitor/history', methods=['GET'])
@login_required
def get_monitor_history():
    history = health_monitor.get_history()
    return jsonify(history)


@api_bp.route('/monitor/check', methods=['POST'])
@admin_required
def trigger_monitor_check():
    import json
    status = health_monitor._collect_status()
    redis_cache.set('phishing:monitor:status', status, expire=120)
    return jsonify(status)


def log_audit(action, action_type, resource=None, detail=None):
    from src.models.db import db
    user_id = session.get('user_id')
    username = session.get('username')
    
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ',' in ip_address:
        ip_address = ip_address.split(',')[0].strip()
    
    if ip_address.startswith('::ffff:'):
        ip_address = ip_address.replace('::ffff:', '')
    elif ip_address.startswith('ffff:'):
        ip_address = ip_address.replace('ffff:', '')
    
    user_agent = request.headers.get('User-Agent', '')[:500]
    
    log = AuditLog(
        user_id=user_id,
        username=username,
        action=action,
        action_type=action_type,
        resource=resource,
        detail=detail,
        ip_address=ip_address,
        user_agent=user_agent
    )
    db.session.add(log)
    db.session.commit()


@api_bp.route('/situation/data', methods=['GET'])
@login_required
def get_situation_data():
    from sqlalchemy import func
    
    total_emails = EmailRecord.query.count()
    phishing_count = EmailRecord.query.join(AnalysisResult).filter(AnalysisResult.is_phishing == True).count()
    normal_count = EmailRecord.query.join(AnalysisResult).filter(AnalysisResult.is_phishing == False).count()
    pending_count = EmailRecord.query.filter_by(status='pending').count()
    replied_count = EmailRecord.query.filter_by(status='replied').count()
    
    high_risk = AnalysisResult.query.filter_by(risk_level='high').count()
    medium_risk = AnalysisResult.query.filter_by(risk_level='medium').count()
    low_risk = AnalysisResult.query.filter_by(risk_level='low').count()
    
    today = datetime.now().date()
    today_emails = EmailRecord.query.filter(func.date(EmailRecord.created_at) == today).count()
    today_phishing = EmailRecord.query.join(AnalysisResult).filter(
        AnalysisResult.is_phishing == True,
        func.date(EmailRecord.created_at) == today
    ).count()
    
    phishing_types = db.session.query(
        AnalysisResult.phishing_type,
        func.count(AnalysisResult.id)
    ).filter(AnalysisResult.is_phishing == True).group_by(AnalysisResult.phishing_type).all()
    
    top_domains = db.session.query(
        func.substring_index(EmailRecord.from_email, '@', -1).label('domain'),
        func.count(EmailRecord.id)
    ).filter(EmailRecord.from_email.contains('@')).group_by('domain').order_by(func.count(EmailRecord.id).desc()).limit(5).all()
    
    recent_24h = datetime.now() - timedelta(hours=24)
    hourly_data = db.session.query(
        func.hour(EmailRecord.created_at).label('hour'),
        func.count(EmailRecord.id)
    ).filter(EmailRecord.created_at >= recent_24h).group_by('hour').all()
    
    hourly_chart = {str(h): 0 for h in range(24)}
    for h, c in hourly_data:
        hourly_chart[str(h)] = c
    
    recent_threats = []
    recent_emails = EmailRecord.query.join(AnalysisResult).filter(
        AnalysisResult.is_phishing == True
    ).order_by(EmailRecord.created_at.desc()).limit(8).all()
    
    for email in recent_emails:
        recent_threats.append({
            'id': email.id,
            'subject': email.subject or '(无主题)',
            'from_email': email.from_email or '-',
            'risk_level': email.analysis.risk_level if email.analysis else 'unknown',
            'phishing_type': email.analysis.phishing_type if email.analysis else '其他',
            'created_at': email.created_at.strftime('%m-%d %H:%M') if email.created_at else '-'
        })
    
    recent_7days = []
    for i in range(6, -1, -1):
        day = datetime.now().date() - timedelta(days=i)
        day_count = EmailRecord.query.filter(func.date(EmailRecord.created_at) == day).count()
        day_phishing = EmailRecord.query.join(AnalysisResult).filter(
            AnalysisResult.is_phishing == True,
            func.date(EmailRecord.created_at) == day
        ).count()
        recent_7days.append({
            'date': day.strftime('%m-%d'),
            'total': day_count,
            'phishing': day_phishing
        })
    
    attack_sources = []
    for domain, count in top_domains:
        if domain and domain.strip():
            attack_sources.append({
                'domain': domain.strip(),
                'count': count,
                'country': _guess_country(domain.strip())
            })
    
    return jsonify({
        'overview': {
            'total_emails': total_emails,
            'phishing_count': phishing_count,
            'normal_count': normal_count,
            'pending_count': pending_count,
            'replied_count': replied_count,
            'today_emails': today_emails,
            'today_phishing': today_phishing,
            'high_risk': high_risk,
            'medium_risk': medium_risk,
            'low_risk': low_risk
        },
        'phishing_types': [{'type': t or '其他', 'count': c} for t, c in phishing_types],
        'hourly_chart': hourly_chart,
        'recent_7days': recent_7days,
        'attack_sources': attack_sources,
        'recent_threats': recent_threats
    })


def _guess_country(domain):
    country_map = {
        'cn': '中国', 'com.cn': '中国', 'net.cn': '中国', 'org.cn': '中国',
        'com': '美国', 'net': '美国', 'org': '美国',
        'ru': '俄罗斯', 'jp': '日本', 'kr': '韩国',
        'uk': '英国', 'de': '德国', 'fr': '法国',
        'br': '巴西', 'in': '印度', 'sg': '新加坡'
    }
    for suffix, country in country_map.items():
        if domain.endswith('.' + suffix) or domain == suffix:
            return country
    return '其他'