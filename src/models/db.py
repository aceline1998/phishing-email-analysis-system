from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy.dialects.mysql import LONGTEXT, MEDIUMTEXT

db = SQLAlchemy()


class MailServerConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    imap_server = db.Column(db.String(200), nullable=False)
    imap_port = db.Column(db.Integer, default=993)
    imap_ssl = db.Column(db.Boolean, default=True)
    smtp_server = db.Column(db.String(200), nullable=False)
    smtp_port = db.Column(db.Integer, default=465)
    smtp_ssl = db.Column(db.Boolean, default=True)
    email = db.Column(db.String(200), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'imap_server': self.imap_server,
            'imap_port': self.imap_port,
            'imap_ssl': self.imap_ssl,
            'smtp_server': self.smtp_server,
            'smtp_port': self.smtp_port,
            'smtp_ssl': self.smtp_ssl,
            'email': self.email,
            'is_active': self.is_active,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': self.updated_at.strftime('%Y-%m-%d %H:%M:%S')
        }


class LLMConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    api_base_url = db.Column(db.String(200), nullable=False)
    api_key = db.Column(db.String(200), nullable=False)
    model_name = db.Column(db.String(100), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'api_base_url': self.api_base_url,
            'api_key': '******',
            'model_name': self.model_name,
            'is_active': self.is_active,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': self.updated_at.strftime('%Y-%m-%d %H:%M:%S')
        }

    def get_api_key(self):
        return self.api_key


class EmailRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.String(255), unique=True, nullable=False)
    subject = db.Column(db.String(500))
    from_email = db.Column(db.String(200), nullable=False)
    to_email = db.Column(db.String(200))
    cc_email = db.Column(db.String(500))
    body = db.Column(db.Text().with_variant(MEDIUMTEXT, 'mysql'))
    raw_content = db.Column(db.Text().with_variant(LONGTEXT, 'mysql'))
    attachments = db.Column(db.Text)
    received_at = db.Column(db.DateTime)
    status = db.Column(db.String(50), default='pending')
    source = db.Column(db.String(50), default='mail_server')
    mail_server_id = db.Column(db.Integer, db.ForeignKey('mail_server_config.id'))
    created_at = db.Column(db.DateTime, default=datetime.now)

    mail_server = db.relationship('MailServerConfig', backref=db.backref('emails', lazy=True))

    def to_dict(self):
        result = {
            'id': self.id,
            'message_id': self.message_id,
            'subject': self.subject,
            'from_email': self.from_email,
            'to_email': self.to_email,
            'cc_email': self.cc_email,
            'body': self.body,
            'attachments': self.attachments,
            'received_at': self.received_at.strftime('%Y-%m-%d %H:%M:%S') if self.received_at else None,
            'status': self.status,
            'source': self.source,
            'mail_server_id': self.mail_server_id,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }
        if self.analysis:
            result['analysis'] = {
                'is_phishing': self.analysis.is_phishing,
                'confidence': self.analysis.confidence,
                'risk_level': self.analysis.risk_level,
                'phishing_type': self.analysis.phishing_type,
                'indicators': self.analysis.indicators,
                'analysis_report': self.analysis.analysis_report,
                'analyzed_at': self.analysis.analyzed_at.strftime('%Y-%m-%d %H:%M:%S')
            }
        return result


class AnalysisResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email_id = db.Column(db.Integer, db.ForeignKey('email_record.id'), unique=True)
    is_phishing = db.Column(db.Boolean, nullable=False)
    confidence = db.Column(db.Float, nullable=False)
    risk_level = db.Column(db.String(50))
    analysis_report = db.Column(db.Text().with_variant(MEDIUMTEXT, 'mysql'))
    phishing_type = db.Column(db.String(100))
    indicators = db.Column(db.Text().with_variant(MEDIUMTEXT, 'mysql'))
    llm_config_id = db.Column(db.Integer, db.ForeignKey('llm_config.id'))
    analyzed_at = db.Column(db.DateTime, default=datetime.now)

    email = db.relationship('EmailRecord', backref=db.backref('analysis', uselist=False))
    llm_config = db.relationship('LLMConfig', backref=db.backref('analyses', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'email_id': self.email_id,
            'is_phishing': self.is_phishing,
            'confidence': self.confidence,
            'risk_level': self.risk_level,
            'analysis_report': self.analysis_report,
            'phishing_type': self.phishing_type,
            'indicators': self.indicators,
            'llm_config_id': self.llm_config_id,
            'analyzed_at': self.analyzed_at.strftime('%Y-%m-%d %H:%M:%S')
        }


class ReplyTemplate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    type = db.Column(db.String(50), nullable=False)
    subject_template = db.Column(db.String(500), nullable=False)
    body_template = db.Column(db.Text, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'type': self.type,
            'subject_template': self.subject_template,
            'body_template': self.body_template,
            'is_active': self.is_active,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': self.updated_at.strftime('%Y-%m-%d %H:%M:%S')
        }


class SecurityAdviceConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), default='default')
    phishing_advice = db.Column(db.Text, nullable=False, default='')
    normal_advice = db.Column(db.Text, nullable=False, default='')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'phishing_advice': self.phishing_advice,
            'normal_advice': self.normal_advice,
            'is_active': self.is_active,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': self.updated_at.strftime('%Y-%m-%d %H:%M:%S')
        }


class ReplyRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.String(255), unique=True, nullable=True)
    email_id = db.Column(db.Integer, db.ForeignKey('email_record.id'))
    reply_to = db.Column(db.String(200), nullable=False)
    from_email = db.Column(db.String(200))
    subject = db.Column(db.String(500))
    body = db.Column(db.Text().with_variant(MEDIUMTEXT, 'mysql'))
    raw_content = db.Column(db.Text().with_variant(LONGTEXT, 'mysql'))
    sent_at = db.Column(db.DateTime, default=datetime.now)
    status = db.Column(db.String(50), default='sent')

    email = db.relationship('EmailRecord', backref=db.backref('replies', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'message_id': self.message_id,
            'email_id': self.email_id,
            'reply_to': self.reply_to,
            'from_email': self.from_email,
            'subject': self.subject,
            'body': self.body,
            'sent_at': self.sent_at.strftime('%Y-%m-%d %H:%M:%S'),
            'status': self.status
        }


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200))
    role = db.Column(db.String(50), default='user')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'is_active': self.is_active,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': self.updated_at.strftime('%Y-%m-%d %H:%M:%S')
        }


class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(200), unique=True, nullable=False)
    code = db.Column(db.String(20), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)

    user = db.relationship('User', backref=db.backref('reset_tokens', lazy=True))


class ThreatIntelConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    provider = db.Column(db.String(50), nullable=False)
    api_key = db.Column(db.String(500), nullable=False)
    api_base_url = db.Column(db.String(200))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'provider': self.provider,
            'api_base_url': self.api_base_url,
            'is_active': self.is_active,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': self.updated_at.strftime('%Y-%m-%d %H:%M:%S')
        }

    def get_api_key(self):
        return self.api_key


class ThreatIntelRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    query_type = db.Column(db.String(50), nullable=False)
    query_value = db.Column(db.String(500), nullable=False)
    provider = db.Column(db.String(50))
    is_malicious = db.Column(db.Boolean)
    threat_type = db.Column(db.String(100))
    confidence = db.Column(db.Float)
    raw_result = db.Column(db.Text)
    queried_at = db.Column(db.DateTime, default=datetime.now)
    email_id = db.Column(db.Integer, db.ForeignKey('email_record.id'))

    email = db.relationship('EmailRecord', backref=db.backref('threat_intels', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'query_type': self.query_type,
            'query_value': self.query_value,
            'provider': self.provider,
            'is_malicious': self.is_malicious,
            'threat_type': self.threat_type,
            'confidence': self.confidence,
            'raw_result': self.raw_result,
            'queried_at': self.queried_at.strftime('%Y-%m-%d %H:%M:%S') if self.queried_at else None,
            'email_id': self.email_id
        }


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    username = db.Column(db.String(100))
    action = db.Column(db.String(100), nullable=False)
    action_type = db.Column(db.String(50))
    resource = db.Column(db.String(200))
    detail = db.Column(db.Text)
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.now)

    user = db.relationship('User', backref=db.backref('audit_logs', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'username': self.username,
            'action': self.action,
            'action_type': self.action_type,
            'resource': self.resource,
            'detail': self.detail,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None
        }


class ChatConversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), default='新对话')
    llm_config_id = db.Column(db.Integer, db.ForeignKey('llm_config.id'))
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

    user = db.relationship('User', backref=db.backref('chat_conversations', lazy=True))
    llm_config = db.relationship('LLMConfig', backref=db.backref('conversations', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'title': self.title,
            'llm_config_id': self.llm_config_id,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': self.updated_at.strftime('%Y-%m-%d %H:%M:%S')
        }


class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('chat_conversation.id'), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # user / assistant / system
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)

    conversation = db.relationship('ChatConversation', backref=db.backref('messages', lazy=True, order_by='ChatMessage.id'))

    def to_dict(self):
        return {
            'id': self.id,
            'conversation_id': self.conversation_id,
            'role': self.role,
            'content': self.content,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }


class VersionInfo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    version = db.Column(db.String(50), nullable=False)
    update_content = db.Column(db.Text)
    release_date = db.Column(db.DateTime, default=datetime.now)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

    def to_dict(self):
        return {
            'id': self.id,
            'version': self.version,
            'update_content': self.update_content,
            'release_date': self.release_date.strftime('%Y-%m-%d %H:%M:%S') if self.release_date else None,
            'is_active': self.is_active,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': self.updated_at.strftime('%Y-%m-%d %H:%M:%S')
        }


class PipelineConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, default='default')
    auto_analyze = db.Column(db.Boolean, default=True)
    auto_reply = db.Column(db.Boolean, default=True)
    analysis_workers = db.Column(db.Integer, default=3)
    reply_workers = db.Column(db.Integer, default=2)
    reply_rate_limit_per_min = db.Column(db.Integer, default=30)
    sender_display_name = db.Column(db.String(100), default='安全室')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'auto_analyze': self.auto_analyze,
            'auto_reply': self.auto_reply,
            'analysis_workers': self.analysis_workers,
            'reply_workers': self.reply_workers,
            'reply_rate_limit_per_min': self.reply_rate_limit_per_min,
            'sender_display_name': self.sender_display_name,
            'is_active': self.is_active,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': self.updated_at.strftime('%Y-%m-%d %H:%M:%S')
        }


class FoxmailConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, default='default')
    foxmail_exe_path = db.Column(db.String(500), nullable=True)
    storage_path = db.Column(db.String(500), nullable=True)
    auto_sync_enabled = db.Column(db.Boolean, default=True)
    sync_inbox = db.Column(db.Boolean, default=True)
    sync_sent = db.Column(db.Boolean, default=True)
    sync_interval_minutes = db.Column(db.Integer, default=5)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'foxmail_exe_path': self.foxmail_exe_path,
            'storage_path': self.storage_path,
            'auto_sync_enabled': self.auto_sync_enabled,
            'sync_inbox': self.sync_inbox,
            'sync_sent': self.sync_sent,
            'sync_interval_minutes': self.sync_interval_minutes,
            'is_active': self.is_active,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None,
            'updated_at': self.updated_at.strftime('%Y-%m-%d %H:%M:%S') if self.updated_at else None
        }


class AnalysisCorrection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email_id = db.Column(db.Integer, db.ForeignKey('email_record.id'), unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    original_is_phishing = db.Column(db.Boolean, nullable=False)
    original_risk_level = db.Column(db.String(50))
    corrected_is_phishing = db.Column(db.Boolean, nullable=False)
    corrected_risk_level = db.Column(db.String(50))
    corrected_phishing_type = db.Column(db.String(100))
    corrected_analysis_report = db.Column(db.Text)
    reason = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.now)

    email = db.relationship('EmailRecord', backref=db.backref('correction', uselist=False))
    user = db.relationship('User', backref=db.backref('corrections', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'email_id': self.email_id,
            'user_id': self.user_id,
            'username': self.user.username if self.user else None,
            'original_is_phishing': self.original_is_phishing,
            'original_risk_level': self.original_risk_level,
            'corrected_is_phishing': self.corrected_is_phishing,
            'corrected_risk_level': self.corrected_risk_level,
            'corrected_phishing_type': self.corrected_phishing_type,
            'corrected_analysis_report': self.corrected_analysis_report,
            'reason': self.reason,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }


class EmailSignature(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    signature_type = db.Column(db.String(50), nullable=False)
    signature_value = db.Column(db.String(500), nullable=False)
    expected_is_phishing = db.Column(db.Boolean, nullable=False)
    expected_risk_level = db.Column(db.String(50))
    expected_phishing_type = db.Column(db.String(100))
    correction_id = db.Column(db.Integer, db.ForeignKey('analysis_correction.id'))
    match_count = db.Column(db.Integer, default=0)
    confidence = db.Column(db.Float, default=0.95)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

    correction = db.relationship('AnalysisCorrection', backref=db.backref('signatures', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'signature_type': self.signature_type,
            'signature_value': self.signature_value,
            'expected_is_phishing': self.expected_is_phishing,
            'expected_risk_level': self.expected_risk_level,
            'expected_phishing_type': self.expected_phishing_type,
            'correction_id': self.correction_id,
            'match_count': self.match_count,
            'confidence': self.confidence,
            'is_active': self.is_active,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': self.updated_at.strftime('%Y-%m-%d %H:%M:%S')
        }