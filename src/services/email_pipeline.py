from src.services.task_queue import task_queue, TaskPriority
from src.models.db import db, EmailRecord, AnalysisResult, LLMConfig, MailServerConfig, SecurityAdviceConfig, ReplyRecord, PipelineConfig
from src.services.llm_service import LLMService
from src.services.email_service import EmailService, generate_analysis_reply_email


class EmailPipeline:
    _instance = None
    _lock = None

    def __new__(cls):
        if cls._instance is None:
            import threading
            cls._lock = threading.Lock()
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._register_handlers()
        self._config_loaded = False
        self._reply_timestamps = []
        self.sender_display_name = '安全室'

    def _load_config_from_db(self):
        try:
            config = PipelineConfig.query.filter_by(name='default').first()
            if config:
                self.auto_analyze = config.auto_analyze
                self.auto_reply = config.auto_reply
                self.analysis_workers = config.analysis_workers
                self.reply_workers = config.reply_workers
                self.reply_rate_limit_per_min = config.reply_rate_limit_per_min
                self.sender_display_name = config.sender_display_name or '安全室'
            else:
                self.auto_analyze = True
                self.auto_reply = False
                self.analysis_workers = 3
                self.reply_workers = 2
                self.reply_rate_limit_per_min = 30
                self.sender_display_name = '安全室'
        except Exception as e:
            print(f"加载流水线配置失败: {e}")
            self.auto_analyze = True
            self.auto_reply = False
            self.analysis_workers = 3
            self.reply_workers = 2
            self.reply_rate_limit_per_min = 30
            self.sender_display_name = '安全室'

    def _register_handlers(self):
        task_queue.register_handler('analysis', self._handle_analysis)
        task_queue.register_handler('reply', self._handle_reply)

    def _handle_analysis(self, payload):
        email_id = payload.get('email_id')
        llm_config_id = payload.get('llm_config_id')
        auto_reply_after = payload.get('auto_reply_after', False)

        try:
            email = EmailRecord.query.get(email_id)
            if not email:
                print(f"[Pipeline] Analysis failed: Email {email_id} not found")
                return {'success': False, 'error': 'Email not found'}

            if llm_config_id:
                llm_config = LLMConfig.query.get(llm_config_id)
            else:
                llm_config = LLMConfig.query.filter_by(is_active=True).first()

            if not llm_config:
                print(f"[Pipeline] Analysis failed: No active LLM config for email {email_id}")
                return {'success': False, 'error': 'No active LLM config'}

            print(f"[Pipeline] Analyzing email {email_id} with LLM {llm_config.name} ({llm_config.model_name})")
            service = LLMService(llm_config)
            result = service.analyze_email(email)
            print(f"[Pipeline] Analysis result for email {email_id}: is_phishing={result.get('is_phishing')}, risk_level={result.get('risk_level')}")

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
            print(f"[Pipeline] Analysis saved for email {email_id}")

            if auto_reply_after and self.auto_reply:
                self._schedule_reply(email_id)

            return {'success': True, 'result': result}
        except Exception as e:
            import traceback
            print(f"[Pipeline] Analysis exception for email {email_id}: {e}")
            traceback.print_exc()
            raise

    def _schedule_reply(self, email_id):
        try:
            payload = {
                'email_id': email_id,
                'use_analysis_template': True
            }
            task_queue.submit_reply(payload, TaskPriority.NORMAL)
            print(f"[Pipeline] Reply scheduled for email {email_id}")
        except Exception as e:
            print(f"[Pipeline] Schedule reply failed for email {email_id}: {e}")

    def _handle_reply(self, payload):
        email_id = payload.get('email_id')
        use_analysis_template = payload.get('use_analysis_template', False)
        template_id = payload.get('template_id')
        subject = payload.get('subject')
        body = payload.get('body')

        import time
        now = time.time()
        window_start = now - 60
        self._reply_timestamps = [t for t in self._reply_timestamps if t > window_start]

        if len(self._reply_timestamps) >= self.reply_rate_limit_per_min:
            sleep_time = 60 - (now - self._reply_timestamps[0]) + 0.5
            time.sleep(sleep_time)

        self._reply_timestamps.append(time.time())

        try:
            email = EmailRecord.query.get(email_id)
            if not email:
                print(f"[Pipeline] Reply failed: Email {email_id} not found")
                return {'success': False, 'error': 'Email not found'}

            mail_server = MailServerConfig.query.filter_by(is_active=True).first()
            if not mail_server:
                print(f"[Pipeline] Reply failed: No active mail server for email {email_id}")
                return {'success': False, 'error': 'No active mail server'}

            if use_analysis_template:
                analysis = AnalysisResult.query.filter_by(email_id=email.id).first()
                if not analysis:
                    return {'success': False, 'error': 'No analysis result'}

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
                reply_subject = email_content['subject']
                plain_body = email_content['plain_body']
                html_body = email_content['html_body']
            else:
                from src.models.db import ReplyTemplate
                if template_id:
                    tpl = ReplyTemplate.query.get(template_id)
                    if tpl:
                        reply_subject = tpl.subject_template
                        plain_body = tpl.body_template
                        html_body = None
                    else:
                        return {'success': False, 'error': 'Template not found'}
                else:
                    reply_subject = subject or 'Re: ' + (email.subject or '')
                    plain_body = body or ''
                    html_body = None

            print(f"[Pipeline] Sending reply for email {email_id} to {email.from_email}")
            service = EmailService(mail_server)
            result = service.send_reply(email.from_email, reply_subject, plain_body, html_body, sender_display_name=self.sender_display_name)
            print(f"[Pipeline] Reply result for email {email_id}: {result}")

            if result.get('success'):
                reply = ReplyRecord(
                    email_id=email.id,
                    reply_to=email.from_email,
                    subject=reply_subject,
                    body=plain_body,
                    status='sent'
                )
                db.session.add(reply)
                email.status = 'replied'
                db.session.commit()

            return result
        except Exception as e:
            import traceback
            print(f"[Pipeline] Reply exception for email {email_id}: {e}")
            traceback.print_exc()
            raise

    def analyze_email(self, email_id, priority=TaskPriority.NORMAL, auto_reply_after=False, llm_config_id=None):
        payload = {
            'email_id': email_id,
            'llm_config_id': llm_config_id,
            'auto_reply_after': auto_reply_after
        }
        try:
            task = task_queue.submit_analysis(payload, priority)
            return task
        except Exception as e:
            print(f"Task queue submit_analysis failed: {e}, executing synchronously for email {email_id}")
            try:
                result = self._handle_analysis(payload)
                return {'fallback': True, 'email_id': email_id, 'result': result}
            except Exception as fallback_err:
                print(f"Synchronous analysis failed for email {email_id}: {fallback_err}")
                return {'fallback': True, 'email_id': email_id, 'error': str(fallback_err)}

    def batch_analyze(self, email_ids, priority=TaskPriority.NORMAL, auto_reply_after=False):
        tasks = []
        for email_id in email_ids:
            task = self.analyze_email(email_id, priority, auto_reply_after)
            tasks.append(task)
        return tasks

    def reply_email(self, email_id, use_analysis_template=False, template_id=None,
                    subject=None, body=None, priority=TaskPriority.NORMAL):
        payload = {
            'email_id': email_id,
            'use_analysis_template': use_analysis_template,
            'template_id': template_id,
            'subject': subject,
            'body': body
        }
        try:
            task = task_queue.submit_reply(payload, priority)
            return task
        except Exception as e:
            print(f"Task queue submit_reply failed: {e}, executing synchronously for email {email_id}")
            try:
                result = self._handle_reply(payload)
                return {'fallback': True, 'email_id': email_id, 'result': result}
            except Exception as fallback_err:
                print(f"Synchronous reply failed for email {email_id}: {fallback_err}")
                return {'fallback': True, 'email_id': email_id, 'error': str(fallback_err)}

    def batch_reply(self, email_ids, use_analysis_template=True, priority=TaskPriority.NORMAL):
        tasks = []
        for email_id in email_ids:
            task = self.reply_email(email_id, use_analysis_template=use_analysis_template, priority=priority)
            tasks.append(task)
        return tasks

    def auto_process_new_emails(self, email_ids):
        if not email_ids:
            return []
        self._load_config_from_db()
        print(f"Auto process {len(email_ids)} new emails: auto_analyze={self.auto_analyze}, auto_reply={self.auto_reply}")
        tasks = []
        for email_id in email_ids:
            if self.auto_analyze:
                try:
                    task = self.analyze_email(email_id, TaskPriority.NORMAL, auto_reply_after=self.auto_reply)
                    tasks.append(task)
                except Exception as e:
                    print(f"Failed to process email {email_id}: {e}")
        return tasks

    def update_config(self, auto_analyze=None, auto_reply=None, analysis_workers=None,
                      reply_workers=None, reply_rate_limit_per_min=None, sender_display_name=None):
        if auto_analyze is not None:
            self.auto_analyze = auto_analyze
        if auto_reply is not None:
            self.auto_reply = auto_reply
        if analysis_workers is not None:
            self.analysis_workers = analysis_workers
            task_queue.update_worker_count(analysis_workers=analysis_workers)
        if reply_workers is not None:
            self.reply_workers = reply_workers
            task_queue.update_worker_count(reply_workers=reply_workers)
        if reply_rate_limit_per_min is not None:
            self.reply_rate_limit_per_min = reply_rate_limit_per_min
        if sender_display_name is not None:
            self.sender_display_name = sender_display_name
        self._save_config_to_db()

    def _save_config_to_db(self):
        try:
            config = PipelineConfig.query.filter_by(name='default').first()
            if config:
                config.auto_analyze = self.auto_analyze
                config.auto_reply = self.auto_reply
                config.analysis_workers = self.analysis_workers
                config.reply_workers = self.reply_workers
                config.reply_rate_limit_per_min = self.reply_rate_limit_per_min
                config.sender_display_name = self.sender_display_name
                config.is_active = True
            else:
                config = PipelineConfig(
                    name='default',
                    auto_analyze=self.auto_analyze,
                    auto_reply=self.auto_reply,
                    analysis_workers=self.analysis_workers,
                    reply_workers=self.reply_workers,
                    reply_rate_limit_per_min=self.reply_rate_limit_per_min,
                    sender_display_name=self.sender_display_name,
                    is_active=True
                )
                db.session.add(config)
            db.session.commit()
        except Exception as e:
            print(f"保存流水线配置失败: {e}")
            db.session.rollback()
            raise e

    def get_config(self):
        self._load_config_from_db()
        return {
            'auto_analyze': self.auto_analyze,
            'auto_reply': self.auto_reply,
            'analysis_workers': self.analysis_workers,
            'reply_workers': self.reply_workers,
            'reply_rate_limit_per_min': self.reply_rate_limit_per_min,
            'sender_display_name': self.sender_display_name
        }


email_pipeline = EmailPipeline()
