import imaplib
import poplib
import smtplib
import email
import base64
import re
import html
import binascii
from email.header import decode_header
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from src.models.db import db, EmailRecord


def modified_utf7_encode(s):
    """
    Modified UTF-7 编码（IMAP邮箱文件夹名编码）
    将中文字符编码为 &<base64-of-utf16be>- 格式
    """
    result = []
    buffer = ''
    for ch in s:
        if ord(ch) >= 0x20 and ord(ch) != 0x7E:
            buffer += ch
        else:
            if buffer:
                encoded = base64.b64encode(buffer.encode('utf-16-be')).decode('ascii').rstrip('=')
                result.append('&' + encoded + '-')
                buffer = ''
            result.append(ch)
    if buffer:
        encoded = base64.b64encode(buffer.encode('utf-16-be')).decode('ascii').rstrip('=')
        result.append('&' + encoded + '-')
    return ''.join(result)


def _extract_email_body_text(body):
    """
    提取并清理邮件正文为纯文本，用于回复时附带原始邮件内容。
    去除HTML标签、解码HTML实体、折叠多余空白，保留完整正文内容。
    """
    if not body:
        return ''

    text = body

    # 去除 <style>/<script> 及其内容
    text = re.sub(r'(?is)<(style|script)[^>]*>.*?</\1>', ' ', text)

    # 将块级标签和 <br> 转为换行，便于保留段落结构
    text = re.sub(r'(?i)<br\s*/?>', '\n', text)
    text = re.sub(r'(?i)</?(p|div|tr|li|h[1-6])[^>]*>', '\n', text)

    # 去除其余所有 HTML 标签
    text = re.sub(r'<[^>]+>', ' ', text)

    # 解码 HTML 实体
    text = html.unescape(text)

    # 去除多余的空白字符，折叠连续换行
    text = text.replace('\r\n', '\n').replace('\r', '\n')
    text = re.sub(r'[ \t]+', ' ', text)
    text = re.sub(r'\n\s*\n+', '\n\n', text)
    text = text.strip()

    return text


def generate_analysis_reply_email(email_record, analysis_result, security_advice):
    """
    生成钓鱼邮件分析回复内容（HTML格式）
    """
    is_phishing = analysis_result.get('is_phishing', False)
    conclusion_text = '钓鱼邮件' if is_phishing else '正常邮件'
    advice_text = security_advice.get('phishing_advice', '') if is_phishing else security_advice.get('normal_advice', '')
    analysis_report = analysis_result.get('analysis_report', '')
    indicators = analysis_result.get('indicators', '')
    confidence = analysis_result.get('confidence')
    risk_level = analysis_result.get('risk_level', '')
    phishing_type = analysis_result.get('phishing_type', '')

    # 风险等级中文映射
    risk_level_map = {'high': '高危', 'medium': '中危', 'low': '低危'}
    risk_level_text = risk_level_map.get(risk_level, str(risk_level)) if risk_level else ''

    # 置信度格式化（confidence 为 0-1 的浮点数）
    confidence_text = ''
    if confidence is not None:
        try:
            confidence_text = f'{float(confidence) * 100:.1f}%'
        except (TypeError, ValueError):
            confidence_text = str(confidence)

    # 原始邮件标题、正文与附件
    original_subject = (email_record.subject or '').strip() or '（无标题）'
    original_body = _extract_email_body_text(getattr(email_record, 'body', ''))

    # 解析附件列表（attachments 字段以逗号分隔的文件名）
    attachment_list = []
    attachments_raw = getattr(email_record, 'attachments', '') or ''
    if attachments_raw:
        attachment_list = [a.strip() for a in attachments_raw.split(',') if a.strip()]

    # 纯文本版本
    if getattr(email_record, 'from_email', ''):
        original_from_line = f'发件人：{email_record.from_email}\n'
    else:
        original_from_line = ''
    attachment_line = ('附件：' + '、'.join(attachment_list) + '\n') if attachment_list else ''
    original_block = f'''【原始邮件信息】
邮件标题：{original_subject}
{original_from_line}{attachment_line}邮件正文：
{original_body if original_body else '（无正文内容）'}'''

    plain_body = f'''尊敬的同事：

钓鱼邮件智能分析系统已对您上报的邮件进行了深度研判分析。

【判定结果】
该邮件已被判定为{conclusion_text}，{('请您高度重视，切勿点击邮件内任何链接、下载附件或回复邮件信息。' if is_phishing else '可视为正常邮件处理。')}

【分析依据】
{('置信度：' + confidence_text) if confidence_text else ''}{('  风险等级：' + risk_level_text) if risk_level_text else ''}{('  钓鱼类型：' + phishing_type) if phishing_type else ''}
{analysis_report if analysis_report else '暂无详细分析依据'}
{('特征指标：' + indicators if indicators else '')}

【安全风险提示】
{advice_text}

{original_block}

感谢您的配合！

网络安全生产室'''

    # HTML版本：将换行符转为<br>标签，确保所有邮件客户端都能正确显示换行
    advice_html = html.escape(advice_text).replace('\n', '<br>') if advice_text else ''
    report_html = html.escape(analysis_report).replace('\n', '<br>') if analysis_report else '暂无详细分析依据'
    indicators_html = html.escape(indicators).replace('\n', '<br>') if indicators else ''
    original_subject_html = html.escape(original_subject)
    original_body_html = html.escape(original_body).replace('\n', '<br>') if original_body else '（无正文内容）'
    original_from_html = html.escape(email_record.from_email) if getattr(email_record, 'from_email', '') else ''
    attachments_html = html.escape('、'.join(attachment_list)) if attachment_list else ''

    result_color = '#ff0000' if is_phishing else '#00aa00'
    result_bg = '#fff0f0' if is_phishing else '#f0fff0'

    # 分析依据附加信息行
    meta_parts = []
    if confidence_text:
        meta_parts.append(f'<strong>置信度：</strong>{confidence_text}')
    if risk_level_text:
        meta_parts.append(f'<strong>风险等级：</strong>{risk_level_text}')
    if phishing_type:
        meta_parts.append(f'<strong>钓鱼类型：</strong>{html.escape(phishing_type)}')
    meta_html = '　'.join(meta_parts)

    html_body = f'''<html>
<head>
<style>
    body {{ font-family: 'Microsoft YaHei', Arial, sans-serif; line-height: 1.3; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }}
    .result-text {{
        color: {result_color};
        font-size: 18px;
        font-weight: bold;
    }}
    .section-title {{ font-weight: bold; font-size: 16px; margin-top: 24px; margin-bottom: 12px; color: #1a5276; }}
    .advice-content {{ margin: 10px 0; padding-left: 10px; }}
    .report-content {{ margin: 10px 0; padding: 12px; background: #f8f9fa; border-left: 3px solid #1a5276; border-radius: 4px; }}
    .indicators {{ margin: 8px 0; padding-left: 10px; color: #555; font-size: 14px; }}
    .meta-info {{ margin: 8px 0; padding: 10px 12px; background: #eef4fb; border-radius: 4px; color: #1a5276; font-size: 14px; }}
    .original-block {{ margin: 10px 0; padding: 12px; background: #fffdf3; border: 1px solid #e8e0c8; border-radius: 4px; }}
    .original-subject {{ font-weight: bold; color: #333; margin-bottom: 6px; }}
    .original-body {{ color: #555; font-size: 13px; margin-top: 6px; }}
    .greeting {{ margin-bottom: 20px; }}
    .footer {{ margin-top: 30px; color: #666; }}
</style>
</head>
<body>
<p class="greeting">尊敬的同事：</p>

<p>钓鱼邮件智能分析系统已对您上报的邮件进行了深度研判分析。</p>

<p class="section-title">【判定结果】</p>
<p>该邮件已被判定为<span class="result-text">{conclusion_text}</span>，{('请您高度重视，切勿点击邮件内任何链接、下载附件或回复邮件信息。' if is_phishing else '可视为正常邮件处理。')}</p>

<p class="section-title">【分析依据】</p>
{f'<div class="meta-info">{meta_html}</div>' if meta_html else ''}
<div class="report-content">{report_html}</div>
{f'<p class="indicators"><strong>特征指标：</strong>{indicators_html}</p>' if indicators_html else ''}

<p class="section-title">【安全风险提示】</p>
<div class="advice-content">{advice_html}</div>

<p class="section-title">【原始邮件信息】</p>
<div class="original-block">
    <div class="original-subject">邮件标题：{original_subject_html}</div>
    {f'<div class="original-subject" style="font-weight:normal;">发件人：{original_from_html}</div>' if original_from_html else ''}
    {f'<div class="original-subject" style="font-weight:normal;">附件：{attachments_html}</div>' if attachments_html else ''}
    <div class="original-body">{original_body_html}</div>
</div>

<div class="footer">
<p>感谢您的配合！</p>
<p>网络安全生产室</p>
</div>
</body>
</html>'''

    # 邮件主题包含原始邮件标题，便于收件人快速识别；标题过长时截断
    subject_title = original_subject if len(original_subject) <= 80 else original_subject[:80] + '…'
    subject = f'【检测结果：{conclusion_text}】{subject_title}'

    return {
        'subject': subject,
        'plain_body': plain_body,
        'html_body': html_body
    }


class EmailService:
    def __init__(self, mail_server_config):
        self.config = mail_server_config

    def test_connection(self):
        results = {'imap': False, 'smtp': False, 'message': ''}
        try:
            if self.config.imap_ssl:
                imap = imaplib.IMAP4_SSL(self.config.imap_server, self.config.imap_port)
            else:
                imap = imaplib.IMAP4(self.config.imap_server, self.config.imap_port)
            imap.login(self.config.email, self.config.password)
            imap.logout()
            results['imap'] = True
        except Exception as e:
            results['message'] += f'IMAP连接失败: {str(e)}; '

        try:
            if self.config.smtp_ssl:
                smtp = smtplib.SMTP_SSL(self.config.smtp_server, self.config.smtp_port)
            else:
                smtp = smtplib.SMTP(self.config.smtp_server, self.config.smtp_port)
            smtp.login(self.config.email, self.config.password)
            smtp.quit()
            results['smtp'] = True
        except Exception as e:
            results['message'] += f'SMTP连接失败: {str(e)}'

        if results['imap'] and results['smtp']:
            results['message'] = 'IMAP和SMTP连接均正常'
        return results

    def fetch_new_emails(self, limit=0):
        domain = self.config.email.split('@')[-1].lower()
        if domain in ('163.com', '126.com', '188.com', 'yeah.net'):
            try:
                result = self._fetch_emails_pop3(limit)
                if result.get('success'):
                    return result
                print(f'POP3 fetch returned failure: {result.get("message")}')
            except Exception as pop3_err:
                print(f'POP3 fetch exception: {pop3_err}')
            try:
                return self._fetch_emails_imap(limit)
            except Exception as imap_err:
                print(f'IMAP fetch exception: {imap_err}')
            return {'success': False, 'message': 'POP3和IMAP获取邮件均失败'}
        try:
            result = self._fetch_emails_imap(limit)
            if result.get('success'):
                return result
            print(f'IMAP fetch returned failure: {result.get("message")}')
        except Exception as imap_err:
            print(f'IMAP fetch exception: {imap_err}')
        try:
            return self._fetch_emails_pop3(limit)
        except Exception as pop3_err:
            print(f'POP3 fetch exception: {pop3_err}')
            return {'success': False, 'message': 'IMAP和POP3获取邮件均失败'}

    def _fetch_emails_pop3(self, limit=0):
        try:
            pop = None
            pop_server = self.config.imap_server.replace('imap.', 'pop.')
            pop_port = 995 if self.config.imap_ssl else 110

            print(f'POP3 connecting to {pop_server}:{pop_port}, ssl={self.config.imap_ssl}')

            if self.config.imap_ssl:
                pop = poplib.POP3_SSL(pop_server, pop_port)
            else:
                pop = poplib.POP3(pop_server, pop_port)

            print(f'POP3 connected, server greeting: {pop.getwelcome()}')

            import time
            time.sleep(1)

            pop.user(self.config.email)
            
            time.sleep(1)
            
            pop.pass_(self.config.password)
            print(f'POP3 login success for {self.config.email}')

            num_messages = len(pop.list()[1])
            print(f'POP3 found {num_messages} messages')

            if limit > 0 and num_messages > limit:
                start_idx = num_messages - limit + 1
            else:
                start_idx = 1

            fetched_count = 0
            for i in range(start_idx, num_messages + 1):
                try:
                    response, lines, octets = pop.retr(i)
                    raw_email = b'\r\n'.join(lines)
                    msg = email.message_from_bytes(raw_email)

                    message_id = msg.get('Message-ID', '')
                    if not message_id:
                        message_id = f"{self.config.email}_{i}"

                    existing = EmailRecord.query.filter_by(message_id=message_id).first()
                    if existing:
                        continue

                    subject = self._decode_header(msg.get('Subject', ''))
                    from_email = self._decode_header(msg.get('From', ''))
                    to_email = self._decode_header(msg.get('To', ''))
                    cc_email = self._decode_header(msg.get('Cc', ''))

                    body = ''
                    attachments = []
                    if msg.is_multipart():
                        for part in msg.walk():
                            content_type = part.get_content_type()
                            content_disposition = str(part.get('Content-Disposition', ''))

                            if 'attachment' in content_disposition:
                                filename = part.get_filename()
                                if filename:
                                    decoded_filename = self._decode_header(filename)
                                    attachments.append(decoded_filename)
                            elif content_type == 'text/plain':
                                try:
                                    payload = part.get_payload(decode=True)
                                    body += self._decode_payload(payload)
                                except Exception:
                                    pass
                            elif content_type == 'text/html' and not body:
                                try:
                                    payload = part.get_payload(decode=True)
                                    html = self._decode_payload(payload)
                                    from bs4 import BeautifulSoup
                                    soup = BeautifulSoup(html, 'html.parser')
                                    text = soup.get_text(separator='\n')
                                    lines = text.split('\n')
                                    cleaned = []
                                    empty_count = 0
                                    for line in lines:
                                        if line.strip() == '':
                                            empty_count += 1
                                            if empty_count <= 1:
                                                cleaned.append('')
                                        else:
                                            empty_count = 0
                                            cleaned.append(line.strip())
                                    body = '\n'.join(cleaned)
                                except Exception:
                                    pass
                    else:
                        try:
                            payload = msg.get_payload(decode=True)
                            body = self._decode_payload(payload)
                        except Exception:
                            pass

                    date_str = msg.get('Date', '')
                    received_at = None
                    try:
                        from email.utils import parsedate_to_datetime
                        received_at = parsedate_to_datetime(date_str)
                    except Exception:
                        received_at = datetime.now()

                    record = EmailRecord(
                        message_id=message_id,
                        subject=subject[:500] if subject else '',
                        from_email=from_email[:200] if from_email else '',
                        to_email=to_email[:200] if to_email else '',
                        cc_email=cc_email[:500] if cc_email else '',
                        body=body,
                        raw_content=base64.b64encode(raw_email).decode('utf-8'),
                        attachments=','.join(attachments) if attachments else None,
                        received_at=received_at,
                        status='pending',
                        source='mail_server',
                        mail_server_id=self.config.id
                    )
                    db.session.add(record)
                    fetched_count += 1
                except Exception as msg_err:
                    print(f'POP3 message {i} error: {msg_err}')
                    continue

            db.session.commit()
            pop.quit()
            print(f'POP3 fetch completed, {fetched_count} new emails')
            return {'success': True, 'message': f'成功获取 {fetched_count} 封邮件', 'count': fetched_count}

        except Exception as e:
            try:
                pop.quit()
            except Exception:
                pass
            err_str = str(e)
            print(f'POP3 error: {err_str}')
            if 'ERR' in err_str and ('登录' in err_str or '认证' in err_str or 'password' in err_str.lower()):
                domain = self.config.email.split('@')[-1].lower()
                if domain in ('163.com', '126.com', '188.com', 'yeah.net'):
                    return {'success': False, 'message': f'网易邮箱({domain})POP3登录失败：请使用邮箱的"客户端授权码"代替登录密码，在邮箱设置->客户端授权中开启POP3并获取授权码'}
                return {'success': False, 'message': f'POP3登录失败，请确认密码正确。部分邮箱需要使用"客户端授权码"而非登录密码'}
            return {'success': False, 'message': f'POP3获取邮件失败: {err_str}'}

    def _fetch_emails_imap(self, limit=0):
        try:
            mail = None
            if self.config.imap_ssl:
                try:
                    mail = imaplib.IMAP4_SSL(self.config.imap_server, self.config.imap_port)
                except Exception as ssl_err:
                    print(f'IMAP4_SSL default error: {ssl_err}')
                    try:
                        import ssl
                        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                        context.minimum_version = ssl.TLSVersion.TLSv1_2
                        mail = imaplib.IMAP4_SSL(self.config.imap_server, self.config.imap_port, ssl_context=context)
                    except Exception as tls12_err:
                        print(f'IMAP4_SSL TLS1.2 error: {tls12_err}')
                        mail = None
            else:
                mail = imaplib.IMAP4(self.config.imap_server, self.config.imap_port)
            
            if mail is None:
                return {'success': False, 'message': '无法建立IMAP连接'}

            login_ok = False
            select_msg = None
            try:
                login_status, login_resp = mail.login(self.config.email, self.config.password)
                print(f'IMAP LOGIN status: {login_status}')
                login_ok = True
            except Exception as login_err:
                err_str = str(login_err)
                print(f'IMAP LOGIN error: {err_str}')
                if 'Unsafe Login' in err_str or 'AUTHENTICATIONFAILED' in err_str:
                    domain = self.config.email.split('@')[-1].lower()
                    if domain in ('163.com', '126.com', '188.com', 'yeah.net'):
                        return {'success': False, 'message': f'网易邮箱({domain})登录失败：请使用邮箱的"客户端授权码"代替登录密码，在邮箱设置->客户端授权中开启IMAP并获取授权码'}
                    return {'success': False, 'message': f'邮箱登录失败，请确认密码正确。部分邮箱需要使用"客户端授权码"而非登录密码'}
                return {'success': False, 'message': f'邮箱登录失败: {err_str}'}

            if not login_ok:
                return {'success': False, 'message': '邮箱登录失败'}

            try:
                cap_status, cap_resp = mail.capability()
                print(f'IMAP CAPABILITY: {cap_status}')
            except Exception:
                pass

            try:
                noop_status, noop_resp = mail.noop()
                print(f'IMAP NOOP status: {noop_status}')
            except Exception:
                pass

            folder_selected = False
            select_msg = None
            for folder_name in ('INBOX', 'inbox'):
                try:
                    status, select_msg = mail.select(folder_name, readonly=True)
                    print(f'IMAP select {folder_name}: {status}, msg: {select_msg}')
                    if status == 'OK':
                        folder_selected = True
                        break
                except Exception as select_err:
                    print(f'IMAP select {folder_name} error: {select_err}')

            if not folder_selected:
                try:
                    mail.logout()
                except Exception:
                    pass
                err_text = ''
                if select_msg and hasattr(select_msg, '__iter__') and len(select_msg) > 0:
                    err_text = select_msg[0].decode() if hasattr(select_msg[0], 'decode') else str(select_msg[0])
                print(f'IMAP select error detail: {err_text}')
                if 'Unsafe Login' in err_text:
                    domain = self.config.email.split('@')[-1].lower()
                    if domain in ('163.com', '126.com', '188.com', 'yeah.net'):
                        return {'success': False, 'message': f'网易邮箱({domain})IMAP登录被拒绝：授权码已确认正确且服务已开启，请在163邮箱网页端查看是否有"异地登录"或"安全验证"弹窗，点击允许后重试'}
                return {'success': False, 'message': f'无法选择收件箱: {err_text}'}

            status, messages = mail.search(None, 'ALL')
            if status != 'OK':
                mail.logout()
                return {'success': False, 'message': '搜索邮件失败'}

            msg_ids = messages[0].split()
            if limit > 0:
                msg_ids = msg_ids[-limit:]

            fetched_count = 0
            for msg_id in msg_ids:
                status, msg_data = mail.fetch(msg_id, '(RFC822)')
                if status != 'OK':
                    continue

                raw_email = msg_data[0][1]
                msg = email.message_from_bytes(raw_email)

                message_id = msg.get('Message-ID', '')
                if not message_id:
                    message_id = f"{self.config.email}_{msg_id.decode()}"

                existing = EmailRecord.query.filter_by(message_id=message_id).first()
                if existing:
                    continue

                subject = self._decode_header(msg.get('Subject', ''))
                from_email = self._decode_header(msg.get('From', ''))
                to_email = self._decode_header(msg.get('To', ''))
                cc_email = self._decode_header(msg.get('Cc', ''))

                body = ''
                attachments = []
                if msg.is_multipart():
                    for part in msg.walk():
                        content_type = part.get_content_type()
                        content_disposition = str(part.get('Content-Disposition', ''))

                        if 'attachment' in content_disposition:
                            filename = part.get_filename()
                            if filename:
                                decoded_filename = self._decode_header(filename)
                                attachments.append(decoded_filename)
                        elif content_type == 'text/plain':
                            try:
                                payload = part.get_payload(decode=True)
                                body += self._decode_payload(payload)
                            except Exception:
                                pass
                        elif content_type == 'text/html' and not body:
                            try:
                                payload = part.get_payload(decode=True)
                                html = self._decode_payload(payload)
                                from bs4 import BeautifulSoup
                                soup = BeautifulSoup(html, 'html.parser')
                                text = soup.get_text(separator='\n')
                                lines = text.split('\n')
                                cleaned = []
                                empty_count = 0
                                for line in lines:
                                    if line.strip() == '':
                                        empty_count += 1
                                        if empty_count <= 1:
                                            cleaned.append('')
                                        else:
                                            empty_count = 0
                                            cleaned.append(line.strip())
                                body = '\n'.join(cleaned)
                            except Exception:
                                pass
                else:
                    try:
                        payload = msg.get_payload(decode=True)
                        body = self._decode_payload(payload)
                    except Exception:
                        pass

                date_str = msg.get('Date', '')
                received_at = None
                try:
                    from email.utils import parsedate_to_datetime
                    received_at = parsedate_to_datetime(date_str)
                except Exception:
                    received_at = datetime.now()

                record = EmailRecord(
                    message_id=message_id,
                    subject=subject[:500] if subject else '',
                    from_email=from_email[:200] if from_email else '',
                    to_email=to_email[:200] if to_email else '',
                    cc_email=cc_email[:500] if cc_email else '',
                    body=body,
                    raw_content=base64.b64encode(raw_email).decode('utf-8'),
                    attachments=','.join(attachments) if attachments else None,
                    received_at=received_at,
                    status='pending',
                    source='mail_server',
                    mail_server_id=self.config.id
                )
                db.session.add(record)
                fetched_count += 1

            db.session.commit()
            mail.logout()
            return {'success': True, 'message': f'成功获取 {fetched_count} 封新邮件'}

        except Exception as e:
            return {'success': False, 'message': f'获取邮件失败: {str(e)}'}

    def send_reply(self, to_email, subject, body, html_body=None, sender_display_name=None):
        try:
            if self.config.smtp_ssl:
                smtp = smtplib.SMTP_SSL(self.config.smtp_server, self.config.smtp_port)
            else:
                smtp = smtplib.SMTP(self.config.smtp_server, self.config.smtp_port)

            smtp.login(self.config.email, self.config.password)

            msg = MIMEMultipart('alternative')
            # 设置发件人显示名称，让对方看到名称而非邮箱账号
            if sender_display_name:
                from email.utils import formataddr
                msg['From'] = formataddr((sender_display_name, self.config.email))
            else:
                msg['From'] = self.config.email
            msg['To'] = to_email
            msg['Subject'] = subject

            msg.attach(MIMEText(body, 'plain', 'utf-8'))
            if html_body:
                msg.attach(MIMEText(html_body, 'html', 'utf-8'))

            raw_content = msg.as_string()
            smtp.sendmail(self.config.email, to_email, raw_content)
            smtp.quit()
            return {'success': True, 'message': '邮件发送成功', 'raw_content': raw_content}
        except Exception as e:
            return {'success': False, 'message': f'发送邮件失败: {str(e)}', 'raw_content': None}

    def fetch_sent_emails(self, limit=50):
        """
        获取已发送邮件
        """
        import base64
        sent_emails = []
        try:
            imap = None
            # 开启 imaplib 调试日志，定位 SELECT 失败原因
            imaplib.Debug = 4
            if self.config.imap_ssl:
                imap = imaplib.IMAP4_SSL(self.config.imap_server, self.config.imap_port)
            else:
                imap = imaplib.IMAP4(self.config.imap_server, self.config.imap_port)

            login_res = imap.login(self.config.email, self.config.password)
            print(f'IMAP LOGIN status: {login_res[0]}')

            # 网易邮箱特殊处理：模拟常见邮件客户端发送ID命令
            # 163邮箱的安全策略会检查客户端ID，模拟Thunderbird等知名客户端更容易通过
            id_sent = False
            email_domain = self.config.email.split('@')[-1].lower()
            is_netease = email_domain in ('163.com', '126.com', '188.com', 'yeah.net')
            
            if is_netease:
                # 模拟Thunderbird的ID（最常见的邮件客户端之一）
                thunderbird_id = ('name', 'Thunderbird', 'version', '115.0', 'vendor', 'Mozilla', 'support-url', 'https://www.thunderbird.net')
                try:
                    if hasattr(imap, 'id_'):
                        id_result = imap.id_(thunderbird_id)
                    elif hasattr(imap, 'id'):
                        id_result = imap.id(thunderbird_id)
                    print(f'IMAP ID (Thunderbird) status: {id_result[0]}')
                    id_sent = True
                except Exception as id_err:
                    print(f'IMAP ID (Thunderbird) failed: {id_err}')
            
            if not id_sent:
                # 标准ID命令
                try:
                    if hasattr(imap, 'id_'):
                        id_result = imap.id_(('name', 'python-imap-client', 'version', '1.0', 'vendor', 'phishing-agent'))
                    elif hasattr(imap, 'id'):
                        id_result = imap.id(('name', 'python-imap-client', 'version', '1.0', 'vendor', 'phishing-agent'))
                    print(f'IMAP ID status: {id_result[0]}')
                except Exception as id_err:
                    print(f'IMAP ID command failed: {id_err}')

            # 发送CAPABILITY命令
            try:
                cap_result = imap.capability()
                print(f'IMAP CAPABILITY: {cap_result[0]}')
            except Exception as cap_err:
                print(f'IMAP CAPABILITY failed: {cap_err}')

            # 发送NOOP命令（保持连接活跃）
            try:
                noop_result = imap.noop()
                print(f'IMAP NOOP status: {noop_result[0]}')
            except Exception as noop_err:
                print(f'IMAP NOOP failed: {noop_err}')

            # 列出所有文件夹，找到"已发送"文件夹
            status, folders = imap.list()
            folder_list = []
            if status == 'OK':
                for f in folders:
                    if f:
                        line = f.decode('utf-8', errors='ignore') if isinstance(f, bytes) else str(f)
                        folder_list.append(line)
                print(f'Available folders: {folder_list}')

            # 从文件夹列表中匹配已发送邮件文件夹
            sent_folder = None
            sent_folder_display = None
            for line in folder_list:
                # 优先匹配带 (\Sent) 标识的文件夹（网易邮箱格式）
                if '\\Sent' in line or '(\\Sent)' in line:
                    match = re.search(r'"([^"]+)"$', line)
                    if match:
                        sent_folder = match.group(1)
                        sent_folder_display = sent_folder
                        break

            if not sent_folder:
                # 使用关键字模糊匹配
                sent_keywords = ['Sent', '已发送', '已发送邮件', 'Sent Messages', 'Sent Items']
                for line in folder_list:
                    for kw in sent_keywords:
                        if kw in line:
                            match = re.search(r'"([^"]+)"$', line)
                            if match:
                                sent_folder = match.group(1)
                                sent_folder_display = sent_folder
                                break
                    if sent_folder:
                        break

            if not sent_folder:
                return {'success': False, 'message': f'未找到已发送邮件文件夹。可用文件夹: {folder_list}', 'emails': []}

            # 选择已发送文件夹
            status = 'NO'
            data = None
            actual_folder = None
            last_error = None
            select_attempts = []

            # 网易邮箱特殊处理：先尝试通过imaplib标准select命令
            # 如果失败，再尝试原始socket方式
            if is_netease:
                for folder_name in [sent_folder, '&XfJT0ZAB-', 'Sent', 'INBOX.Sent', '&g0l6P3ux-']:
                    if not folder_name:
                        continue
                    try:
                        # 先尝试EXAMINE（只读模式，可能绕过安全检查）
                        status_examine, msg_examine = imap.examine(folder_name)
                        print(f'IMAP EXAMINE {folder_name}: {status_examine}, {msg_examine}')
                        if status_examine == 'OK':
                            status = 'OK'
                            actual_folder = folder_name
                            print(f'Selected sent folder via EXAMINE: {folder_name}')
                            break
                        select_attempts.append(f'EXAMINE {folder_name}: {status_examine}')
                        
                        # 尝试SELECT
                        status_select, msg_select = imap.select(folder_name, readonly=True)
                        print(f'IMAP SELECT {folder_name}: {status_select}, {msg_select}')
                        if status_select == 'OK':
                            status = 'OK'
                            actual_folder = folder_name
                            print(f'Selected sent folder via SELECT: {folder_name}')
                            break
                        select_attempts.append(f'SELECT {folder_name}: {status_select}')
                        
                    except Exception as e:
                        select_attempts.append(f'{folder_name}: exception {e}')
                        print(f'Select {folder_name} exception: {e}')
                        continue

            # 如果标准方式失败，尝试原始socket方式
            if status != 'OK':
                for attempt_folder in [sent_folder, '&XfJT0ZAB-', 'Sent', 'INBOX.Sent', '&g0l6P3ux-']:
                    if not attempt_folder:
                        continue
                    try:
                        if attempt_folder.startswith('&'):
                            folder_bytes = b'"' + attempt_folder.encode('ascii') + b'"'
                        else:
                            try:
                                folder_bytes = b'"' + attempt_folder.encode('ascii') + b'"'
                            except UnicodeEncodeError:
                                folder_bytes = b'"' + modified_utf7_encode(attempt_folder).encode('ascii') + b'"'
                        
                        # 先尝试EXAMINE命令（只读模式）
                        raw_tag = b'XEXAMINE'
                        raw_cmd = raw_tag + b' EXAMINE ' + folder_bytes + b'\r\n'
                        print(f'Raw EXAMINE command: {raw_cmd}')
                        imap.sock.sendall(raw_cmd)
                        
                        response_lines = []
                        final_status = None
                        final_data = b''
                        while True:
                            line = imap.file.readline()
                            if not line:
                                raise Exception('socket closed')
                            line = line.rstrip(b'\r\n')
                            print(f'  IMAP response: {line!r}')
                            if line.startswith(raw_tag + b' '):
                                parts = line.split(b' ', 2)
                                if len(parts) >= 2:
                                    final_status = parts[1].decode('ascii', errors='replace')
                                    if len(parts) >= 3:
                                        final_data = parts[2]
                                break
                            elif line.startswith(raw_tag + b' OK') or line.startswith(raw_tag + b' NO') or line.startswith(raw_tag + b' BAD'):
                                parts = line.split(b' ', 2)
                                if len(parts) >= 2:
                                    final_status = parts[1].decode('ascii', errors='replace')
                                break
                            else:
                                response_lines.append(line)
                        
                        last_error = f'status={final_status}, data={final_data!r}'
                        select_attempts.append(f'Raw EXAMINE {attempt_folder}: {final_status}')
                        
                        if final_status == 'OK':
                            status = 'OK'
                            data = response_lines
                            actual_folder = attempt_folder
                            print(f'Selected sent folder via raw EXAMINE: {attempt_folder}')
                            imap.state = 'SELECTED'
                            imap.untagged_responses = {}
                            imap.tagged_commands = {}
                            break
                        
                        # 再尝试SELECT命令
                        raw_tag = b'XSELECT'
                        raw_cmd = raw_tag + b' SELECT ' + folder_bytes + b'\r\n'
                        print(f'Raw SELECT command: {raw_cmd}')
                        imap.sock.sendall(raw_cmd)
                        
                        response_lines = []
                        final_status = None
                        final_data = b''
                        while True:
                            line = imap.file.readline()
                            if not line:
                                raise Exception('socket closed')
                            line = line.rstrip(b'\r\n')
                            print(f'  IMAP response: {line!r}')
                            if line.startswith(raw_tag + b' '):
                                parts = line.split(b' ', 2)
                                if len(parts) >= 2:
                                    final_status = parts[1].decode('ascii', errors='replace')
                                    if len(parts) >= 3:
                                        final_data = parts[2]
                                break
                            elif line.startswith(raw_tag + b' OK') or line.startswith(raw_tag + b' NO') or line.startswith(raw_tag + b' BAD'):
                                parts = line.split(b' ', 2)
                                if len(parts) >= 2:
                                    final_status = parts[1].decode('ascii', errors='replace')
                                break
                            else:
                                response_lines.append(line)
                        
                        last_error = f'status={final_status}, data={final_data!r}'
                        select_attempts.append(f'Raw SELECT {attempt_folder}: {final_status}')
                        
                        if final_status == 'OK':
                            status = 'OK'
                            data = response_lines
                            actual_folder = attempt_folder
                            print(f'Selected sent folder via raw SELECT: {attempt_folder}')
                            imap.state = 'SELECTED'
                            imap.untagged_responses = {}
                            imap.tagged_commands = {}
                            break
                            
                    except Exception as e:
                        last_error = str(e)
                        select_attempts.append(f'{attempt_folder}: exception {e}')
                        print(f'select "{attempt_folder}" exception: {e}')
                        continue

            if status != 'OK':
                err_msg = ''
                if last_error:
                    err_msg = str(last_error)
                if 'Unsafe Login' in err_msg or 'unsafe' in err_msg.lower():
                    return {
                        'success': False,
                        'message': f'网易邮箱安全策略限制：无法访问发件箱文件夹({sent_folder_display})。\n\n【原因】\n163邮箱的IMAP服务器对非官方客户端访问发件箱有严格限制，这是服务器端策略，代码无法绕过。\n\n【当前状态】\n✓ 收件箱同步正常\n✓ SMTP发送邮件正常\n✗ 发件箱同步暂时不可用\n\n【建议方案】\n1. 手动访问163网页邮箱查看已发送邮件\n2. 使用其他邮箱服务商（QQ邮箱、企业邮箱等）\n3. 在163网页邮箱联系客服解除限制\n\n如需跳过发件箱同步，请忽略此提示。',
                        'emails': [],
                        'unsafe_login': True
                    }
                attempts_info = ', '.join(select_attempts) if select_attempts else ''
                return {'success': False, 'message': f'选择文件夹失败: {sent_folder_display}。可用文件夹: {folder_list}。尝试记录: {attempts_info}。最后错误: {last_error}', 'emails': []}
            sent_folder = actual_folder
            sent_folder_display = actual_folder
            print(f'Selected sent folder: {sent_folder_display}')
            imaplib.Debug = 0

            # 搜索邮件
            status, messages = imap.search(None, 'ALL')
            if status != 'OK':
                return {'success': False, 'message': '搜索已发送邮件失败', 'emails': []}

            email_ids = messages[0].split()
            if limit > 0:
                email_ids = email_ids[-limit:]

            for email_id in email_ids:
                status, msg_data = imap.fetch(email_id, '(RFC822)')
                if status != 'OK':
                    continue

                raw_email = msg_data[0][1]
                msg = email.message_from_bytes(raw_email)

                # 解析邮件
                subject = self._decode_header(msg.get('Subject', ''))
                from_email = self._decode_header(msg.get('From', ''))
                to_email = self._decode_header(msg.get('To', ''))
                date_str = msg.get('Date', '')

                # 获取正文
                body = ''
                if msg.is_multipart():
                    for part in msg.walk():
                        content_type = part.get_content_type()
                        if content_type == 'text/plain' and not body:
                            try:
                                payload = part.get_payload(decode=True)
                                charset = part.get_content_charset() or 'utf-8'
                                body = payload.decode(charset, errors='replace')
                            except:
                                pass
                else:
                    try:
                        payload = msg.get_payload(decode=True)
                        charset = msg.get_content_charset() or 'utf-8'
                        body = payload.decode(charset, errors='replace')
                    except:
                        pass

                # 解析日期
                received_at = datetime.now()
                if date_str:
                    try:
                        from email.utils import parsedate_to_datetime
                        received_at = parsedate_to_datetime(date_str)
                    except:
                        pass

                sent_emails.append({
                    'message_id': msg.get('Message-ID', f'<sent-{email_id}@local>'),
                    'subject': subject,
                    'from_email': from_email,
                    'to_email': to_email,
                    'body': body,
                    'raw_content': base64.b64encode(raw_email).decode('utf-8'),
                    'received_at': received_at
                })

            imap.close()
            imap.logout()

            return {'success': True, 'message': f'成功获取 {len(sent_emails)} 封已发送邮件', 'emails': sent_emails}

        except Exception as e:
            print(f'Fetch sent emails error: {str(e)}')
            return {'success': False, 'message': f'获取已发送邮件失败: {str(e)}', 'emails': []}

    def _decode_header(self, header_value):
        if not header_value:
            return ''
        decoded = decode_header(header_value)
        result = ''
        for part, charset in decoded:
            if isinstance(part, bytes):
                try:
                    result += part.decode(charset or 'utf-8', errors='ignore')
                except Exception:
                    result += part.decode('utf-8', errors='ignore')
            else:
                result += part
        return result

    def _decode_payload(self, payload):
        if payload is None:
            return ''
        if isinstance(payload, str):
            return payload
        encodings = ['utf-8', 'gb2312', 'gbk', 'gb18030', 'big5', 'iso-8859-1']
        for encoding in encodings:
            try:
                return payload.decode(encoding)
            except Exception:
                continue
        try:
            decoded = base64.b64decode(payload).decode('utf-8', errors='ignore')
            if decoded and len(decoded) > len(payload) // 2:
                return decoded
        except Exception:
            pass
        return payload.decode('utf-8', errors='replace')