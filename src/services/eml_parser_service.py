import email
import uuid
import re
import base64
from datetime import datetime
from email.utils import parseaddr, parsedate_to_datetime


class EmlParserService:
    @staticmethod
    def parse_eml_file(eml_content):
        """解析 .eml 格式邮件内容"""
        try:
            msg = email.message_from_bytes(eml_content)
            
            message_id = msg.get('Message-ID', '') or str(uuid.uuid4())
            if message_id:
                message_id = message_id.strip('<>')
            
            subject = msg.get('Subject', '') or '(无主题)'
            try:
                from email.header import decode_header
                decoded_subject = []
                for part, charset in decode_header(subject):
                    if isinstance(part, bytes):
                        decoded_subject.append(part.decode(charset or 'utf-8', errors='replace'))
                    else:
                        decoded_subject.append(part)
                subject = ''.join(decoded_subject)
            except Exception:
                pass
            
            from_email = msg.get('From', '')
            from_name, from_addr = parseaddr(from_email)
            if not from_addr:
                from_addr = from_email
            
            to_email = msg.get('To', '')
            to_emails = []
            if to_email:
                for addr in to_email.split(','):
                    _, email_addr = parseaddr(addr.strip())
                    if email_addr:
                        to_emails.append(email_addr)
                to_email = ', '.join(to_emails)
            
            cc_email = msg.get('Cc', '')
            if cc_email:
                cc_emails = []
                for addr in cc_email.split(','):
                    _, email_addr = parseaddr(addr.strip())
                    if email_addr:
                        cc_emails.append(email_addr)
                cc_email = ', '.join(cc_emails)
            
            received_at = None
            date_str = msg.get('Date', '')
            if date_str:
                try:
                    received_at = parsedate_to_datetime(date_str)
                except Exception:
                    pass
            
            body = ''
            attachments = []
            
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get('Content-Disposition', ''))
                    
                    if 'attachment' in content_disposition:
                        filename = part.get_filename()
                        if filename:
                            attachments.append(filename)
                    elif content_type == 'text/plain' and 'attachment' not in content_disposition:
                        try:
                            payload = part.get_payload(decode=True)
                            if payload:
                                charset = part.get_content_charset() or 'utf-8'
                                body = payload.decode(charset, errors='replace')
                        except Exception:
                            pass
                    elif content_type == 'text/html' and not body and 'attachment' not in content_disposition:
                        try:
                            payload = part.get_payload(decode=True)
                            if payload:
                                charset = part.get_content_charset() or 'utf-8'
                                html_body = payload.decode(charset, errors='replace')
                                text = re.sub(r'<[^>]+>', '', html_body)
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
                    if payload:
                        charset = msg.get_content_charset() or 'utf-8'
                        body = payload.decode(charset, errors='replace')
                except Exception:
                    body = msg.get_payload() or ''
            
            return {
                'success': True,
                'message_id': message_id,
                'subject': subject,
                'from_email': from_addr or 'unknown@unknown.com',
                'to_email': to_email,
                'cc_email': cc_email,
                'body': body,
                'received_at': received_at,
                'attachments': ', '.join(attachments) if attachments else None,
                'raw_content': base64.b64encode(eml_content).decode('utf-8')
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    @staticmethod
    def parse_eml_file_path(file_path):
        """从文件路径解析 .eml 文件"""
        try:
            with open(file_path, 'rb') as f:
                eml_content = f.read()
            return EmlParserService.parse_eml_file(eml_content)
        except Exception as e:
            return {
                'success': False,
                'error': f'无法读取文件: {str(e)}'
            }