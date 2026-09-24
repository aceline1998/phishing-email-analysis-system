import os
import struct
import ctypes
import subprocess
import json
import base64
import email
from email.header import decode_header
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import glob
import tempfile

# Windows 专用模块：Linux 环境下不可用，做跨平台兼容处理
try:
    import ctypes.wintypes  # noqa: F401
except ImportError:
    pass

try:
    import winreg
except ImportError:
    winreg = None

MAPI_LOGON_UI = 0x00000001
MAPI_DIALOG = 0x00000008
MAPI_USE_DEFAULT = 0x00000020
MAPI_E_SUCCESS = 0
MAPI_E_USER_ABORT = 0x80040101


class MapiRecipDesc(ctypes.Structure):
    _fields_ = [
        ("ulReserved", ctypes.c_ulong),
        ("ulRecipClass", ctypes.c_ulong),
        ("lpszName", ctypes.c_char_p),
        ("lpszAddress", ctypes.c_char_p),
        ("ulEIDSize", ctypes.c_ulong),
        ("lpEntryID", ctypes.c_void_p),
    ]


class MapiFileDesc(ctypes.Structure):
    _fields_ = [
        ("ulReserved", ctypes.c_ulong),
        ("ulFlags", ctypes.c_ulong),
        ("lpszPathName", ctypes.c_char_p),
        ("lpszFileName", ctypes.c_char_p),
        ("lpFileData", ctypes.c_void_p),
        ("ulFileSize", ctypes.c_ulong),
    ]


class MapiMessage(ctypes.Structure):
    _fields_ = [
        ("ulReserved", ctypes.c_ulong),
        ("lpszSubject", ctypes.c_char_p),
        ("lpszNoteText", ctypes.c_char_p),
        ("lpszMessageType", ctypes.c_char_p),
        ("lpszDateReceived", ctypes.c_char_p),
        ("lpszConversationID", ctypes.c_char_p),
        ("flFlags", ctypes.c_ulong),
        ("lpOriginator", ctypes.POINTER(MapiRecipDesc)),
        ("nRecipCount", ctypes.c_ulong),
        ("lpRecips", ctypes.POINTER(MapiRecipDesc)),
        ("nFileCount", ctypes.c_ulong),
        ("lpFiles", ctypes.POINTER(MapiFileDesc)),
    ]


class FoxmailService:
    def __init__(self):
        self.foxmail_path = None
        self.foxmail_data_path = None
        self.mapi32 = None
        self._manual_exe_path = None
        self._manual_storage_path = None
        self._config_loaded = False
        self._load_manual_config()
        self._detect_foxmail()
        self._init_mapi()

    def _load_manual_config(self):
        """从数据库加载手动配置的Foxmail路径"""
        try:
            from src.models.db import db, FoxmailConfig
            from flask import has_app_context
            if not has_app_context():
                return
            config = FoxmailConfig.query.filter_by(name='default').first()
            if config:
                self._manual_exe_path = config.foxmail_exe_path or None
                self._manual_storage_path = config.storage_path or None
            self._config_loaded = True
        except Exception as e:
            print(f'加载Foxmail手动配置失败: {e}')

    def _ensure_config_loaded(self):
        """确保手动配置已加载（在app context中且未加载过时）"""
        if not self._config_loaded:
            self._load_manual_config()
            self._detect_foxmail()

    def reload_config(self):
        """重新加载手动配置（用于配置更新后）"""
        self._config_loaded = False
        self._load_manual_config()
        self._detect_foxmail()

    def set_manual_paths(self, exe_path=None, storage_path=None):
        """设置手动配置路径（运行时）"""
        if exe_path:
            self._manual_exe_path = exe_path
        if storage_path:
            self._manual_storage_path = storage_path
        self._detect_foxmail()

    def _init_mapi(self):
        try:
            self.mapi32 = ctypes.WinDLL('mapi32.dll')
            self.mapi32.MAPISendMail.argtypes = [
                ctypes.c_ulong, ctypes.c_ulong, ctypes.POINTER(MapiMessage),
                ctypes.c_ulong, ctypes.c_ulong
            ]
            self.mapi32.MAPISendMail.restype = ctypes.c_long
        except Exception as e:
            print(f"MAPI初始化失败: {e}")
            self.mapi32 = None

    def _detect_foxmail(self):
        # 1. 优先使用手动配置的exe路径
        if self._manual_exe_path and os.path.exists(self._manual_exe_path):
            self.foxmail_path = self._manual_exe_path
        else:
            # 2. 自动检测常见路径
            paths = [
                r'D:\Foxmail 7.2\Foxmail.exe',
                r'D:\Foxmail\Foxmail.exe',
                r'C:\Program Files\Foxmail\Foxmail.exe',
                r'C:\Program Files (x86)\Foxmail\Foxmail.exe',
                r'C:\Foxmail\Foxmail.exe',
                r'E:\Foxmail 7.2\Foxmail.exe',
                r'E:\Foxmail\Foxmail.exe',
            ]
            for path in paths:
                if os.path.exists(path):
                    self.foxmail_path = path
                    break

            # 3. 通过注册表查找
            if not self.foxmail_path:
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                         r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall') as key:
                        for i in range(0, winreg.QueryInfoKey(key)[0]):
                            try:
                                subkey_name = winreg.EnumKey(key, i)
                                with winreg.OpenKey(key, subkey_name) as subkey:
                                    display_name = winreg.QueryValueEx(subkey, 'DisplayName')[0]
                                    if 'Foxmail' in display_name:
                                        install_location = winreg.QueryValueEx(subkey, 'InstallLocation')[0]
                                        exe_path = os.path.join(install_location, 'Foxmail.exe')
                                        if os.path.exists(exe_path):
                                            self.foxmail_path = exe_path
                                            break
                            except Exception:
                                continue
                except Exception:
                    pass

        self.foxmail_data_path = self._detect_data_path()

    def _detect_data_path(self):
        # 1. 优先使用手动配置的存储路径
        if self._manual_storage_path and os.path.exists(self._manual_storage_path):
            # 如果手动配置的路径本身就是账户目录（含Mail子目录），直接使用
            if self._is_account_dir(self._manual_storage_path):
                # 用户指定到了具体账户目录，使用其父目录作为data_path
                parent = os.path.dirname(self._manual_storage_path)
                return parent
            return self._manual_storage_path

        appdata = os.environ.get('APPDATA', '')
        localappdata = os.environ.get('LOCALAPPDATA', '')

        candidates = []
        if appdata:
            candidates.append(os.path.join(appdata, 'Foxmail'))
        if localappdata:
            candidates.append(os.path.join(localappdata, 'Foxmail'))
        if self.foxmail_path:
            foxmail_dir = os.path.dirname(self.foxmail_path)
            candidates.append(os.path.join(foxmail_dir, 'Data'))
            candidates.append(os.path.join(foxmail_dir, 'Storage'))
            candidates.append(os.path.join(foxmail_dir, 'mail'))

        for path in candidates:
            if os.path.exists(path):
                if self._is_foxmail_data_dir(path):
                    return path

        return None

    def _is_foxmail_data_dir(self, path):
        """判断是否为Foxmail数据目录（含Accounts/Storage/邮箱命名的子目录）"""
        if not os.path.exists(path):
            return False
        # 标准结构: .../Accounts/账号/...
        if os.path.exists(os.path.join(path, 'Accounts')):
            return True
        # 标准结构: .../Storage/账号/...
        if os.path.exists(os.path.join(path, 'Storage')):
            return True
        # 简易结构: .../账号/Mail/... (Storage直接含邮箱命名的目录)
        try:
            for item in os.listdir(path):
                item_path = os.path.join(path, item)
                if os.path.isdir(item_path) and self._is_account_dir(item_path):
                    return True
        except Exception:
            pass
        return False

    def _is_account_dir(self, path):
        """判断是否为Foxmail账户目录"""
        if not os.path.exists(path) or not os.path.isdir(path):
            return False
        # 包含Account.stg配置文件
        if os.path.exists(os.path.join(path, 'Account.stg')):
            return True
        # 包含Mail子目录
        if os.path.exists(os.path.join(path, 'Mail')):
            return True
        # 直接包含.box文件（某些Foxmail版本）
        try:
            for item in os.listdir(path):
                if item.endswith('.box') or item.endswith('.ind'):
                    return True
        except Exception:
            pass
        # 包含子目录且子目录内有.box文件（如INBOX/In.box、收件箱/收件箱.box等）
        try:
            for item in os.listdir(path):
                sub_path = os.path.join(path, item)
                if os.path.isdir(sub_path):
                    for sub_item in os.listdir(sub_path):
                        if sub_item.endswith('.box') or sub_item.endswith('.ind'):
                            return True
        except Exception:
            pass
        return False

    def is_installed(self):
        return self.foxmail_path is not None

    def get_accounts(self):
        self._ensure_config_loaded()
        accounts = []
        if not self.foxmail_data_path:
            # 手动配置路径可能直接指向账户目录
            if self._manual_storage_path and self._is_account_dir(self._manual_storage_path):
                email_addr = self._get_account_email(self._manual_storage_path, os.path.basename(self._manual_storage_path))
                accounts.append({
                    'id': os.path.basename(self._manual_storage_path),
                    'email': email_addr,
                    'path': self._manual_storage_path
                })
            return accounts

        accounts_dir = self._find_accounts_dir(self.foxmail_data_path)
        if not accounts_dir:
            return accounts

        for item in os.listdir(accounts_dir):
            item_path = os.path.join(accounts_dir, item)
            if os.path.isdir(item_path) and self._is_account_dir(item_path):
                email_addr = self._get_account_email(item_path, item)
                accounts.append({
                    'id': item,
                    'email': email_addr,
                    'path': item_path
                })
        return accounts

    def _find_accounts_dir(self, data_path):
        """查找账户目录的父目录（Accounts/Storage/直接存放账户的目录）"""
        # 1. .../Accounts
        accounts_path = os.path.join(data_path, 'Accounts')
        if os.path.exists(accounts_path) and os.path.isdir(accounts_path):
            return accounts_path
        # 2. .../Storage
        storage_path = os.path.join(data_path, 'Storage')
        if os.path.exists(storage_path) and os.path.isdir(storage_path):
            return storage_path
        # 3. data_path本身直接存放账户目录
        try:
            for item in os.listdir(data_path):
                item_path = os.path.join(data_path, item)
                if os.path.isdir(item_path) and self._is_account_dir(item_path):
                    return data_path
        except Exception:
            pass
        return None

    def _get_account_email(self, account_path, default_id):
        config_file = os.path.join(account_path, 'Account.stg')
        if os.path.exists(config_file):
            try:
                with open(config_file, 'rb') as f:
                    content = f.read()
                try:
                    text = content.decode('utf-8', errors='ignore')
                except:
                    text = content.decode('gbk', errors='ignore')

                import re
                email_match = re.search(r'email\s*=\s*([^\n\r]+)', text, re.IGNORECASE)
                if email_match:
                    return email_match.group(1).strip()
            except Exception:
                pass

        mail_dir = os.path.join(account_path, 'Mail')
        if os.path.exists(mail_dir):
            for folder in os.listdir(mail_dir):
                if '@' in folder:
                    return folder

        # 没有Mail子目录时，检查目录名是否像邮箱地址
        if '@' in default_id:
            return default_id

        return default_id

    def get_folders(self, account_path):
        folders = []
        # 优先检查 Mail 子目录
        mail_dir = os.path.join(account_path, 'Mail')
        search_dirs = []
        if os.path.exists(mail_dir):
            search_dirs.append(mail_dir)
        # 同时也检查账户目录本身
        search_dirs.append(account_path)

        folder_map = {
            'INBOX': '收件箱',
            '收件箱': '收件箱',
            'Sent': '已发送',
            '已发送': '已发送',
            '发送': '已发送',
            'Drafts': '草稿箱',
            '草稿箱': '草稿箱',
            'Trash': '回收站',
            '回收站': '回收站',
            'Junk': '垃圾邮件',
            '垃圾邮件': '垃圾邮件',
            'Outbox': '发件箱',
            '发件箱': '发件箱',
        }

        seen_names = set()
        for search_dir in search_dirs:
            for item in os.listdir(search_dir):
                item_path = os.path.join(search_dir, item)
                if not os.path.isdir(item_path):
                    continue
                # 跳过 Mail 目录本身（防止account_path下有Mail又被当作普通目录）
                if item == 'Mail' and search_dir == account_path:
                    continue
                if item in seen_names:
                    continue
                box_file = os.path.join(item_path, 'In.box')
                if not os.path.exists(box_file):
                    box_file = os.path.join(item_path, item + '.box')
                if os.path.exists(box_file) or os.path.exists(os.path.join(item_path, 'ind')):
                    display_name = folder_map.get(item, item)
                    folders.append({
                        'name': display_name,
                        'path': item_path,
                        'raw_name': item,
                        'is_inbox': item in ['INBOX', '收件箱'],
                        'is_sent': item in ['Sent', '已发送', '发送']
                    })
        return folders

    def read_emails_from_folder(self, folder_path, limit=100):
        emails = []
        box_file = None

        for fname in ['In.box', '收件箱.box', '已发送.box', 'Sent.box']:
            test_path = os.path.join(folder_path, fname)
            if os.path.exists(test_path):
                box_file = test_path
                break

        if not box_file:
            box_files = glob.glob(os.path.join(folder_path, '*.box'))
            if box_files:
                box_file = box_files[0]

        if not box_file or not os.path.exists(box_file):
            return emails

        try:
            eml_files = glob.glob(os.path.join(folder_path, '*.eml'))
            eml_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)

            for eml_file in eml_files[:limit]:
                parsed = self._parse_eml_file(eml_file)
                if parsed:
                    emails.append(parsed)

            if len(emails) < limit:
                remaining = limit - len(emails)
                box_emails = self._parse_box_file(box_file, remaining)
                existing_ids = set(e.get('message_id', '') for e in emails)
                for be in box_emails:
                    if be.get('message_id', '') not in existing_ids:
                        emails.append(be)

        except Exception as e:
            print(f'读取Foxmail文件夹失败: {e}')

        return emails

    def _parse_eml_file(self, eml_file):
        try:
            with open(eml_file, 'rb') as f:
                raw_content = f.read()
            return self._parse_raw_email(raw_content)
        except Exception as e:
            print(f'解析EML文件失败 {eml_file}: {e}')
            return None

    def _parse_box_file(self, box_file, limit=100):
        emails = []
        try:
            file_size = os.path.getsize(box_file)
            if file_size == 0:
                return emails

            with open(box_file, 'rb') as f:
                pos = 0
                count = 0

                while pos < file_size and count < limit:
                    f.seek(pos)
                    header_marker = f.read(5)
                    if header_marker == b'From ':
                        end_pos = self._find_next_from(f, pos)
                        f.seek(pos)
                        raw_data = f.read(end_pos - pos)
                        parsed = self._parse_raw_email(raw_data)
                        if parsed:
                            emails.append(parsed)
                            count += 1
                        pos = end_pos
                    else:
                        next_from = self._find_from_offset(f, pos + 1)
                        if next_from <= pos:
                            break
                        pos = next_from
        except Exception as e:
            print(f'解析BOX文件失败 {box_file}: {e}')

        return emails

    def _find_next_from(self, f, start_pos):
        chunk_size = 8192
        f.seek(start_pos)
        pos = start_pos
        leftover = b''

        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                return f.tell()

            data = leftover + chunk
            offset = data.find(b'\nFrom ', 1)
            if offset != -1:
                return start_pos + offset + 1

            leftover = data[-5:]
            pos += len(chunk)

    def _find_from_offset(self, f, start_pos):
        chunk_size = 8192
        f.seek(start_pos)
        pos = start_pos

        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                return pos

            idx = chunk.find(b'From ')
            if idx != -1:
                if idx == 0 or chunk[idx - 1:idx] == b'\n':
                    return pos + idx

            pos += len(chunk)
            if len(chunk) < chunk_size:
                break

        return pos

    def _parse_raw_email(self, raw_data):
        try:
            if raw_data.startswith(b'From '):
                first_line_end = raw_data.find(b'\n')
                if first_line_end != -1:
                    raw_data = raw_data[first_line_end + 1:]

            msg = email.message_from_bytes(raw_data)

            subject = ''
            if msg['Subject']:
                decoded = decode_header(msg['Subject'])
                parts = []
                for part, charset in decoded:
                    if isinstance(part, bytes):
                        if charset:
                            parts.append(part.decode(charset, errors='ignore'))
                        else:
                            parts.append(part.decode('utf-8', errors='ignore'))
                    else:
                        parts.append(str(part))
                subject = ''.join(parts)

            from_email = msg['From'] or ''
            to_email = msg['To'] or ''
            cc_email = msg['Cc'] or ''
            message_id = msg['Message-ID'] or ''

            date_str = msg['Date'] or ''
            received_at = None
            if date_str:
                try:
                    from email.utils import parsedate_to_datetime
                    received_at = parsedate_to_datetime(date_str)
                except Exception:
                    pass

            body = ''
            attachments = []

            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_disposition() == 'attachment':
                        filename = part.get_filename()
                        if filename:
                            decoded_name = decode_header(filename)
                            final_name = ''
                            for name_part, name_charset in decoded_name:
                                if isinstance(name_part, bytes):
                                    if name_charset:
                                        final_name += name_part.decode(name_charset, errors='ignore')
                                    else:
                                        final_name += name_part.decode('utf-8', errors='ignore')
                                else:
                                    final_name += str(name_part)
                            attachments.append(final_name)
                    elif part.get_content_type() == 'text/plain' and not part.get_content_disposition():
                        charset = part.get_content_charset() or 'utf-8'
                        payload = part.get_payload(decode=True)
                        if payload:
                            body += payload.decode(charset, errors='ignore')
            else:
                charset = msg.get_content_charset() or 'utf-8'
                payload = msg.get_payload(decode=True)
                if payload:
                    body = payload.decode(charset, errors='ignore')

            return {
                'message_id': message_id,
                'subject': subject,
                'from_email': from_email,
                'to_email': to_email,
                'cc_email': cc_email,
                'body': body,
                'attachments': attachments,
                'received_at': received_at,
                'raw_content': base64.b64encode(raw_data).decode('utf-8'),
                'source': 'foxmail'
            }
        except Exception as e:
            print(f'解析邮件失败: {e}')
            return None

    def send_email_via_mapi(self, to_email, subject, body, cc_email=None, attachments=None):
        if not self.mapi32:
            return False, 'MAPI不可用'

        try:
            recipients = []
            for addr in [to_email] + ([cc_email] if cc_email else []):
                if addr:
                    for email_addr in addr.split(','):
                        email_addr = email_addr.strip()
                        if email_addr:
                            recipients.append(MapiRecipDesc(
                                ulReserved=0, ulRecipClass=1,
                                lpszName=None,
                                lpszAddress=email_addr.encode('gbk'),
                                ulEIDSize=0, lpEntryID=None
                            ))

            files = []
            if attachments:
                for filepath in attachments:
                    if os.path.exists(filepath):
                        filename = os.path.basename(filepath)
                        files.append(MapiFileDesc(
                            ulReserved=0, ulFlags=0,
                            lpszPathName=filepath.encode('gbk'),
                            lpszFileName=filename.encode('gbk'),
                            lpFileData=None, ulFileSize=0
                        ))

            lp_recips = (MapiRecipDesc * len(recipients))(*recipients) if recipients else None
            lp_files = (MapiFileDesc * len(files))(*files) if files else None

            message = MapiMessage(
                ulReserved=0,
                lpszSubject=subject.encode('gbk'),
                lpszNoteText=body.encode('gbk'),
                lpszMessageType=None, lpszDateReceived=None,
                lpszConversationID=None, flFlags=0,
                lpOriginator=None,
                nRecipCount=len(recipients), lpRecips=lp_recips,
                nFileCount=len(files), lpFiles=lp_files
            )

            result = self.mapi32.MAPISendMail(
                0, 0, ctypes.byref(message),
                MAPI_DIALOG | MAPI_USE_DEFAULT, 0
            )

            if result == MAPI_E_SUCCESS:
                return True, '邮件编辑窗口已打开'
            elif result == MAPI_E_USER_ABORT:
                return False, '用户取消操作'
            else:
                return False, f'MAPI错误码: {result}'
        except Exception as e:
            return False, str(e)

    def open_foxmail(self):
        if self.foxmail_path:
            subprocess.Popen([self.foxmail_path])
            return True
        return False

    def get_diagnostic_info(self):
        self._ensure_config_loaded()
        info = {
            'foxmail_path': self.foxmail_path,
            'data_path': self.foxmail_data_path,
            'mapi_available': self.mapi32 is not None,
            'manual_exe_path': self._manual_exe_path,
            'manual_storage_path': self._manual_storage_path,
            'accounts': []
        }
        accounts = self.get_accounts()
        for acc in accounts:
            folders = self.get_folders(acc['path'])
            info['accounts'].append({
                'email': acc['email'],
                'id': acc['id'],
                'path': acc['path'],
                'folder_count': len(folders),
                'folders': [f['name'] for f in folders]
            })
        return info


foxmail_service = FoxmailService()