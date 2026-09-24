import requests
import json
from datetime import datetime


class ThreatIntelService:
    def __init__(self, config):
        self.config = config
        self.provider = config.provider
        self.api_key = config.get_api_key()
        self.api_base_url = config.api_base_url

    def query_ip(self, ip_address):
        if self.provider == 'threatbook':
            return self._query_threatbook_ip(ip_address)
        elif self.provider == 'virustotal':
            return self._query_virustotal_ip(ip_address)
        elif self.provider == 'abuseipdb':
            return self._query_abuseipdb_ip(ip_address)
        else:
            return {'success': False, 'message': f'不支持的情报源: {self.provider}'}

    def query_domain(self, domain):
        if self.provider == 'threatbook':
            return self._query_threatbook_domain(domain)
        elif self.provider == 'virustotal':
            return self._query_virustotal_domain(domain)
        elif self.provider == 'abuseipdb':
            return {'success': False, 'message': '该情报源不支持域名查询'}
        else:
            return {'success': False, 'message': f'不支持的情报源: {self.provider}'}

    def query_url(self, url):
        if self.provider == 'threatbook':
            return self._query_threatbook_url(url)
        elif self.provider == 'virustotal':
            return self._query_virustotal_url(url)
        elif self.provider == 'abuseipdb':
            return {'success': False, 'message': '该情报源不支持URL查询'}
        else:
            return {'success': False, 'message': f'不支持的情报源: {self.provider}'}

    def query_file(self, file_hash):
        if self.provider == 'threatbook':
            return self._query_threatbook_file(file_hash)
        elif self.provider == 'virustotal':
            return self._query_virustotal_file(file_hash)
        elif self.provider == 'abuseipdb':
            return {'success': False, 'message': '该情报源不支持文件哈希查询'}
        else:
            return {'success': False, 'message': f'不支持的情报源: {self.provider}'}

    def _query_threatbook_ip(self, ip):
        url = f"{self.api_base_url or 'https://api.threatbook.cn'}/v3/scene/ip_reputation"
        params = {
            'apikey': self.api_key,
            'resource': ip
        }
        try:
            resp = requests.get(url, params=params, timeout=15)
            data = resp.json()
            if data.get('response_code') == 0 or data.get('response_code') == '0':
                all_data = data.get('data', {})
                info = all_data.get(ip, {}) if isinstance(all_data, dict) else {}
                is_malicious = False
                threat_type = None
                confidence = 0.0
                
                malicious_keywords = [
                    'c2', 'c&c', 'phishing', 'phish', 'malware', 'botnet',
                    'spam', 'hijack', 'exploit', 'sinkhole', 'scan',
                    'brute', 'ransomware', 'trojan', 'worm', 'backdoor',
                    '钓鱼', '恶意', '僵尸', '木马', '病毒', '勒索', '爆破', '扫描'
                ]
                
                judgments = info.get('judgments', [])
                tags = info.get('tags', [])
                severity = info.get('severity', 'info')
                
                malicious_judgments = []
                for j in judgments:
                    j_lower = j.lower()
                    if any(kw in j_lower for kw in malicious_keywords):
                        malicious_judgments.append(j)
                
                if malicious_judgments:
                    is_malicious = True
                    threat_type = ', '.join(malicious_judgments[:3])
                    confidence = 0.9
                elif severity in ['high', 'critical', 'high-risk', 'malicious']:
                    is_malicious = True
                    threat_type = severity
                    confidence = 0.6
                
                basic = info.get('basic', {})
                location = basic.get('location', {}) if basic else {}
                country = location.get('country', '-') if location else '-'
                province = location.get('province', '-') if location else '-'
                city = location.get('city', '-') if location else '-'
                carrier = basic.get('carrier', '-') if basic else '-'
                
                asn = info.get('asn', {})
                asn_number = asn.get('number', '-') if asn else '-'
                asn_info = asn.get('info', '-') if asn else '-'
                asn_rank = asn.get('rank', '-') if asn else '-'
                
                return {
                    'success': True,
                    'is_malicious': is_malicious,
                    'threat_type': threat_type,
                    'confidence': confidence,
                    'raw_data': data,
                    'provider': 'threatbook',
                    'details': {
                        'ip': ip,
                        'country': country,
                        'province': province,
                        'city': city,
                        'carrier': carrier,
                        'asn_number': asn_number,
                        'asn_info': asn_info,
                        'asn_rank': asn_rank,
                        'judgments': judgments,
                        'tags': tags,
                        'severity': severity
                    }
                }
            else:
                return {'success': False, 'message': data.get('verbose_msg', '查询失败')}
        except Exception as e:
            return {'success': False, 'message': str(e)}

    def _query_threatbook_domain(self, domain):
        url = f"{self.api_base_url or 'https://api.threatbook.cn'}/v3/scene/domain"
        params = {
            'apikey': self.api_key,
            'resource': domain
        }
        try:
            resp = requests.get(url, params=params, timeout=15)
            data = resp.json()
            if data.get('response_code') == 0 or data.get('response_code') == '0':
                all_data = data.get('data', {})
                info = all_data.get(domain, {}) if isinstance(all_data, dict) else all_data
                is_malicious = False
                threat_type = None
                confidence = 0.0
                
                malicious_keywords = [
                    'c2', 'c&c', 'phishing', 'phish', 'malware', 'botnet',
                    'spam', 'hijack', 'exploit', 'sinkhole', 'scan',
                    'brute', 'ransomware', 'trojan', 'worm', 'backdoor',
                    '钓鱼', '恶意', '僵尸', '木马', '病毒', '勒索', '爆破', '扫描'
                ]
                
                judgments = info.get('judgments', [])
                tags = info.get('tags', [])
                severity = info.get('severity', 'info')
                
                malicious_judgments = []
                for j in judgments:
                    j_lower = j.lower()
                    if any(kw in j_lower for kw in malicious_keywords):
                        malicious_judgments.append(j)
                
                if malicious_judgments:
                    is_malicious = True
                    threat_type = ', '.join(malicious_judgments[:3])
                    confidence = 0.9
                elif severity in ['high', 'critical', 'high-risk', 'malicious']:
                    is_malicious = True
                    threat_type = severity
                    confidence = 0.6
                
                basic = info.get('basic', {})
                return {
                    'success': True,
                    'is_malicious': is_malicious,
                    'threat_type': threat_type,
                    'confidence': confidence,
                    'raw_data': data,
                    'provider': 'threatbook',
                    'details': {
                        'domain': domain,
                        'judgments': judgments,
                        'tags': tags,
                        'severity': severity,
                        'registrar': basic.get('registrar', '-') if basic else '-',
                        'create_time': basic.get('create_time', '-') if basic else '-',
                        'country': basic.get('location', {}).get('country', '-') if basic and basic.get('location') else '-'
                    }
                }
            else:
                return {'success': False, 'message': data.get('verbose_msg', '查询失败')}
        except Exception as e:
            return {'success': False, 'message': str(e)}

    def _query_threatbook_url(self, url):
        api_url = f"{self.api_base_url or 'https://api.threatbook.cn'}/v3/url/query"
        params = {
            'apikey': self.api_key,
            'resource': url
        }
        try:
            resp = requests.get(api_url, params=params, timeout=15)
            data = resp.json()
            if data.get('response_code') == 0 or data.get('response_code') == '0':
                info = data.get('data', {})
                is_malicious = False
                threat_type = None
                confidence = 0.0
                
                judgments = info.get('judgments', [])
                if judgments:
                    is_malicious = True
                    threat_type = ', '.join(judgments[:3])
                    confidence = 0.85
                
                return {
                    'success': True,
                    'is_malicious': is_malicious,
                    'threat_type': threat_type,
                    'confidence': confidence,
                    'raw_data': data,
                    'details': {
                        'url': url,
                        'judgments': judgments,
                        'tags': info.get('tags', []),
                        'final_url': info.get('final_url', '-')
                    }
                }
            else:
                return {'success': False, 'message': data.get('verbose_msg', '查询失败')}
        except Exception as e:
            return {'success': False, 'message': str(e)}

    def _query_threatbook_file(self, file_hash):
        url = f"{self.api_base_url or 'https://api.threatbook.cn'}/v3/file/query"
        params = {
            'apikey': self.api_key,
            'resource': file_hash
        }
        try:
            resp = requests.get(url, params=params, timeout=15)
            data = resp.json()
            if data.get('response_code') == 0 or data.get('response_code') == '0':
                info = data.get('data', {})
                is_malicious = False
                threat_type = None
                confidence = 0.0
                
                multi_engines = info.get('multi_engine', {})
                detected = [k for k, v in multi_engines.items() if v.get('detected')]
                if detected:
                    is_malicious = True
                    threat_type = f'{len(detected)}个引擎检出'
                    confidence = min(len(detected) / 10, 0.99)
                
                malware_type = info.get('malware_type', [])
                if malware_type:
                    is_malicious = True
                    threat_type = ', '.join(malware_type[:3])
                    confidence = 0.9
                
                return {
                    'success': True,
                    'is_malicious': is_malicious,
                    'threat_type': threat_type,
                    'confidence': confidence,
                    'raw_data': data,
                    'details': {
                        'hash': file_hash,
                        'malware_type': malware_type,
                        'detected_engines': len(detected),
                        'total_engines': len(multi_engines),
                        'file_name': info.get('file_name', '-')
                    }
                }
            else:
                return {'success': False, 'message': data.get('verbose_msg', '查询失败')}
        except Exception as e:
            return {'success': False, 'message': str(e)}

    def _query_virustotal_ip(self, ip):
        url = f"{self.api_base_url or 'https://www.virustotal.com/api/v3'}/ip_addresses/{ip}"
        headers = {'x-apikey': self.api_key}
        try:
            resp = requests.get(url, headers=headers, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                attr = data.get('data', {}).get('attributes', {})
                stats = attr.get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0) + stats.get('suspicious', 0)
                total = sum(stats.values()) if stats else 0
                
                is_malicious = malicious > 0
                threat_type = None
                confidence = 0.0
                
                if is_malicious:
                    results = attr.get('last_analysis_results', {})
                    types = []
                    for engine, result in results.items():
                        if result.get('category') in ['malicious', 'suspicious'] and result.get('result'):
                            types.append(result['result'])
                    if types:
                        threat_type = ', '.join(list(set(types))[:3])
                    confidence = min(malicious / max(total, 1), 0.99)
                
                return {
                    'success': True,
                    'is_malicious': is_malicious,
                    'threat_type': threat_type,
                    'confidence': confidence,
                    'raw_data': data,
                    'details': {
                        'ip': ip,
                        'country': attr.get('country', '-'),
                        'as_owner': attr.get('as_owner', '-'),
                        'malicious_engines': malicious,
                        'total_engines': total,
                        'reputation': attr.get('reputation', 0)
                    }
                }
            else:
                return {'success': False, 'message': f'HTTP {resp.status_code}'}
        except Exception as e:
            return {'success': False, 'message': str(e)}

    def _query_virustotal_domain(self, domain):
        url = f"{self.api_base_url or 'https://www.virustotal.com/api/v3'}/domains/{domain}"
        headers = {'x-apikey': self.api_key}
        try:
            resp = requests.get(url, headers=headers, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                attr = data.get('data', {}).get('attributes', {})
                stats = attr.get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0) + stats.get('suspicious', 0)
                total = sum(stats.values()) if stats else 0
                
                is_malicious = malicious > 0
                threat_type = None
                confidence = 0.0
                
                if is_malicious:
                    results = attr.get('last_analysis_results', {})
                    types = []
                    for engine, result in results.items():
                        if result.get('category') in ['malicious', 'suspicious'] and result.get('result'):
                            types.append(result['result'])
                    if types:
                        threat_type = ', '.join(list(set(types))[:3])
                    confidence = min(malicious / max(total, 1), 0.99)
                
                return {
                    'success': True,
                    'is_malicious': is_malicious,
                    'threat_type': threat_type,
                    'confidence': confidence,
                    'raw_data': data,
                    'details': {
                        'domain': domain,
                        'malicious_engines': malicious,
                        'total_engines': total,
                        'reputation': attr.get('reputation', 0),
                        'registrar': attr.get('registrar', '-')
                    }
                }
            else:
                return {'success': False, 'message': f'HTTP {resp.status_code}'}
        except Exception as e:
            return {'success': False, 'message': str(e)}

    def _query_virustotal_url(self, url):
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
        api_url = f"{self.api_base_url or 'https://www.virustotal.com/api/v3'}/urls/{url_id}"
        headers = {'x-apikey': self.api_key}
        try:
            resp = requests.get(api_url, headers=headers, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                attr = data.get('data', {}).get('attributes', {})
                stats = attr.get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0) + stats.get('suspicious', 0)
                total = sum(stats.values()) if stats else 0
                
                is_malicious = malicious > 0
                threat_type = None
                confidence = 0.0
                
                if is_malicious:
                    results = attr.get('last_analysis_results', {})
                    types = []
                    for engine, result in results.items():
                        if result.get('category') in ['malicious', 'suspicious'] and result.get('result'):
                            types.append(result['result'])
                    if types:
                        threat_type = ', '.join(list(set(types))[:3])
                    confidence = min(malicious / max(total, 1), 0.99)
                
                return {
                    'success': True,
                    'is_malicious': is_malicious,
                    'threat_type': threat_type,
                    'confidence': confidence,
                    'raw_data': data,
                    'details': {
                        'url': url,
                        'malicious_engines': malicious,
                        'total_engines': total,
                        'reputation': attr.get('reputation', 0),
                        'final_url': attr.get('last_final_url', '-')
                    }
                }
            else:
                return {'success': False, 'message': f'HTTP {resp.status_code}'}
        except Exception as e:
            return {'success': False, 'message': str(e)}

    def _query_virustotal_file(self, file_hash):
        url = f"{self.api_base_url or 'https://www.virustotal.com/api/v3'}/files/{file_hash}"
        headers = {'x-apikey': self.api_key}
        try:
            resp = requests.get(url, headers=headers, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                attr = data.get('data', {}).get('attributes', {})
                stats = attr.get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0) + stats.get('suspicious', 0)
                total = sum(stats.values()) if stats else 0
                
                is_malicious = malicious > 0
                threat_type = None
                confidence = 0.0
                
                if is_malicious:
                    popular = attr.get('popular_threat_classification', {})
                    threat_type = popular.get('suggested_threat_label') or f'{malicious}个引擎检出'
                    confidence = min(malicious / max(total, 1), 0.99)
                
                return {
                    'success': True,
                    'is_malicious': is_malicious,
                    'threat_type': threat_type,
                    'confidence': confidence,
                    'raw_data': data,
                    'details': {
                        'hash': file_hash,
                        'malicious_engines': malicious,
                        'total_engines': total,
                        'file_name': attr.get('meaningful_name', '-'),
                        'file_size': attr.get('size', 0)
                    }
                }
            else:
                return {'success': False, 'message': f'HTTP {resp.status_code}'}
        except Exception as e:
            return {'success': False, 'message': str(e)}

    def _query_abuseipdb_ip(self, ip):
        url = f"{self.api_base_url or 'https://api.abuseipdb.com/api/v2'}/check"
        headers = {'Key': self.api_key, 'Accept': 'application/json'}
        params = {'ipAddress': ip, 'maxAgeInDays': 90}
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                info = data.get('data', {})
                abuse_score = info.get('abuseConfidenceScore', 0)
                total_reports = info.get('totalReports', 0)
                
                is_malicious = abuse_score >= 25
                threat_type = None
                confidence = abuse_score / 100.0
                
                if is_malicious:
                    categories = info.get('reports', [])
                    cat_types = set()
                    for rep in categories[:10]:
                        for cat in rep.get('categories', []):
                            cat_types.add(str(cat))
                    if cat_types:
                        threat_type = f'滥用IP ({len(cat_types)}类)'
                
                return {
                    'success': True,
                    'is_malicious': is_malicious,
                    'threat_type': threat_type,
                    'confidence': confidence,
                    'raw_data': data,
                    'details': {
                        'ip': ip,
                        'abuse_score': abuse_score,
                        'total_reports': total_reports,
                        'country': info.get('countryCode', '-'),
                        'isp': info.get('isp', '-'),
                        'last_reported': info.get('lastReportedAt', '-')
                    }
                }
            else:
                return {'success': False, 'message': f'HTTP {resp.status_code}'}
        except Exception as e:
            return {'success': False, 'message': str(e)}