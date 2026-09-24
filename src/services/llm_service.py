import requests
import json
import re


class LLMService:
    def __init__(self, llm_config):
        self.config = llm_config
        self.api_base = llm_config.api_base_url.rstrip('/')

    def test_connection(self):
        try:
            headers = {
                'Authorization': f'Bearer {self.config.get_api_key()}',
                'Content-Type': 'application/json'
            }
            data = {
                'model': self.config.model_name,
                'messages': [{'role': 'user', 'content': 'Hello'}],
                'max_tokens': 5
            }
            resp = requests.post(
                f'{self.api_base}/chat/completions',
                headers=headers,
                json=data,
                timeout=30
            )
            if resp.status_code == 200:
                return {'success': True, 'message': '大模型连接正常'}
            else:
                return {'success': False, 'message': f'API返回错误: {resp.status_code}, {resp.text}'}
        except Exception as e:
            return {'success': False, 'message': f'连接失败: {str(e)}'}

    def analyze_email(self, email_record):
        matched_signatures = self._find_matching_signatures(email_record)
        
        if matched_signatures:
            for sig in matched_signatures:
                if sig['confidence'] >= 0.9:
                    print(f"[LLM] Signature match found: type={sig['signature_type']}, value={sig['signature_value']}, expected_is_phishing={sig['expected_is_phishing']}")
                    return {
                        'is_phishing': sig['expected_is_phishing'],
                        'confidence': sig['confidence'],
                        'risk_level': sig['expected_risk_level'] or 'medium',
                        'phishing_type': sig['expected_phishing_type'] or '其他',
                        'indicators': f"匹配特征签名: {sig['signature_type']}={sig['signature_value']}",
                        'analysis_report': f"该邮件匹配已验证的特征签名（{sig['signature_type']}: {sig['signature_value']}），直接使用人工纠错后的判定结果。"
                    }
        
        prompt = self._build_analysis_prompt(email_record, matched_signatures)

        try:
            headers = {
                'Authorization': f'Bearer {self.config.get_api_key()}',
                'Content-Type': 'application/json'
            }
            data = {
                'model': self.config.model_name,
                'messages': [
                    {'role': 'system', 'content': '你是一个专业的网络安全分析专家，擅长识别钓鱼邮件。请用JSON格式返回分析结果。'},
                    {'role': 'user', 'content': prompt}
                ],
                'temperature': 0.3,
                'max_tokens': 2000
            }
            resp = requests.post(
                f'{self.api_base}/chat/completions',
                headers=headers,
                json=data,
                timeout=60
            )
            resp.raise_for_status()
            result = resp.json()
            content = result['choices'][0]['message']['content']
            
            self._update_signature_match_count(matched_signatures)
            
            return self._parse_analysis_result(content)
        except Exception as e:
            return {
                'is_phishing': False,
                'confidence': 0.0,
                'risk_level': 'unknown',
                'analysis_report': f'分析失败: {str(e)}',
                'phishing_type': None,
                'indicators': None
            }
    
    def _find_matching_signatures(self, email_record):
        from src.models.db import EmailSignature
        
        signatures = []
        
        from_email = email_record.from_email or ''
        subject = email_record.subject or ''
        body = email_record.body or ''
        
        active_signatures = EmailSignature.query.filter_by(is_active=True).all()
        
        for sig in active_signatures:
            matched = False
            
            if sig.signature_type == 'domain':
                if '@' in from_email and from_email.split('@')[-1] == sig.signature_value:
                    matched = True
            elif sig.signature_type == 'from_email':
                if from_email.strip() == sig.signature_value:
                    matched = True
            elif sig.signature_type == 'subject_pattern':
                if len(subject) > 5 and subject.strip().lower().startswith(sig.signature_value[:50]):
                    matched = True
            elif sig.signature_type == 'body_hash':
                body_hash = str(hash(body[:500]))[:32] if len(body) > 20 else ''
                if body_hash == sig.signature_value:
                    matched = True
            
            if matched:
                signatures.append(sig.to_dict())
        
        return signatures
    
    def _update_signature_match_count(self, signatures):
        from src.models.db import db, EmailSignature
        
        for sig_dict in signatures:
            sig = EmailSignature.query.get(sig_dict['id'])
            if sig:
                sig.match_count += 1
        db.session.commit()

    def _build_analysis_prompt(self, email_record, matched_signatures=None):
        body_preview = (email_record.body or '')[:3000]
        attachments = email_record.attachments or '无'
        
        signature_info = ''
        if matched_signatures:
            sig_lines = []
            for sig in matched_signatures:
                result_text = '钓鱼邮件' if sig['expected_is_phishing'] else '正常邮件'
                sig_lines.append(f"- 类型: {sig['signature_type']}, 值: {sig['signature_value']}, 历史判定: {result_text}")
            signature_info = f'''

【历史纠错参考（特征签名匹配）】
以下特征在历史纠错中已被标记，请作为分析参考：
{chr(10).join(sig_lines)}
'''

        return f'''请对以下邮件进行钓鱼邮件深度分析，以JSON格式返回结果。

邮件信息：
发件人: {email_record.from_email}
主题: {email_record.subject}
收件人: {email_record.to_email or '未知'}
附件: {attachments}

邮件正文：
{body_preview}
{signature_info}

重要说明：
- 所有邮件均由内部员工转发至本系统，发件人地址为转发人（内部员工）的邮箱地址，不是邮件的原始发件人。
- 因此不要对"发件人地址"本身进行分析（例如：不要分析"发件人地址为xxx@nsfocus.net，与签名中身份一致，域名nsfocus.net为真实公司域名"等内容）。
- 请从邮件正文中识别真正的原始发件人信息（通常在转发邮件的"发件人"、"From"字段中），并针对原始发件人的域名、身份进行可信度分析。
- 分析维度应聚焦于：邮件正文中是否存在钓鱼特征，而非转发人地址的真实性。

请从以下维度进行分析（跳过转发人地址分析）：
1. 原始发件人是否可疑（从邮件正文中提取原始发件人信息，分析其域名是否仿冒知名域名、是否与声称身份一致）
2. 邮件主题是否具有诱导性（紧急、恐吓、利益诱惑等）
3. 邮件正文是否包含钓鱼特征（索要敏感信息、诱导点击链接、反向心理操纵语句）
4. 链接的安全性（是否重定向、伪装、仿冒）
5. 附件的安全性（是否包含可执行文件、宏脚本、加密特征）
6. 风险等级评估

请严格按照以下JSON格式返回，analysis_report需要包含详细的判定依据，不要包含对转发人地址的分析：
{{
    "is_phishing": true/false,
    "confidence": 0.0-1.0,
    "risk_level": "high/medium/low",
    "phishing_type": "仿冒登录/附件病毒/冒充领导/链接诱导/其他/非钓鱼",
    "indicators": "发现的钓鱼特征列表，用分号分隔",
    "analysis_report": "详细的研判依据分析报告，格式如下：\\n原始发件人分析：从邮件正文中提取的原始发件人为xxx@xxx.com，域名xxx.com为/非真实域名...\\n邮件主题分析：邮件主题虽涉及'XX'等安全敏感词，但正文内容规范，未使用'紧急'等诱导性语言...\\n附件分析：附件为...\\n链接分析：链接指向...\\n综上，最终判定为钓鱼邮件/非钓鱼邮件"
}}'''

    def _parse_analysis_result(self, content):
        try:
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                return {
                    'is_phishing': data.get('is_phishing', False),
                    'confidence': float(data.get('confidence', 0)),
                    'risk_level': data.get('risk_level', 'unknown'),
                    'phishing_type': data.get('phishing_type'),
                    'indicators': data.get('indicators'),
                    'analysis_report': data.get('analysis_report', content)
                }
        except Exception:
            pass

        is_phishing = '是钓鱼邮件' in content or '钓鱼' in content
        confidence = 0.8 if is_phishing else 0.2
        risk_level = 'high' if is_phishing else 'low'

        return {
            'is_phishing': is_phishing,
            'confidence': confidence,
            'risk_level': risk_level,
            'phishing_type': '其他' if is_phishing else '非钓鱼',
            'indicators': None,
            'analysis_report': content
        }