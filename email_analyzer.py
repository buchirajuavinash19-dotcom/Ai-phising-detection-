import re
from typing import Dict, Any, List, Optional


class EmailAnalyzer:
    """
    NLP-based email phishing analyzer.
    In production: integrate fine-tuned BERT model for text classification.
    """

    URGENCY_KEYWORDS = [
        'urgent', 'immediately', 'action required', 'account suspended',
        'verify now', 'limited time', 'expires', 'warning', 'alert',
        'your account will be', 'failure to', 'click here now',
    ]
    CREDENTIAL_KEYWORDS = [
        'password', 'username', 'ssn', 'social security', 'credit card',
        'bank account', 'routing number', 'pin', 'cvv', 'confirm your',
        'enter your', 'provide your',
    ]
    SUSPICIOUS_DOMAINS = [
        'gmail.tk', 'yahoo.xyz', 'support-noreply', 'no-reply-secure',
        'paypal-secure', 'apple-id', 'microsoft-verify',
    ]
    PHISHING_PHRASES = [
        r'click (?:here|below) to (?:verify|confirm|update)',
        r'your (?:account|password) (?:has been|will be) (?:suspended|locked|compromised)',
        r'we detected (?:unusual|suspicious) activity',
        r'confirm your (?:identity|account|information)',
        r'dear (?:valued )?customer',
        r'you have won',
        r'prize|lottery|winner',
    ]

    def __init__(self, model_path: str = None):
        self.model = None
        # In production: load BERT classifier here

    def _check_sender_spoofing(self, sender: str) -> List[str]:
        issues = []
        domain = sender.split('@')[-1].lower() if '@' in sender else ''

        if any(sus in domain for sus in self.SUSPICIOUS_DOMAINS):
            issues.append(f"Suspicious sender domain: {domain}")
        if re.search(r'\d{4,}', domain):
            issues.append("Unusual numeric sequence in sender domain")
        if domain.count('.') > 3:
            issues.append("Overly complex sender domain structure")
        if re.search(r'(paypal|apple|google|amazon|microsoft|facebook)(?!\.com)', domain):
            issues.append("Possible brand impersonation in sender domain")

        return issues

    def _check_body_content(self, body: str) -> List[str]:
        issues = []
        body_lower = body.lower()

        urgency_count = sum(1 for kw in self.URGENCY_KEYWORDS if kw in body_lower)
        if urgency_count >= 2:
            issues.append(f"High urgency language ({urgency_count} urgency phrases)")

        credential_count = sum(1 for kw in self.CREDENTIAL_KEYWORDS if kw in body_lower)
        if credential_count >= 1:
            issues.append("Requesting sensitive credential information")

        for pattern in self.PHISHING_PHRASES:
            if re.search(pattern, body_lower):
                issues.append(f"Phishing phrase detected: matches pattern '{pattern[:40]}...'")
                break

        urls = re.findall(r'https?://\S+', body)
        if len(urls) > 5:
            issues.append(f"Excessive number of URLs in body ({len(urls)})")

        suspicious_urls = [u for u in urls if not u.startswith('https')]
        if suspicious_urls:
            issues.append(f"{len(suspicious_urls)} non-HTTPS link(s) in body")

        if re.search(r'dear (valued )?customer', body_lower):
            issues.append("Generic greeting — not personalized")

        return issues

    def _check_subject(self, subject: str) -> List[str]:
        issues = []
        sub_lower = subject.lower()

        urgency_count = sum(1 for kw in self.URGENCY_KEYWORDS if kw in sub_lower)
        if urgency_count >= 1:
            issues.append(f"Urgent/threatening subject line")

        if re.search(r'[A-Z]{5,}', subject):
            issues.append("Excessive CAPS in subject line")
        if subject.count('!') > 2:
            issues.append("Multiple exclamation marks in subject")
        if re.search(r'(free|prize|winner|lottery|congratulations)', sub_lower):
            issues.append("Reward/prize bait in subject line")

        return issues

    def _compute_risk_score(self, indicators: List[str]) -> float:
        base = len(indicators) * 12
        return min(base, 100)

    def analyze(
        self,
        subject: str,
        sender: str,
        body: str,
        headers: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        indicators = []
        indicators.extend(self._check_sender_spoofing(sender))
        indicators.extend(self._check_subject(subject))
        indicators.extend(self._check_body_content(body))

        risk_score = self._compute_risk_score(indicators)
        confidence = round(risk_score / 100, 2)
        is_phishing = risk_score >= 36

        if risk_score >= 70:
            risk_level = "CRITICAL"
        elif risk_score >= 50:
            risk_level = "HIGH"
        elif risk_score >= 25:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return {
            "is_phishing": is_phishing,
            "confidence": confidence,
            "risk_score": round(risk_score),
            "risk_level": risk_level,
            "indicators": indicators,
            "analysis": {
                "sender": sender,
                "subject": subject,
                "body_length": len(body),
            },
        }
