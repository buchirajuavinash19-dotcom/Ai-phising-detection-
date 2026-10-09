import re
import math
import urllib.parse
from datetime import datetime
from typing import Dict, Any, List


class URLAnalyzer:
    """
    Rule-based + ML hybrid URL analyzer for phishing detection.
    In production, load a trained RandomForest/XGBoost model here.
    """

    SUSPICIOUS_TLDS = {'.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.click', '.link'}
    BRAND_KEYWORDS = [
        'paypal', 'apple', 'google', 'microsoft', 'amazon', 'facebook',
        'netflix', 'instagram', 'twitter', 'bank', 'secure', 'verify',
        'account', 'login', 'update', 'confirm', 'ebay', 'chase', 'wells',
    ]
    PHISHING_PATTERNS = [
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',   # IP address as host
        r'@',                                        # @ in URL
        r'(login|signin|verify|update|secure).*\.(?!com|net|org)',
        r'-{2,}',                                   # Multiple hyphens
    ]

    def __init__(self, model_path: str = None):
        self.model = None
        # In production: self.model = joblib.load(model_path)

    def extract_features(self, url: str) -> Dict[str, Any]:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc
        path = parsed.path

        return {
            "url_length": len(url),
            "domain_length": len(domain),
            "num_dots": url.count('.'),
            "num_hyphens": url.count('-'),
            "num_at": url.count('@'),
            "num_slashes": url.count('/'),
            "num_digits": sum(c.isdigit() for c in url),
            "has_https": url.startswith('https'),
            "has_ip": bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain)),
            "domain_has_brand": any(kw in domain.lower() for kw in self.BRAND_KEYWORDS),
            "path_has_brand": any(kw in path.lower() for kw in self.BRAND_KEYWORDS),
            "suspicious_tld": any(domain.endswith(tld) for tld in self.SUSPICIOUS_TLDS),
            "subdomain_count": len(domain.split('.')) - 2,
            "path_length": len(path),
            "has_suspicious_pattern": any(
                re.search(p, url, re.IGNORECASE) for p in self.PHISHING_PATTERNS
            ),
            "entropy": self._entropy(domain),
        }

    def _entropy(self, text: str) -> float:
        if not text:
            return 0
        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        return -sum((f / len(text)) * math.log2(f / len(text)) for f in freq.values())

    def _get_indicators(self, features: Dict, url: str) -> List[str]:
        indicators = []
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc

        if not features['has_https']:
            indicators.append("No HTTPS — unencrypted connection")
        if features['has_ip']:
            indicators.append("IP address used instead of domain name")
        if features['suspicious_tld']:
            tld = '.' + domain.split('.')[-1]
            indicators.append(f"Suspicious TLD detected ({tld})")
        if features['domain_has_brand'] and not features['has_https']:
            indicators.append("Brand name in domain without HTTPS")
        if features['path_has_brand'] and not features['domain_has_brand']:
            indicators.append("Brand keyword in path — possible impersonation")
        if features['url_length'] > 100:
            indicators.append(f"Unusually long URL ({features['url_length']} chars)")
        if features['num_hyphens'] > 3:
            indicators.append("Excessive hyphens in URL")
        if features['subdomain_count'] > 2:
            indicators.append(f"Deep subdomain nesting ({features['subdomain_count']} levels)")
        if features['entropy'] > 4.0:
            indicators.append("High domain entropy — possible random/generated domain")
        if features['num_at'] > 0:
            indicators.append("@ symbol in URL — redirects to different host")
        if features['has_suspicious_pattern']:
            indicators.append("Suspicious URL pattern detected")

        return indicators

    def _compute_risk_score(self, features: Dict) -> float:
        score = 0.0
        if not features['has_https']:       score += 20
        if features['has_ip']:              score += 25
        if features['suspicious_tld']:      score += 20
        if features['domain_has_brand']:    score += 15
        if features['path_has_brand'] and not features['domain_has_brand']: score += 10
        if features['url_length'] > 100:    score += 5
        if features['num_hyphens'] > 3:     score += 5
        if features['subdomain_count'] > 2: score += 10
        if features['entropy'] > 4.0:       score += 10
        if features['num_at'] > 0:          score += 20
        if features['has_suspicious_pattern']: score += 15
        return min(score, 100)

    def analyze(self, url: str) -> Dict[str, Any]:
        features = self.extract_features(url)
        risk_score = self._compute_risk_score(features)
        indicators = self._get_indicators(features, url)

        confidence = round(risk_score / 100, 2)
        is_phishing = risk_score >= 40

        if risk_score >= 70:
            risk_level = "CRITICAL"
        elif risk_score >= 50:
            risk_level = "HIGH"
        elif risk_score >= 30:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return {
            "is_phishing": is_phishing,
            "confidence": confidence,
            "risk_score": round(risk_score),
            "risk_level": risk_level,
            "indicators": indicators,
            "features": features,
        }
