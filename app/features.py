import re
import urllib.parse
from typing import List

def extract_features(url: str) -> List[float]:

    features = []

    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        full_url = url
    except Exception:
        return [0.0] * 15

    # Feature 1: URL total length
    # Phishing URLs tend to be very long
    features.append(len(full_url))

    # Feature 2: Domain length
    features.append(len(domain))

    # Feature 3: Number of dots
    # evil.paypal.secure.login.com has many dots
    features.append(full_url.count('.'))

    # Feature 4: Has @ symbol
    # http://google.com@evil.com tricks users
    features.append(1 if '@' in full_url else 0)

    # Feature 5: Has IP address instead of domain name
    # http://192.168.1.1/login is suspicious
    ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
    features.append(1 if ip_pattern.search(domain) else 0)

    # Feature 6: Uses HTTPS (secure) or HTTP (insecure)
    features.append(1 if parsed.scheme == 'https' else 0)

    # Feature 7: Number of hyphens in domain
    # paypal-login-secure.com is suspicious
    features.append(domain.count('-'))

    # Feature 8: Number of subdomains
    # paypal.com.evil.com has 4 parts
    parts = domain.split('.')
    features.append(len(parts))

    # Feature 9: Contains suspicious words
    suspicious_words = ['login', 'secure', 'account', 'update', 'banking',
                        'verify', 'confirm', 'password', 'paypal', 'signin',
                        'free', 'lucky', 'winner', 'claim', 'urgent']
    found = sum(1 for word in suspicious_words if word in full_url.lower())
    features.append(found)

    # Feature 10: Number of special characters
    special_chars = re.findall(r'[%=?&#+]', full_url)
    features.append(len(special_chars))

    # Feature 11: Path depth (how many slashes)
    features.append(path.count('/'))

    # Feature 12: Has a port number
    # http://evil.com:8080/login is suspicious
    features.append(1 if parsed.port else 0)

    # Feature 13: Domain contains numbers
    # paypa1.com (with number 1 instead of letter l)
    features.append(1 if re.search(r'\d', domain) else 0)

    # Feature 14: Is a URL shortener
    # bit.ly and tinyurl hide the real destination
    shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd']
    features.append(1 if any(s in domain for s in shorteners) else 0)

    # Feature 15: Query string length
    features.append(len(parsed.query))

    return features


def get_feature_names() -> List[str]:
    return [
        'url_length', 'domain_length', 'dot_count', 'has_at_symbol',
        'has_ip_address', 'uses_https', 'hyphen_count', 'subdomain_count',
        'suspicious_word_count', 'special_char_count', 'path_depth',
        'has_port', 'domain_has_numbers', 'is_url_shortener', 'query_length'
    ]
