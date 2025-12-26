import re
from urllib.parse import urlparse
import socket
import math

def is_ip(domain):
    try:
        if socket.inet_aton(domain):
            return 1
    except:
        return 0
    return 0

def entropy(string):
    "Calculates the Shannon entropy of a string"
    prob = [ float(string.count(c)) / len(string) for c in dict.fromkeys(list(string)) ]
    entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])
    return entropy

class FeatureExtractor:
    def __init__(self):
        self.suspicious_keywords = [
            'login', 'secure', 'account', 'update', 'verify', 'signin', 'banking', 
            'confirm', 'service', 'paypal', 'ebay', 'amazon', 'apple', 'google', 
            'microsoft', 'facebook', 'netflix', 'wallet', 'crypto', 'payment'
        ]
        self.shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                                   r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                                   r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                                   r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.cn|lnkd\.in|db\.tt|" \
                                   r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                                   r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                                   r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                                   r"tr\.im|link\.zip\.net"

    def extract_features(self, url):
        features = {}
        
        # Ensure URL has a scheme for parsing
        if not url.startswith(('http://', 'https://')):
            parse_url = 'http://' + url
        else:
            parse_url = url
            
        parsed = urlparse(parse_url)
        domain = parsed.netloc
        path = parsed.path
        
        # 1. URLLength
        features['URLLength'] = len(url)
        
        # 2. DomainLength
        features['DomainLength'] = len(domain)
        
        # 3. IsDomainIP
        features['IsDomainIP'] = is_ip(domain)
        
        # 4. TLDLength
        try:
            tld = domain.split('.')[-1]
            features['TLDLength'] = len(tld)
        except:
            features['TLDLength'] = 0
            
        # 5. NoOfSubDomain
        features['NoOfSubDomain'] = domain.count('.')
        
        # 6. NoOfLettersInURL
        features['NoOfLettersInURL'] = sum(c.isalpha() for c in url)
        
        # 7. LetterRatioInURL
        features['LetterRatioInURL'] = features['NoOfLettersInURL'] / len(url) if len(url) > 0 else 0
        
        # 8. NoOfDegitsInURL
        features['NoOfDegitsInURL'] = sum(c.isdigit() for c in url)
        
        # 9. DegitRatioInURL
        features['DegitRatioInURL'] = features['NoOfDegitsInURL'] / len(url) if len(url) > 0 else 0
        
        # 10. NoOfEqualsInURL
        features['NoOfEqualsInURL'] = url.count('=')
        
        # 11. NoOfQMarkInURL
        features['NoOfQMarkInURL'] = url.count('?')
        
        # 12. NoOfAmpersandInURL
        features['NoOfAmpersandInURL'] = url.count('&')
        
        # 13. NoOfOtherSpecialCharsInURL
        features['NoOfOtherSpecialCharsInURL'] = sum(not c.isalnum() for c in url)
        
        # 14. SpacialCharRatioInURL
        features['SpacialCharRatioInURL'] = features['NoOfOtherSpecialCharsInURL'] / len(url) if len(url) > 0 else 0
        
        # 15. IsHTTPS
        features['IsHTTPS'] = 1 if parse_url.startswith('https://') else 0
        
        # --- NEW FEATURES ---
        
        # 16. SuspiciousKeywords
        lower_url = url.lower()
        features['SuspiciousKeywords'] = sum(1 for keyword in self.suspicious_keywords if keyword in lower_url)
        
        # 17. Entropy
        features['Entropy'] = entropy(url)
        
        # 18. IsShortened
        features['IsShortened'] = 1 if re.search(self.shortening_services, url, flags=re.I) else 0
        
        # 19. HasAtSymbol
        features['HasAtSymbol'] = 1 if '@' in url else 0

        return features

    def get_feature_names(self):
        return [
            'URLLength', 'DomainLength', 'IsDomainIP', 'TLDLength', 'NoOfSubDomain',
            'NoOfLettersInURL', 'LetterRatioInURL', 'NoOfDegitsInURL', 'DegitRatioInURL',
            'NoOfEqualsInURL', 'NoOfQMarkInURL', 'NoOfAmpersandInURL', 'NoOfOtherSpecialCharsInURL',
            'SpacialCharRatioInURL', 'IsHTTPS', 
            'SuspiciousKeywords', 'Entropy', 'IsShortened', 'HasAtSymbol'
        ]
