import re
import difflib 

def is_suspiciously_long(url):
    # Catch long paths hiding malicious domains
    return len(url) > 50

def has_ip_address(domain):
    # Catch raw IP addresses used instead of domain names
    ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    return True if ip_pattern.search(domain) else False

def has_suspicious_tld(domain):
    # High-risk extensions often used in phishing
    bad_tlds = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.ee', '.info']
    return any(domain.lower().endswith(tld) for tld in bad_tlds)

def is_impersonating_brand(domain):
    # The official domains we trust
    trusted_domains = ["maybank2u.com.my", "uum.edu.my", "google.com", "cimbclicks.com.my"]
    
    # The core brands we want to protect
    brands = ["maybank", "maybank2u", "uum", "google", "cimb"]
    
    domain_lower = domain.lower()
    
    # 1. If it's the exact trusted domain, it's safe.
    if any(trust in domain_lower for trust in trusted_domains):
        return False
        
    # 2. Check for EXACT spoofing (e.g., secure-maybank.com)
    if any(brand in domain_lower for brand in brands):
        return True
        
    # 3. TYPOSQUATTING CHECK (Fuzzy Logic)
    # Break the domain into pieces (ignoring dots and dashes)
    words_in_domain = re.split(r'[-.]', domain_lower)
    
    for word in words_in_domain:
        for brand in brands:
            # Calculates a similarity score from 0.0 to 1.0
            similarity = difflib.SequenceMatcher(None, word, brand).ratio()
            
            # If it's highly similar but not exact, it's a typo/phish!
            if similarity > 0.80 and similarity < 1.0:
                return True 
                
    return False