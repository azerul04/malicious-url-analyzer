import requests
import base64

# Tool 1: Check the specific full URL
def check_url_reputation(target_url, api_key):
    # Encode the URL for VirusTotal
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    headers = {"x-apikey": api_key}
    
    # We return the whole response object so app.py can check the status code
    return requests.get(api_url, headers=headers)

# Tool 2: Check the Domain (The Fallback)
def check_domain_reputation(domain, api_key):
    api_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    
    headers = {"x-apikey": api_key}
    
    response = requests.get(api_url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        # Digging for malicious flags specifically for the domain
        votes = data['data']['attributes']['last_analysis_stats']['malicious']
        return votes
    return None # Return None if the domain itself is also unknown