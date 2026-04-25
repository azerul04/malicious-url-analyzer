from urllib.parse import urlparse
import rules       # Brings in your local tests
import threat_api  # Brings in your internet tests

def run_full_scan(target_url, api_key):
    print(f"\n{'='*50}")
    print(f" STARTING SCAN: {target_url}")
    print(f"{'='*50}\n")

    # --- 1. PARSING THE URL ---
    parsed = urlparse(target_url)
    print("[+] 1. URL BREAKDOWN")
    print(f"    Protocol: {parsed.scheme}")
    print(f"    Domain:   {parsed.netloc}")
    print(f"    Path:     {parsed.path}\n")

    # --- 2. LEXICAL ANALYSIS (rules.py) ---
    print("[+] 2. LOCAL RULE CHECKS")
    is_long = rules.is_suspiciously_long(target_url)
    has_ip = rules.has_ip_address(parsed.netloc)
    print(f"    Suspiciously Long?   {is_long}")
    print(f"    Uses IP as Domain?   {has_ip}\n")

    # --- 3. REPUTATION ANALYSIS (threat_api.py) ---
    print("[+] 3. THREAT INTEL (VIRUSTOTAL)")
    threat_api.check_virustotal(target_url, api_key)
    print(f"\n{'='*50}\n")

# ==========================================
# RUNNING THE ENGINE
# ==========================================

# 1. Paste your real API key here again
MY_API_KEY = "2b254339d864f035ac3edba19c91ec2ebca7d08c305415fa8dda6bbf338a66ee"

# Create an infinite loop so the program keeps asking for URLs
while True:
    print("\n" + "*" * 50)
    # This line creates a prompt in the terminal waiting for you to type
    user_input = input("Paste a URL to scan (or type 'exit' to quit): ")
    
    # Give the user a way to close the program safely
    if user_input.lower() == 'exit':
        print("Shutting down analyzer. Goodbye!")
        break
        
    # Run the scan on whatever the user pasted!
    run_full_scan(user_input, MY_API_KEY)