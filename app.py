import streamlit as st
import os
from dotenv import load_dotenv
from urllib.parse import urlparse
import rules
import threat_api

# 1. Load the vault
load_dotenv() 
MY_API_KEY = os.getenv("VT_API_KEY")

# --- WEB PAGE DESIGN ---
st.set_page_config(page_title="URL Threat Analyzer", page_icon="🛡️")

st.title("🛡️ Malicious URL Analyzer")
st.write("Enter a suspicious link below to scan it against local rules and the VirusTotal database.")

# --- THE ELITE RISK CALCULATION ENGINE ---
def calculate_risk(is_long, has_ip, has_bad_tld, is_spoofing, vt_votes, is_new):
    score = 0
    if is_long: score += 15
    if has_ip: score += 35
    if has_bad_tld: score += 25
    if is_spoofing: score += 75 
    if vt_votes > 0: score += 45
    if is_new and (is_long or has_bad_tld or is_spoofing): score += 15 
    return min(score, 100)

target_url = st.text_input("Target URL:", placeholder="https://example.com/login")

if st.button("Scan URL"):
    if target_url:
        st.divider() 
        final_vt_votes = 0
        is_new_url = False
        
        # 1. URL Breakdown
        st.subheader("1. URL Breakdown")
        parsed = urlparse(target_url)
        st.code(f"Protocol: {parsed.scheme}\nDomain: {parsed.netloc}\nPath: {parsed.path}")
        
        # 2. Lexical Analysis
        st.subheader("2. Lexical Analysis")
        is_long = rules.is_suspiciously_long(target_url)
        has_ip = rules.has_ip_address(parsed.netloc)
        has_bad_tld = rules.has_suspicious_tld(parsed.netloc)
        is_spoofing = rules.is_impersonating_brand(parsed.netloc) 
        
        st.write(f"**Suspiciously Long:** {'🚨 Yes' if is_long else '✅ No'}")
        st.write(f"**Uses IP as Domain:** {'🚨 Yes' if has_ip else '✅ No'}")
        st.write(f"**Suspicious Extension (.xyz, etc):** {'🚨 Yes' if has_bad_tld else '✅ No'}")
        st.write(f"**Brand Impersonation:** {'🚨 Yes' if is_spoofing else '✅ No'}")
        
        # 3. Reputation Analysis
        st.subheader("3. Threat Intelligence (VirusTotal)")
        with st.spinner("Analyzing reputation..."):
            url_resp = threat_api.check_url_reputation(target_url, MY_API_KEY)
            
            if url_resp.status_code == 200:
                data = url_resp.json()
                final_vt_votes = data['data']['attributes']['last_analysis_stats']['malicious']
                if final_vt_votes > 0:
                    st.error(f"🚨 DANGER: {final_vt_votes} vendors flagged this link!")
                else:
                    st.success("✅ This specific link is verified safe.")
            
            elif url_resp.status_code == 404:
                is_new_url = True
                st.warning("❓ This specific link is NEW/UNVERIFIED in the database.")
                
                domain_votes = threat_api.check_domain_reputation(parsed.netloc, MY_API_KEY)
                if domain_votes is not None:
                    final_vt_votes = domain_votes
                    if domain_votes > 0:
                        st.error(f"❌ WARNING: The domain itself is flagged!")
                    else:
                        
                        st.warning(f"⚠️ Domain ({parsed.netloc}) has 0 vendor flags, but remains unverified by historical data.")
                else:
                    st.error("Domain unknown. High risk of fresh phishing.")

        # 4. Final Verdict
        st.divider()
        st.subheader("4. Final Security Verdict")
        
        # Passing all variables to the updated engine
        risk_pct = calculate_risk(is_long, has_ip, has_bad_tld, is_spoofing, final_vt_votes, is_new_url)
        
        if risk_pct >= 70:
            st.error(f"🔴 CRITICAL RISK: {risk_pct}% - High probability of phishing!")
        elif risk_pct >= 30:
            st.warning(f"🟡 MODERATE RISK: {risk_pct}% - Proceed with extreme caution.")
        else:
            st.success(f"🟢 LOW RISK: {risk_pct}% - No immediate threats detected.")
            
        st.progress(risk_pct / 100)
    else:
        st.warning("Please enter a URL first!")
