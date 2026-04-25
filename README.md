# 🛡️ Malicious URL Threat Analyzer

An intelligent URL analysis tool designed to detect phishing and malicious links using local lexical heuristics and global threat intelligence.

## 🚀 Features
* **Lexical Analysis:** Detects typosquatting (brand impersonation), suspicious TLDs (.xyz, .tk), and IP-based domains.
* **Fuzzy Logic Matching:** Uses `difflib` to catch subtle misspellings of protected brands (e.g., "maybanck").
* **Global Threat Intel:** Integrated with the **VirusTotal API v3** for real-time reputation scoring.
* **Risk Engine:** Calculates a weighted risk percentage (0-100%) based on multiple security factors.

## 🛠️ Technology Stack
* **Language:** Python 3.x
* **Web Framework:** Streamlit
* **APIs:** VirusTotal API
* **Libraries:** `requests`, `python-dotenv`, `urllib`, `difflib`

## 📦 Installation & Setup
1. Clone the repository.
2. Install dependencies: `pip install -r requirements.txt`
3. Create a `.env` file based on `.env.example`.
4. Add your VirusTotal API key to `.env`.
5. Run the app: `streamlit run app.py`
