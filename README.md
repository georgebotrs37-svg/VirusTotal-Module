# ServerSpy-SOC v1.1  
### The SOC Analyst's Swiss Army Knife 🔍🛡️

## 📖 Overview
ServerSpy-SOC v1.1 is a Recon & Threat Intelligence tool designed for SOC Analysts.  
It combines DNS, WHOIS, HTTP Headers, SSL/TLS Certificates inspection, and integrates with **VirusTotal API** for Hash Lookup and URL Scan.  
Results are saved in JSON format and a quick summary is displayed in the terminal with color formatting.

---

## 🚀 Features
- **DNS Lookup**: Queries A, AAAA, MX, NS, TXT records.  
- **WHOIS Lookup**: Retrieves domain registration details with date handling.  
- **HTTP Headers Analysis**: Attempts HTTPS first, then HTTP.  
- **SSL/TLS Certificate Info**: Extracts certificate details.  
- **VirusTotal Integration**:
  - Hash Lookup (SHA256) for suspicious files.
  - URL Scan for suspicious links.
- **Output**:
  - JSON report with safe filename.
  - Color-coded summary in terminal.

---

## 📦 Installation
Make sure you have Python 3.10+ installed, then run:

```bash
pip install requests aiohttp dnspython python-whois virustotal-python
Optional modules for extended features:
pip install python-nmap shodan
🖥️ Usage
Basic Scan
python main.py example.com
With VirusTotal (Hash Lookup)
python main.py example.com --vt YOUR_API_KEY --file suspicious.exe
With VirusTotal (URL Scan)
python main.py example.com --vt YOUR_API_KEY --url http://badurl.com
Output
• 	JSON report file:
report_example.com_YYYYMMDD_HHMMSS.json
	Quick summary in terminal.
📂 Example Output
{
  "scan_metadata": {
    "target": "example.com",
    "timestamp": "2026-03-09T13:06:00",
    "tool_version": "1.1"
  },
  "dns": {
    "A": ["93.184.216.34"],
    "MX": [],
    "NS": ["ns1.example.com"]
  },
  "whois": {
    "registrar": "Example Registrar, Inc.",
    "creation_date": "1995-08-13"
  },
  "http_headers": {
    "url_accessed": "https://example.com",
    "status_code": 200,
    "headers": {
      "Server": "ECS (nyb/1D2E)",
      "Content-Type": "text/html"
    }
  },
  "ssl_info": {
    "subject": {"CN": "example.com"},
    "issuer": {"CN": "Example CA"}
  },
  "vt_url_report": {
    "attributes": {
      "last_analysis_stats": {"malicious": 0, "suspicious": 0}
    }
  }
}


🛡️ Notes
• 	A VirusTotal API Key is required for Hash Lookup and URL Scan.
• 	This tool is intended to assist in Incident Response and Threat Hunting, not to replace SIEM platforms.
• 	Reports can be easily integrated into Splunk, QRadar, or other SIEM solutions.

 Roadmap
• 	Add Port Scanning Module (python-nmap).
• 	Integrate Shodan API for passive reconnaissance.
• 	Generate PDF/Markdown reports for incident documentation.

---

This README is polished and GitHub-ready.  
Do you want me to also create a **short badge section** (like Python version, license, build status) at the top so it looks more professional on GitHub?
