
import argparse
import socket
import ssl
import re
import requests
import json
import hashlib
import sys
from virustotal_python import Virustotal
import whois
import dns.resolver
from datetime import datetime

# -----------------------------
# الألوان لتنسيق المخرجات في التيرمينال
# -----------------------------
class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def log_status(msg, status="info"):
    if status == "info":
        print(f"[*] {msg}")
    elif status == "success":
        print(f"{Colors.GREEN}[+] {msg}{Colors.ENDC}")
    elif status == "error":
        print(f"{Colors.RED}[!] {msg}{Colors.ENDC}")
    elif status == "warn":
        print(f"{Colors.YELLOW}[!] {msg}{Colors.ENDC}")

# -----------------------------
# Utilities
# -----------------------------
def safe_filename(value: str) -> str:
    """تحويل اسم النطاق لاسم ملف صالح للنظام"""
    safe = re.sub(r'[<>:"/\\|?*\s]+', "_", value)
    safe = re.sub(r"_+", "_", safe).strip("_.")
    return safe or "output"

# -----------------------------
# DNS Resolution (تحسين: فحص كل سجل على حدة)
# -----------------------------
def dns_lookup(target):
    results = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT"]
    log_status(f"Starting DNS Lookup for {target}...", "info")
    
    for r_type in record_types:
        try:
            answers = dns.resolver.resolve(target, r_type)
            results[r_type] = [str(r) for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            results[r_type] = []
        except Exception as e:
            results[r_type] = f"Error: {str(e)}"
    return results

# -----------------------------
# WHOIS Lookup
# -----------------------------
def whois_lookup(target):
    log_status(f"Starting WHOIS Lookup...", "info")
    try:
        w = whois.whois(target)
        # تحويل الكائن لقاموس مع معالجة التواريخ (لأن JSON لا يدعم datetime مباشرة)
        return json.loads(json.dumps(w, default=str))
    except Exception as e:
        return {"error": str(e)}

# -----------------------------
# HTTP Headers Analysis (تحسين: محاولة HTTPS ثم HTTP)
# -----------------------------
def http_headers(target):
    log_status(f"Analyzing HTTP Headers...", "info")
    protocols = ["https://", "http://"]
    for proto in protocols:
        try:
            url = f"{proto}{target}"
            resp = requests.get(url, timeout=10, verify=True)
            return {
                "url_accessed": url,
                "status_code": resp.status_code,
                "headers": dict(resp.headers)
            }
        except requests.exceptions.RequestException:
            continue
    return {"error": "Target unreachable on HTTP/HTTPS"}

# -----------------------------
# SSL/TLS Certificate Info
# -----------------------------
def ssl_info(target):
    log_status(f"Fetching SSL Certificate info...", "info")
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((target, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception as e:
        return {"error": str(e)}

# -----------------------------
# VirusTotal Module
# -----------------------------
class VirusTotalModule:
    def __init__(self, api_key):
        self.vtotal = Virustotal(API_KEY=api_key)

    def hash_lookup(self, file_path):
        log_status(f"Calculating hash and checking VirusTotal...", "info")
        try:
            with open(file_path, "rb") as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            resp = self.vtotal.request(f"files/{file_hash}")
            return resp.data
        except Exception as e:
            return {"error": str(e)}

    def url_scan(self, url):
        log_status(f"Scanning URL on VirusTotal...", "info")
        try:
            resp = self.vtotal.request("urls", data={"url": url}, method="POST")
            return resp.data
        except Exception as e:
            return {"error": str(e)}

# -----------------------------
# Main Function
# -----------------------------
def main():
    parser = argparse.ArgumentParser(
        description=f"{Colors.BOLD}ServerSpy-SOC v1.1 - The SOC Analyst's Swiss Army Knife{Colors.ENDC}",
        epilog="Example: python main.py google.com --vt YOUR_API_KEY"
    )
    parser.add_argument("target", help="Target domain or IP address")
    parser.add_argument("--vt", help="VirusTotal API Key (Optional)", default=None)
    parser.add_argument("--file", help="Local file path for hash lookup", default=None)
    parser.add_argument("--url", help="Specific URL to scan via VT", default=None)
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
        
    args = parser.parse_args()
    target = args.target
    
    results = {
        "scan_metadata": {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "tool_version": "1.1"
        }
    }

    # تنفيذ المهام الأساسية
    results["dns"] = dns_lookup(target)
    results["whois"] = whois_lookup(target)
    results["http_headers"] = http_headers(target)
    results["ssl_info"] = ssl_info(target)

    # مهام VirusTotal اختيارية
    if args.vt:
        vt = VirusTotalModule(api_key=args.vt)
        if args.file:
            results["vt_file_report"] = vt.hash_lookup(args.file)
        if args.url:
            results["vt_url_report"] = vt.url_scan(args.url)
    elif args.file or args.url:
        log_status("File/URL provided but VirusTotal API key is missing!", "warn")

    # حفظ النتائج
    filename = safe_filename(f"report_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    try:
        with open(filename, "w", encoding='utf-8') as f:
            json.dump(results, f, indent=4, ensure_ascii=False)
        log_status(f"Full report saved to: {filename}", "success")
    except Exception as e:
        log_status(f"Failed to save report: {e}", "error")

    # عرض ملخص سريع في التيرمينال
    print(f"\n{Colors.BOLD}{'='*40}")
    print(f" SCAN SUMMARY FOR: {target}")
    print(f"{'='*40}{Colors.ENDC}")
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(0)