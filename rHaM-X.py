import requests
import socket
import ssl
from urllib.parse import urlparse

# بررسی IP و DNS
def get_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"[🧠] IP address: {ip}")
    except Exception as e:
        print(f"[!] DNS lookup failed: {e}")

# بررسی SSL
def check_ssl(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert['subject'])
                print(f"[✓] SSL certificate valid for: {subject.get('commonName', 'Unknown')}")
    except Exception as e:
        print(f"[!] SSL check failed: {e}")

# بررسی هدرهای امنیتی
def check_headers(url):
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        security_headers = [
            'Content-Security-Policy',
            'X-Frame-Options',
            'Strict-Transport-Security',
            'X-Content-Type-Options'
        ]
        print("\n🔐 Security Headers:")
        for h in security_headers:
            if h in headers:
                print(f"[✓] {h} present.")
            else:
                print(f"[!] {h} missing.")
    except Exception as e:
        print(f"[!] Header check failed: {e}")

# بررسی فرم‌های ناامن
def check_insecure_forms(url):
    try:
        response = requests.get(url, timeout=5)
        if "<form" in response.text and "http://" in response.text:
            print("[!] Insecure form detected (uses HTTP).")
        else:
            print("[✓] No insecure forms found.")
    except Exception as e:
        print(f"[!] Form check failed: {e}")

def scan_website(url):
    print(f"\n🔍 Scanning: {url}")
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    if domain.startswith("www."):
        domain = domain[4:]

    get_ip(domain)
    check_ssl(domain)
    check_headers(url)
    check_insecure_forms(url)
    print("\n✅ Silent scan complete. —R")

if __name__ == "__main__":
    target_url = input("🔎 Enter website URL (e.g. https://example.com): ")
    scan_website(target_url)
