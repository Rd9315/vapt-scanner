# 🔐 Advanced VAPT Scanner (Python)

A mini automated vulnerability scanner inspired by tools like Burp Suite and OWASP ZAP.

---

## 🚀 Features
- **Port Scanning** (Multithreaded)
- **Smart Crawling** of websites
- **Form Detection** (Login, search, contact forms)
- **SQL Injection Testing** (URL + Forms)
- **XSS Testing** (URL + Forms)
- **Directory Brute-force** (admin, login, dashboard, api)
- **Header Security Checks** (CSP, X-Frame-Options)
- **Report Generation** (TXT / HTML)

---

## 🛠️ Installation
1. Clone the repo:
```bash
git clone https://github.com/Rd9315/vapt-scanner.git
cd vapt-scanner

2.Install dependencies:
pip install -r requirements.txt

▶️ Usage
python scanner.py
python scanner.py
Enter target URL when prompted.
Scanner will crawl, detect forms, test SQLi/XSS, check headers, scan ports, and generate a report.
📄 Sample Output
[OPEN] 80
[OPEN] 443
[FORM] http://target.com/login.php
[SQLi] http://target.com/login.php
[FORM XSS] http://target.com/search.php
[DIR] http://target.com/admin

✅ Scan Complete → report.txt

## ⚠️ Disclaimer

This tool is for educational purposes only.
Do not use on unauthorized websites.
Use only in controlled environments or with proper permission (labs, bug bounty programs).
