# XSSPwn - Reflected XSS Detection & Simulation Tool

**Author:** GH0STH4CKER  
**Version:** 1.1  
**License:** For educational and authorized security testing only.

---
![Screenshot 2025-07-07 112313 - Copy_LI](https://github.com/user-attachments/assets/c621aee6-9c56-4e11-9f8d-d314cf91a0e3)


## 🔍 About

**XSSPwn** is a command-line tool designed to:
- Check if a target URL is vulnerable to **reflected XSS**.
- Simulate **real-world XSS attack payloads** like cookie theft and keylogging.
- Generate **ready-to-use malicious URLs** with embedded JavaScript payloads.

It uses a third-party API to safely analyze the target for XSS vulnerabilities.

---

## ⚠️ Disclaimer

> This tool is intended **ONLY** for educational purposes and authorized penetration testing.  
> **Do not** use it on websites you do not own or have explicit permission to test.

---

## 💡 Features

- ✅ Detects reflected XSS using `check4xss.vercel.app` API (also mine)
- ✅ Simulates cookie stealing, keylogging, and alert box attacks
- ✅ Generates encoded malicious URLs for testing
- ✅ Colorful, user-friendly terminal output
- ✅ Works with webhook services like: [webhook.site](https://webhook.site) [webhook-test.com](https://webhook-test.com/) [webhook.cook](https://webhook.cool/)

---

## 🧰 Requirements

- Python 3.x
- `requests` and `colorama` Python libraries

Install them via pip:

```bash
pip install requests colorama
