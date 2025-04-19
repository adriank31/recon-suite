# modules/webs/active_web_attacks.py

import requests
import os
from urllib.parse import urljoin, urlencode
from utils.logger import log
from utils.helpers import ensure_dir

# Common redirect parameters
REDIRECT_PARAMS = ["redirect", "redir", "url", "next", "target", "r"]
REDIRECT_PAYLOAD = "https://evil.com"
HOST_HEADER_PAYLOAD = "evil-injected.com"
CORS_ORIGIN = "https://evil.com"


# --- CORS Check ---
def check_cors(url):
    try:
        res = requests.options(url, headers={
            "Origin": CORS_ORIGIN,
            "Access-Control-Request-Method": "GET"
        }, timeout=10)

        acao = res.headers.get("Access-Control-Allow-Origin")
        acac = res.headers.get("Access-Control-Allow-Credentials")

        if acao == "*":
            return ("Wildcard CORS", url)
        elif acao == CORS_ORIGIN:
            return ("Reflected CORS", url)
        elif acao and acac == "true":
            return ("Credentialed CORS", url)
    except Exception as e:
        log(f"[CORS] Error checking {url}: {e}", level="ERROR")
    return None


# --- Open Redirect Check ---
def check_open_redirect(base_url):
    found = []
    for param in REDIRECT_PARAMS:
        try:
            payload = {param: REDIRECT_PAYLOAD}
            full_url = base_url + ("?" if "?" not in base_url else "&") + urlencode(payload)
            res = requests.get(full_url, allow_redirects=False, timeout=10)
            loc = res.headers.get("Location", "")
            if REDIRECT_PAYLOAD in loc:
                found.append((param, full_url))
        except Exception as e:
            log(f"[REDIRECT] Error probing {base_url} param {param}: {e}", level="ERROR")
    return found


# --- Host Header Injection ---
def check_host_header_injection(url):
    try:
        res = requests.get(url, headers={"Host": HOST_HEADER_PAYLOAD}, timeout=10)
        if HOST_HEADER_PAYLOAD in res.text:
            return ("Possible Reflection", url)
        if res.status_code in [301, 302, 307, 308]:
            loc = res.headers.get("Location", "")
            if HOST_HEADER_PAYLOAD in loc:
                return ("Redirect Location Injection", url)
    except Exception as e:
        log(f"[HOST HEADER] Error: {e}", level="ERROR")
    return None


# --- Run Full Suite ---
def run(domain):
    input_file = f"reports/{domain}_web_probe.txt"
    output_file = f"reports/{domain}_web_attacks.txt"
    ensure_dir("reports")

    if not os.path.exists(input_file):
        log(f"[ACTIVE WEB ATTACKS] Web probe file not found: {input_file}", level="ERROR")
        return

    with open(input_file, "r") as f:
        urls = [line.strip() for line in f if line.strip()]

    cors_results = []
    redirect_results = []
    host_results = []

    log("[ACTIVE WEB ATTACKS] Starting security checks on web endpoints...")

    for url in urls:
        # Check CORS
        cors_check = check_cors(url)
        if cors_check:
            cors_results.append(cors_check)
            log(f"[CORS] {cors_check[0]} misconfiguration found at {cors_check[1]}")

        # Check Open Redirects
        redirect_checks = check_open_redirect(url)
        for param, link in redirect_checks:
            redirect_results.append((param, link))
            log(f"[REDIRECT] Open redirect via `{param}` param at {link}")

        # Check Host Header Injection
        host_injection = check_host_header_injection(url)
        if host_injection:
            host_results.append(host_injection)
            log(f"[HOST HEADER] {host_injection[0]} at {host_injection[1]}")

    # Save Results
    try:
        with open(output_file, "w") as f:
            if cors_results:
                f.write("# CORS Misconfigurations\n")
                for tag, link in cors_results:
                    f.write(f"[{tag}] {link}\n")
                f.write("\n")

            if redirect_results:
                f.write("# Open Redirects\n")
                for param, link in redirect_results:
                    f.write(f"[param={param}] {link}\n")
                f.write("\n")

            if host_results:
                f.write("# Host Header Injection\n")
                for tag, link in host_results:
                    f.write(f"[{tag}] {link}\n")

        log(f"[ACTIVE WEB ATTACKS] Results saved to {output_file}")
    except Exception as e:
        log(f"[ACTIVE WEB ATTACKS] Failed to save output: {e}", level="ERROR")
