# modules/webs/js_analyzer.py

import requests
import re
import os
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from utils.logger import log
from utils.helpers import ensure_dir

SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Heroku API Key": r"[hH]eroku[a-zA-Z0-9]{32,}",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "Stripe Live Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
    "Generic Bearer Token": r"Bearer\s+[a-zA-Z0-9\-_\.]+",
    "Authorization Header": r"Authorization\s*[:=]\s*[\"']?[Bb]earer\s+[a-zA-Z0-9\-_\.]+",
    "Basic Auth Token": r"Basic\s+[a-zA-Z0-9=:\-]+",
    "Twilio SID": r"AC[a-zA-Z0-9]{32}",
    "SendGrid API Key": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
    "Facebook OAuth Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
    "Auth0 Client ID": r"[0-9a-zA-Z]{7,}\.[0-9a-zA-Z]{7,}",
    "JWT Token": r"eyJ[A-Za-z0-9=\-_]+\.[A-Za-z0-9=\-_]+\.[A-Za-z0-9=\-_]+"
}

DOM_XSS_SINKS = [
    "document.write", "document.writeln", "document.innerHTML", "element.innerHTML",
    "outerHTML", "window.location", "location.href", "location.assign",
    "eval", "setTimeout", "setInterval", "Function", "innerHTML", "open"
]

DOM_XSS_SOURCES = [
    "document.URL", "document.documentURI", "document.URLUnencoded",
    "document.baseURI", "location.href", "location.search", "location.hash",
    "window.name", "referrer"
]

UNTRUSTED_CDNS = ["cdn.jsdelivr.net", "unpkg.com", "raw.githubusercontent.com"]

JS_EXTENSIONS = [".js"]
JS_MIME = ["application/javascript", "text/javascript"]

API_ENDPOINT_REGEX = r"[\"'](\/api\/[a-zA-Z0-9_\/-]+)[\"']"


def extract_js_urls(html, base_url):
    soup = BeautifulSoup(html, 'html.parser')
    script_urls = []
    for script in soup.find_all("script"):
        src = script.get("src")
        if src:
            full_url = urljoin(base_url, src)
            script_urls.append(full_url)
    return script_urls


def extract_secrets(js_text):
    secrets = []
    for label, regex in SECRET_PATTERNS.items():
        matches = re.findall(regex, js_text)
        for match in matches:
            secrets.append((label, match))
    return secrets


def find_dom_xss(js_text):
    findings = []
    for sink in DOM_XSS_SINKS:
        if sink in js_text:
            for source in DOM_XSS_SOURCES:
                pattern = f"{sink}\\s*\\(.*{source}.*\\)"
                if re.search(pattern, js_text):
                    findings.append((sink, source))
    return findings


def extract_debug_info(js_text):
    debug_flags = []
    patterns = [
        r"debug\s*[:=]\s*true",
        r"test\s*[:=]\s*true",
        r"ENV\s*[:=]\s*[\"']dev[\"']",
        r"(username|user|email)\s*[:=]\s*[\"'][^\"']{3,}[\"']",
        r"(password|pass|passwd|pwd)\s*[:=]\s*[\"'][^\"']{3,}[\"']"
    ]
    for p in patterns:
        matches = re.findall(p, js_text, re.IGNORECASE)
        debug_flags.extend(matches)
    return debug_flags


def detect_unsafe_functions(js_text):
    unsafe = []
    patterns = [
        r"new Function\\(", r"eval\\(", r"window\\['eval'\\]",
        r"setTimeout\\([^,]*,[^)]+\\)", r"setInterval\\([^,]*,[^)]+\\)"
    ]
    for pat in patterns:
        if re.search(pat, js_text):
            unsafe.append(pat)
    return unsafe


def extract_api_endpoints(js_text):
    return re.findall(API_ENDPOINT_REGEX, js_text)


def is_js_response(url):
    try:
        head = requests.head(url, timeout=10, allow_redirects=True)
        content_type = head.headers.get("Content-Type", "")
        return any(x in content_type for x in JS_MIME) or any(url.lower().endswith(ext) for ext in JS_EXTENSIONS)
    except:
        return False


def flag_untrusted_js(js_links):
    flagged = []
    for js in js_links:
        if any(cdn in js for cdn in UNTRUSTED_CDNS):
            flagged.append(js)
    return flagged


def run(domain):
    log(f"[JS ANALYZER] Ultra-deep JavaScript analysis for: {domain}")
    input_file = f"reports/{domain}_web_probe.txt"
    output_file = f"reports/{domain}_js_analysis.txt"
    ensure_dir("reports")

    if not os.path.exists(input_file):
        log(f"[JS ANALYZER] Web probe results missing: {input_file}")
        return

    try:
        with open(input_file, "r") as f:
            urls = [line.strip() for line in f if line.strip()]

        all_js_links = set()
        found_secrets = []
        dom_xss_issues = []
        debug_hints = []
        unsafe_calls = []
        api_discovered = []

        for url in urls:
            try:
                log(f"[JS ANALYZER] Fetching HTML from {url}")
                res = requests.get(url, timeout=10)
                if res.status_code != 200:
                    continue
                js_links = extract_js_urls(res.text, url)
                for js_url in js_links:
                    if is_js_response(js_url):
                        all_js_links.add(js_url)
            except Exception as e:
                log(f"[JS ANALYZER] Error analyzing HTML {url}: {e}", level="WARN")

        for js_url in sorted(all_js_links):
            try:
                log(f"[JS ANALYZER] Downloading JS: {js_url}")
                js_res = requests.get(js_url, timeout=10)
                if js_res.status_code != 200:
                    continue
                js_text = js_res.text

                found_secrets.extend([(js_url, *s) for s in extract_secrets(js_text)])
                dom_xss_issues.extend([(js_url, sink, src) for sink, src in find_dom_xss(js_text)])
                debug_hints.extend([(js_url, d) for d in extract_debug_info(js_text)])
                unsafe_calls.extend([(js_url, u) for u in detect_unsafe_functions(js_text)])
                api_discovered.extend([(js_url, ep) for ep in extract_api_endpoints(js_text)])

            except Exception as e:
                log(f"[JS ANALYZER] Error analyzing JS {js_url}: {e}", level="WARN")

        flagged_cdn = flag_untrusted_js(all_js_links)

        with open(output_file, "w") as f:
            f.write("# Discovered JavaScript Files\n")
            for js in sorted(all_js_links):
                f.write(js + "\n")

            f.write("\n# Discovered Secrets\n")
            for js_url, label, secret in found_secrets:
                f.write(f"{label} in {js_url}: {secret}\n")

            f.write("\n# Potential DOM XSS Issues\n")
            for js_url, sink, src in dom_xss_issues:
                f.write(f"{sink} sinks {src} in {js_url}\n")

            f.write("\n# Debug Flags and Hardcoded Credentials\n")
            for js_url, debug in debug_hints:
                f.write(f"Found debug info in {js_url}: {debug}\n")

            f.write("\n# Unsafe Function Calls\n")
            for js_url, call in unsafe_calls:
                f.write(f"{call} used in {js_url}\n")

            f.write("\n# API Endpoints Discovered\n")
            for js_url, api in api_discovered:
                f.write(f"{api} in {js_url}\n")

            f.write("\n# Untrusted JS CDN Links\n")
            for js in flagged_cdn:
                f.write(f"{js}\n")

        log(f"[JS ANALYZER] JavaScript analysis complete. Results saved to {output_file}")

    except Exception as e:
        log(f"[JS ANALYZER] General exception: {e}", level="ERROR")
