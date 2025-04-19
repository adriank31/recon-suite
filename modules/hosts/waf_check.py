# modules/hosts/waf_check.py

import requests
from utils.logger import log

def run(domain):
    log(f"[WAF CHECK] Detecting Web Application Firewall for: {domain}")

    test_url = f"http://{domain}"
    headers = {
        "User-Agent": "WAFScanner/1.0",
        "X-Original-URL": "/admin",
        "X-Custom-IP-Authorization": "127.0.0.1",
    }

    waf_signatures = {
        "Cloudflare": ["cloudflare", "cf-ray"],
        "Akamai": ["akamai", "akamai-bot"],
        "AWS WAF": ["aws", "x-amzn-requestid"],
        "Imperva": ["incapsula"],
        "F5 BigIP": ["bigipserver"],
        "Sucuri": ["sucuri"]
    }

    try:
        res = requests.get(test_url, headers=headers, timeout=10)
        detected = []

        # Check headers
        for key, value in res.headers.items():
            lower = f"{key}: {value}".lower()
            for waf, sigs in waf_signatures.items():
                for sig in sigs:
                    if sig in lower:
                        detected.append(waf)

        # Check response body as well
        for waf, sigs in waf_signatures.items():
            for sig in sigs:
                if sig in res.text.lower():
                    detected.append(waf)

        detected = list(set(detected))
        output_path = f"reports/{domain}_waf_check.txt"
        with open(output_path, "w") as f:
            if detected:
                for waf in detected:
                    f.write(f"Detected: {waf}\n")
                log(f"[WAF CHECK] WAF detected: {', '.join(detected)}")
            else:
                f.write("No WAF detected.\n")
                log("[WAF CHECK] No WAF signatures detected.")

        log(f"[WAF CHECK] Results saved to {output_path}")

    except Exception as e:
        log(f"[WAF CHECK] Error detecting WAF for {domain}: {e}")
