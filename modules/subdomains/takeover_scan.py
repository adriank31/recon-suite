# modules/subdomains/takeover_scan.py

import subprocess
from utils.logger import log
import os

def run(domain):
    log(f"[TAKEOVER SCAN] Checking for subdomain takeover vulnerabilities for: {domain}")

    input_file = f"reports/{domain}_subdomains.txt"
    output_file = f"reports/{domain}_takeover_scan.txt"
    found_takeovers = []

    if not os.path.exists(input_file):
        log(f"[TAKEOVER SCAN] Required subdomain file not found: {input_file}")
        return

    try:
        with open(input_file, "r") as f:
            subdomains = [line.strip() for line in f if line.strip()]

        log(f"[TAKEOVER SCAN] Loaded {len(subdomains)} subdomains for checking.")

        fingerprints = {
            "Amazon S3": "NoSuchBucket",
            "GitHub Pages": "There isn't a GitHub Pages site here.",
            "Heroku": "No such app",
            "Bitbucket": "Repository not found",
            "Shopify": "Sorry, this shop is currently unavailable.",
            "Squarespace": "No Such Domain",
            "Cloudfront": "Bad request",
            "Fastly": "Fastly error: unknown domain",
            "Zendesk": "Help Center Closed",
            "Tumblr": "There's nothing here",
            "Wix": "Looks like this domain isn't connected to a website yet!"
        }

        for sub in subdomains:
            try:
                response = subprocess.run(["curl", "-s", f"http://{sub}"], capture_output=True, text=True, timeout=10)
                for service, signature in fingerprints.items():
                    if signature.lower() in response.stdout.lower():
                        log(f"[TAKEOVER SCAN] Potential {service} takeover: {sub}")
                        found_takeovers.append(f"{sub} - {service}")
            except Exception as e:
                log(f"[TAKEOVER SCAN] Error scanning {sub}: {e}")

        with open(output_file, "w") as f:
            for takeover in found_takeovers:
                f.write(takeover + "\n")

        log(f"[TAKEOVER SCAN] Completed. {len(found_takeovers)} potential takeovers saved to {output_file}")

    except Exception as e:
        log(f"[TAKEOVER SCAN] General exception: {e}")
