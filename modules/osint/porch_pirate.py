# modules/osint/porch_pirate.py

import requests
from utils.logger import log

def run(domain):
    log(f"[PORCH PIRATE] Searching for exposed API endpoints for: {domain}")
    endpoints = [
        f"https://{domain}/swagger.json",
        f"https://{domain}/api/swagger.json",
        f"https://{domain}/v1/swagger.json",
        f"https://{domain}/openapi.json",
        f"https://{domain}/api-docs",
        f"https://{domain}/docs"
    ]

    found = []
    for url in endpoints:
        try:
            res = requests.get(url, timeout=5)
            if res.status_code == 200 and ("swagger" in res.text or "openapi" in res.text):
                found.append(url)
        except requests.RequestException:
            continue

    output_path = f"reports/{domain}_api_leaks.txt"
    with open(output_path, "w") as f:
        for link in found:
            f.write(link + "\n")

    if found:
        log(f"[PORCH PIRATE] Found {len(found)} exposed API endpoint(s). Saved to {output_path}")
    else:
        log("[PORCH PIRATE] No exposed API endpoints detected.")
