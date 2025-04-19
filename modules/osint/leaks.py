# modules/osint/leaks.py

import requests
from utils.logger import log

def run(domain):
    log(f"[LEAKS] Checking for credential leaks for: {domain}")
    try:
        url = f"https://leak-lookup.com/api/search?key=public&query={domain}"
        headers = {
            "Accept": "application/json"
        }
        res = requests.get(url, headers=headers, timeout=10)

        if res.status_code == 200 and res.text:
            output_path = f"reports/{domain}_leaks.txt"
            with open(output_path, "w") as f:
                f.write(res.text)
            log(f"[LEAKS] Leak results saved to {output_path}")
        else:
            log("[LEAKS] No leak data found or API rate limited.")
    except Exception as e:
        log(f"[LEAKS] Exception occurred: {e}")
