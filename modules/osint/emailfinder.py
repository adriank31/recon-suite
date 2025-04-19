# modules/osint/emailfinder.py

import re
import requests
from utils.logger import log

def run(domain):
    log(f"[EMAILFINDER] Searching for emails related to: {domain}")
    try:
        sources = [
            f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey",
            f"https://crt.sh/?q=%25.{domain}&output=json"
        ]
        found_emails = set()

        for source in sources:
            res = requests.get(source, timeout=10)
            matches = re.findall(r"[\w.-]+@[\w.-]+", res.text)
            found_emails.update(matches)

        output_path = f"reports/{domain}_emails.txt"
        with open(output_path, "w") as f:
            for email in sorted(found_emails):
                f.write(email + "\n")

        log(f"[EMAILFINDER] Found {len(found_emails)} email(s). Saved to {output_path}")
    except Exception as e:
        log(f"[EMAILFINDER] Exception occurred: {e}")
