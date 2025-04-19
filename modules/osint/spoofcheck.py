# modules/osint/spoofcheck.py

import dns.resolver
from utils.logger import log

def run(domain):
    log(f"[SPOOFCHECK] Checking SPF, DKIM, and DMARC records for: {domain}")
    results = {}

    try:
        spf = dns.resolver.resolve(domain, 'TXT')
        results['SPF'] = [r.to_text() for r in spf if 'v=spf1' in r.to_text()]
    except Exception:
        results['SPF'] = []

    try:
        dmarc = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        results['DMARC'] = [r.to_text() for r in dmarc if 'v=DMARC1' in r.to_text()]
    except Exception:
        results['DMARC'] = []

    # DKIM detection (selector brute-forcing skipped for speed)
    results['DKIM'] = "Check manually (selector required)"

    output_path = f"reports/{domain}_spoofcheck.txt"
    with open(output_path, "w") as f:
        for record, value in results.items():
            f.write(f"{record}: {value}\n")

    log(f"[SPOOFCHECK] Spoof check results saved to {output_path}")
