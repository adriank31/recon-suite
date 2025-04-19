# modules/subdomains/dns_takeover.py

import dns.resolver
import dns.exception
import os
from utils.logger import log

def run(domain):
    log(f"[DNS TAKEOVER] Checking for unresolvable CNAMEs for domain: {domain}")

    input_file = f"reports/{domain}_subdomains.txt"
    output_file = f"reports/{domain}_dns_takeover.txt"

    if not os.path.exists(input_file):
        log(f"[DNS TAKEOVER] Missing input subdomain list: {input_file}")
        return

    with open(input_file, "r") as f:
        subdomains = [line.strip() for line in f if line.strip()]

    dangling_cnames = []

    for sub in subdomains:
        try:
            answers = dns.resolver.resolve(sub, 'CNAME')
            for rdata in answers:
                cname_target = str(rdata.target).rstrip('.')
                try:
                    dns.resolver.resolve(cname_target, 'A')
                except dns.resolver.NXDOMAIN:
                    log(f"[DNS TAKEOVER] Potential dangling CNAME: {sub} -> {cname_target}")
                    dangling_cnames.append(f"{sub} -> {cname_target}")
                except dns.resolver.NoAnswer:
                    log(f"[DNS TAKEOVER] No A record for CNAME target: {sub} -> {cname_target}")
                    dangling_cnames.append(f"{sub} -> {cname_target}")
                except Exception as e:
                    log(f"[DNS TAKEOVER] Unexpected error resolving CNAME target {cname_target}: {e}")
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN:
            continue
        except Exception as e:
            log(f"[DNS TAKEOVER] Error resolving CNAME for {sub}: {e}")

    with open(output_file, "w") as f:
        for entry in dangling_cnames:
            f.write(entry + "\n")

    log(f"[DNS TAKEOVER] DNS takeover scan complete. Found {len(dangling_cnames)} candidates. Results saved to {output_file}")
