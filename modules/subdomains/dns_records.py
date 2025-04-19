# modules/subdomains/dns_records.py

import dns.resolver
import dns.zone
import dns.query
import dns.exception
from utils.logger import log

def run(domain):
    log(f"[DNS RECORDS] Gathering DNS records for: {domain}")

    record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]
    results = {}

    for rtype in record_types:
        try:
            log(f"[DNS RECORDS] Resolving {rtype} records...")
            answers = dns.resolver.resolve(domain, rtype)
            records = [str(rdata.to_text()) for rdata in answers]
            results[rtype] = records
        except dns.resolver.NoAnswer:
            log(f"[DNS RECORDS] No {rtype} records found.")
            results[rtype] = []
        except dns.resolver.NXDOMAIN:
            log(f"[DNS RECORDS] Domain does not exist: {domain}")
            break
        except dns.exception.DNSException as e:
            log(f"[DNS RECORDS] DNS error while querying {rtype}: {e}")
            results[rtype] = []

    # Attempt zone transfer from all NS records
    if "NS" in results and results["NS"]:
        for ns in results["NS"]:
            ns_clean = ns.strip('.')
            log(f"[DNS RECORDS] Attempting zone transfer from {ns_clean}...")
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns_clean, domain, timeout=10))
                names = zone.nodes.keys()
                zrecords = [str(n) + "." + domain for n in names]
                results["AXFR"] = zrecords
                log(f"[DNS RECORDS] Zone transfer successful from {ns_clean}, {len(zrecords)} records found.")
                break
            except Exception as e:
                log(f"[DNS RECORDS] Zone transfer failed from {ns_clean}: {e}")

    output_path = f"reports/{domain}_dns_records.txt"
    with open(output_path, "w") as f:
        for rtype, records in results.items():
            f.write(f"{rtype} Records:\n")
            for record in records:
                f.write(f"  {record}\n")
            f.write("\n")

    log(f"[DNS RECORDS] DNS record enumeration complete. Results saved to {output_path}")
