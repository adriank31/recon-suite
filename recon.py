# recon.py

import argparse
import sys
import os
from modules.osint import whois_lookup, emailfinder, leaks, metadata_finder, porch_pirate, spoofcheck
from modules.subdomains import passive_enum, dns_records, takeover_scan, dns_takeover
from modules.hosts import ip_info, waf_check, port_scanner, vuln_scan
from modules.webs import web_probe, template_scanner, cms_detector, js_analyzer, fuzzer
from utils.logger import log


def main():
    parser = argparse.ArgumentParser(description="Recon Suite: Modular Red Team Recon Tool")
    parser.add_argument("-d", "--domain", help="Target domain")
    parser.add_argument("-i", "--ip", help="Target IP")
    parser.add_argument("--all", action="store_true", help="Run full recon stack")
    parser.add_argument("--osint", action="store_true", help="Run OSINT module")
    parser.add_argument("--subdomains", action="store_true", help="Run subdomain enumeration")
    parser.add_argument("--hosts", action="store_true", help="Run host info scan")
    parser.add_argument("--webs", action="store_true", help="Run web analysis module")

    args = parser.parse_args()

    if not (args.domain or args.ip):
        parser.error("You must specify a domain (-d) or IP (-i)")

    if args.all or args.osint:
        log("[+] Running OSINT recon...")
        whois_lookup.run(args.domain)
        emailfinder.run(args.domain)
        leaks.run(args.domain)
        metadata_finder.run(args.domain)
        porch_pirate.run(args.domain)
        spoofcheck.run(args.domain)

    if args.all or args.subdomains:
        log("[+] Running Subdomain recon...")
        passive_enum.run(args.domain)
        dns_records.run(args.domain)
        takeover_scan.run(args.domain)
        dns_takeover.run(args.domain)

    if args.all or args.hosts:
        log("[+] Running Host recon...")
        ip_info.run(args.domain or args.ip)
        waf_check.run(args.domain)
        port_scanner.run(args.domain or args.ip)
        vuln_scan.run(args.domain or args.ip)

    if args.all or args.webs:
        log("[+] Running Web recon...")
        web_probe.run(args.domain)
        template_scanner.run(args.domain)
        cms_detector.run(args.domain)
        js_analyzer.run(args.domain)
        fuzzer.run(args.domain)

    log("[+] Recon complete. Reports saved in /reports")


if __name__ == "__main__":
    main()
