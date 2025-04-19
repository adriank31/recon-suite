# recon.py

import argparse
import os
import shutil
from modules.osint import whois_lookup, emailfinder, leaks, metadata_finder, porch_pirate, spoofcheck, people_contacts
from modules.subdomains import passive_enum, dns_records, takeover_scan, dns_takeover, dns_resolver
from modules.hosts import ip_info, waf_check, port_scanner, vuln_scan, ssl_checker
from modules.webs import web_probe, template_scanner, cms_detector, js_analyzer, fuzzer, discovery_paths, active_web_attacks
from utils.logger import log, log_banner, log_section

REQUIRED_TOOLS = [
    "subfinder",
    "assetfinder",
    "httpx",
    "nuclei",
    "whatweb",
    "gobuster",
    "masscan",
    "nmap",
    "whois",
    "curl",
    "amass",
    "ffuf",
    "dnsx",
    "sslscan"
]

def check_dependencies():
    missing = []
    for tool in REQUIRED_TOOLS:
        if not shutil.which(tool):
            log(f"[DEPENDENCY] Missing: {tool}", level="WARN")
            missing.append(tool)
    if missing:
        log("[DEPENDENCY] WARNING: Some tools are missing. Certain modules may fail.", level="WARN")
    else:
        log("[DEPENDENCY] All required tools found.")

def main():
    parser = argparse.ArgumentParser(description="Red Team Recon Suite")
    parser.add_argument("-d", "--domain", help="Target domain name")
    parser.add_argument("-i", "--ip", help="Target IP address")
    parser.add_argument("--osint", action="store_true", help="Run OSINT modules")
    parser.add_argument("--subdomains", action="store_true", help="Run subdomain enumeration modules")
    parser.add_argument("--hosts", action="store_true", help="Run host discovery and scans")
    parser.add_argument("--webs", action="store_true", help="Run web reconnaissance modules")
    parser.add_argument("--all", action="store_true", help="Run all modules")
    args = parser.parse_args()

    if args.domain:
        args.domain = args.domain.replace("https://", "").replace("http://", "").strip("/").lower()

    if not os.path.exists("reports"):
        os.makedirs("reports")

    log_banner()
    check_dependencies()

    if args.all or args.osint:
        log_section("Running OSINT recon")
        whois_lookup.run(args.domain)
        emailfinder.run(args.domain)
        leaks.run(args.domain)
        metadata_finder.run(args.domain)
        porch_pirate.run(args.domain)
        spoofcheck.run(args.domain)
        people_contacts.run(args.domain)

    if args.all or args.subdomains:
        log_section("Running Subdomain recon")
        passive_enum.run(args.domain)
        dns_records.run(args.domain)
        takeover_scan.run(args.domain)
        dns_takeover.run(args.domain)
        dns_resolver.run(args.domain)

    if args.all or args.hosts:
        log_section("Running Host recon")
        ip_info.run(args.domain or args.ip)
        waf_check.run(args.domain or args.ip)
        port_scanner.run(args.domain or args.ip)
        vuln_scan.run(args.domain or args.ip)
        ssl_checker.run(args.domain or args.ip)

    if args.all or args.webs:
        log_section("Running Web recon")
        web_probe.run(args.domain)
        template_scanner.run(args.domain)
        cms_detector.run(args.domain)
        js_analyzer.run(args.domain)
        fuzzer.run(args.domain)
        discovery_paths.run(args.domain)
        active_web_attacks.run(args.domain)

    log("[+] Recon complete. Reports saved in /reports")

if __name__ == "__main__":
    main()