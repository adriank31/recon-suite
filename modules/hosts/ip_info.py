# modules/hosts/ip_info.py

import requests
from utils.logger import log
import ipaddress

def run(target):
    log(f"[IP INFO] Gathering IP information for: {target}")

    try:
        # Validate IP or resolve domain to IP
        ip = target
        try:
            ipaddress.ip_address(target)  # Will raise if not IP
        except ValueError:
            log(f"[IP INFO] Resolving domain to IP: {target}")
            ip = requests.get(f"https://dns.google/resolve?name={target}&type=A", timeout=10).json()
            ip = ip['Answer'][0]['data'] if 'Answer' in ip else target

        log(f"[IP INFO] Using IP: {ip}")

        # Query IPinfo API (no key needed for limited use)
        res = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
        ip_data = res.json()

        output_path = f"reports/{target}_ip_info.txt"
        with open(output_path, "w") as f:
            for key, value in ip_data.items():
                f.write(f"{key}: {value}\n")

        log(f"[IP INFO] IP data saved to {output_path}")

    except Exception as e:
        log(f"[IP INFO] Exception occurred while retrieving IP info: {e}")
