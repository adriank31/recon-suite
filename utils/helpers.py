# utils/helpers.py

import socket
import random
import string
import os
from urllib.parse import urlparse
from utils.logger import log

def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def generate_random_string(length=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)
        log(f"[HELPERS] Created directory: {path}")

def extract_domain_from_url(url):
    try:
        parsed = urlparse(url)
        return parsed.netloc or parsed.path.split('/')[0]
    except Exception as e:
        log(f"[HELPERS] Failed to extract domain from URL {url}: {e}")
        return None

def load_lines_from_file(filepath):
    if not os.path.exists(filepath):
        log(f"[HELPERS] File not found: {filepath}", level="WARN")
        return []
    with open(filepath, "r") as f:
        return [line.strip() for line in f if line.strip()]

def save_lines_to_file(lines, filepath):
    ensure_dir(os.path.dirname(filepath))
    with open(filepath, "w") as f:
        for line in lines:
            f.write(line + "\n")
    log(f"[HELPERS] Saved {len(lines)} lines to {filepath}")
