# modules/osint/metadata_finder.py

import os
import requests
import tempfile
import zipfile
from utils.logger import log

from subprocess import run as shell


def run(domain):
    log(f"[METAFINDER] Searching for public documents with metadata for: {domain}")

    dorks = [
        f"site:{domain} filetype:pdf",
        f"site:{domain} filetype:doc",
        f"site:{domain} filetype:xls"
    ]

    search_links = []
    for dork in dorks:
        try:
            url = f"https://www.google.com/search?q={dork}"
            log(f"[METAFINDER] Search Dork: {url}")
            search_links.append(url)  # just show links for now
        except Exception as e:
            log(f"[METAFINDER] Error generating dork: {e}")

    output_path = f"reports/{domain}_meta_links.txt"
    with open(output_path, "w") as f:
        for link in search_links:
            f.write(link + "\n")

    log(f"[METAFINDER] Metadata-related search dorks saved to {output_path}")
    log("[METAFINDER] Downloading and analyzing files not automated to avoid spam detection.")
