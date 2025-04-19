# modules/osint/people_contacts.py

import os
import re
import requests
from bs4 import BeautifulSoup
from utils.logger import log
from utils.helpers import ensure_dir
from urllib.parse import quote_plus

PDF_DORKS = [
    "site:{} filetype:pdf",
    "site:{} intitle:directory filetype:pdf",
    "site:{} intitle:staff filetype:pdf",
    "site:{} contact filetype:pdf",
    "site:{} phone filetype:pdf",
    "site:{} staff list filetype:pdf"
]

HTML_DORKS = [
    "site:{} staff",
    "site:{} contact",
    "site:{} phone",
    "site:{} directory",
    "site:{} faculty"
]

LINKEDIN_DORKS = [
    "site:linkedin.com/in \"{}\"",
    "site:linkedin.com/in \"{} employees\"",
    "site:linkedin.com/in \"{}\" AND (HR OR Director OR Principal OR Admin)"
]

PHONE_REGEX = re.compile(r"(?:\+?\d{1,2}\s?)?(?:\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})")
EMAIL_REGEX = re.compile(r"[\w\.-]+@[\w\.-]+\.[a-zA-Z]{2,}")
NAME_REGEX = re.compile(r"(?:(?:Mr|Mrs|Ms|Dr|Prof)\.\s)?(?:[A-Z][a-z]+\s[A-Z][a-z]+)")

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
}


def google_search(query, limit=10):
    results = []
    try:
        url = f"https://www.google.com/search?q={quote_plus(query)}"
        res = requests.get(url, headers=HEADERS, timeout=15)
        soup = BeautifulSoup(res.text, "html.parser")
        for a in soup.select("a"):
            href = a.get("href")
            if href and href.startswith("/url?q="):
                clean = href.split("/url?q=")[1].split("&sa=")[0]
                results.append(clean)
                if len(results) >= limit:
                    break
    except Exception as e:
        log(f"[GOOGLE] Error during Google search: {e}", level="ERROR")
    return results


def extract_from_html(url):
    found = []
    try:
        res = requests.get(url, headers=HEADERS, timeout=10)
        soup = BeautifulSoup(res.text, "html.parser")
        text = soup.get_text()

        phones = set(PHONE_REGEX.findall(text))
        emails = set(EMAIL_REGEX.findall(text))
        names = set(NAME_REGEX.findall(text))

        for item in zip(names, emails):
            found.append((item[0], item[1], "N/A", url))

        for phone in phones:
            found.append(("N/A", "N/A", phone.strip(), url))
    except Exception as e:
        log(f"[HTML EXTRACT] Failed to extract from {url}: {e}", level="WARN")
    return found


def scrape_linkedin_profiles(domain):
    log(f"[LINKEDIN] Scraping LinkedIn employee profiles for: {domain}")
    results = []
    for dork in LINKEDIN_DORKS:
        query = dork.format(domain)
        links = google_search(query, limit=10)
        for url in links:
            if "linkedin.com/in" in url:
                try:
                    res = requests.get(url, headers=HEADERS, timeout=10)
                    soup = BeautifulSoup(res.text, "html.parser")
                    snippet = soup.get_text()
                    name_match = NAME_REGEX.findall(snippet)
                    title_match = re.findall(r"(?i)([\w\s\-/]+)(?: at|\n)", snippet)
                    name = name_match[0] if name_match else "N/A"
                    title = title_match[0].strip() if title_match else "N/A"
                    results.append((name, "N/A", "N/A", url, title))
                except Exception as e:
                    log(f"[LINKEDIN] Error scraping profile: {e}", level="WARN")
    return results


def run(domain):
    output_file = f"reports/{domain}_people_and_contacts.txt"
    ensure_dir("reports")
    collected = set()

    log("[PEOPLE SCAN] Starting enumeration of names, emails, and phones...")

    for dork in HTML_DORKS:
        query = dork.format(domain)
        links = google_search(query)
        for url in links:
            results = extract_from_html(url)
            for r in results:
                collected.add(r)

    for dork in PDF_DORKS:
        query = dork.format(domain)
        links = google_search(query)
        for url in links:
            log(f"[PDF LINK] (Manual Review): {url}")

    linkedin_results = scrape_linkedin_profiles(domain)
    for name, email, phone, source, title in linkedin_results:
        collected.add((name, email, phone, f"{source} | {title}"))

    try:
        with open(output_file, "w") as f:
            for name, email, phone, source in sorted(collected):
                f.write(f"Name: {name}\nEmail: {email}\nPhone: {phone}\nSource: {source}\n\n")
        log(f"[PEOPLE SCAN] Results saved to {output_file}")
    except Exception as e:
        log(f"[PEOPLE SCAN] Error writing to file: {e}", level="ERROR")
