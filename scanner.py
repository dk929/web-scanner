import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import csv

# Payloads
xss_payload = "<script>alert('XSS')</script>"
sqli_payload = "' OR '1'='1"

visited = set()

def crawl(url, max_pages=20):
    urls = [url]
    crawled = []
    while urls and len(crawled) < max_pages:
        link = urls.pop(0)
        if link in visited:
            continue
        visited.add(link)
        try:
            response = requests.get(link, timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")
            for a in soup.find_all("a", href=True):
                new_link = urljoin(url, a["href"])
                if url in new_link and new_link not in visited:
                    urls.append(new_link)
            crawled.append(link)
        except:
            pass
    return crawled

def test_xss(url):
    test_url = url + "?q=" + xss_payload
    r = requests.get(test_url)
    if xss_payload in r.text:
        return True
    return False

def test_sqli(url):
    test_url = url + "?id=" + sqli_payload
    r = requests.get(test_url)
    if "sql" in r.text.lower() or "error" in r.text.lower():
        return True
    return False

def main(target):
    results = []
    print(f"[+] Crawling {target}")
    urls = crawl(target)
    print(f"[+] Found {len(urls)} URLs")

    for u in urls:
        if test_xss(u):
            print(f"[!] Possible XSS vulnerability: {u}")
            results.append(("XSS", u))
        if test_sqli(u):
            print(f"[!] Possible SQLi vulnerability: {u}")
            results.append(("SQLi", u))

    # Save results
    with open("scan_report.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Vulnerability", "URL"])
        writer.writerows(results)

    print("[+] Report saved to scan_report.csv")

if __name__ == "__main__":
    target_site = input("http://testphp.vulnweb.com)")
    main(target_site)
