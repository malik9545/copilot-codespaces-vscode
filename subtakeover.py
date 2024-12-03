import requests
import argparse
import concurrent.futures
import re
import time
import json
import random
from urllib.parse import urlparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from collections import defaultdict
from termcolor import colored

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Advanced headers and randomization
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"
]

def read_subdomains(file_path):
    """
    Reads subdomains from a txt file.
    """
    with open(file_path, 'r') as f:
        return [line.strip() for line in f.readlines() if line.strip()]

def is_potential_takeover(response_text, response_status):
    """
    Checks if the response body contains common indicators of a subdomain takeover.
    """
    takeover_indicators = [
        "There isn't a GitHub Pages site here.",
        "NoSuchBucket",  # Amazon S3
        "You're almost there!",  # Heroku
        "Do you want to register *.wordpress.com?",
        "The specified bucket does not exist",  # Amazon S3
        "Sorry, We Couldn't Find That Page",  # Tumblr
        "Fastly error: unknown domain",
        "This page is reserved for future use",  # Microsoft Azure
        "project not found",  # GitLab Pages
        "404 Not Found",  # Common in services such as Shopify
        "CNAME Cross-User Banned",  # CloudFront
        "Temporary Redirect",
        "Trying to access your account?",
        "No such app",  # Fly.io
        "No such site at this address",  # Pantheon
        "The service you requested is not available."  # Bitbucket
    ]

    # Check for 404 status code and common indicators
    if response_status == 404:
        return True
    
    for indicator in takeover_indicators:
        if re.search(indicator, response_text, re.IGNORECASE):
            return True

    return False

def check_subdomain(subdomain):
    """
    Checks a single subdomain for potential takeover.
    """
    urls = [f"http://{subdomain}", f"https://{subdomain}"]
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
    }
    
    for url in urls:
        try:
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            if is_potential_takeover(response.text, response.status_code):
                print(colored(f"[!] Potential Subdomain Takeover Detected: {subdomain}", "red", attrs=["bold"]))
                log_vulnerability(subdomain, url, response.status_code, response.text)
                return
            else:
                print(colored(f"[-] No Takeover Detected: {subdomain}", "green"))
        except requests.exceptions.SSLError as e:
            print(colored(f"[!] SSL Error checking subdomain {subdomain}: {e}", "yellow"))
        except requests.exceptions.RequestException as e:
            print(colored(f"[!] Error checking subdomain {subdomain}: {e}", "yellow"))

def log_vulnerability(subdomain, url, status_code, response_text):
    """
    Logs the details of a potential subdomain takeover to a JSON file.
    """
    log_entry = {
        "subdomain": subdomain,
        "url": url,
        "status_code": status_code,
        "response_snippet": response_text[:200]
    }
    with open("subdomain_takeover_vulnerabilities.json", "a") as log_file:
        json.dump(log_entry, log_file)
        log_file.write("\n")

def main(file_path, max_threads, retry_attempts):
    subdomains = read_subdomains(file_path)
    retry_count = 0
    failed_attempts = defaultdict(int)
    
    while retry_count <= retry_attempts:
        with concurrent.futures.ThreadPoolExecutor(max_threads) as executor:
            future_to_subdomain = {executor.submit(check_subdomain, subdomain): subdomain for subdomain in subdomains}
            for future in concurrent.futures.as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                try:
                    future.result()
                except Exception as e:
                    print(colored(f"[!] Error processing subdomain {subdomain}: {e}", "yellow"))
                    failed_attempts[subdomain] += 1
        retry_count += 1
        if retry_count <= retry_attempts:
            subdomains = [subdomain for subdomain, attempts in failed_attempts.items() if attempts < retry_attempts]
            if subdomains:
                print(colored(f"[+] Retrying failed requests... Attempt {retry_count} of {retry_attempts}", "cyan"))
                time.sleep(5)
            else:
                break

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check for subdomain takeover vulnerabilities.")
    parser.add_argument("file", help="Path to the file containing the list of subdomains.")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads to use for concurrent requests (default: 10)")
    parser.add_argument("--retries", type=int, default=1, help="Number of retry attempts for failed requests (default: 1)")
    args = parser.parse_args()

    main(args.file, args.threads, args.retries)
