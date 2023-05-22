import requests
import re
from bs4 import BeautifulSoup
from argparse import ArgumentParser

class Scanner():
    """Website Vulnerability Page Scanner"""
    
    def __init__(self, target_url, whitelist=None):
        """
        Initializes the Scanner object.

        Args:
        target_url (str) - The URL of the target webstie to be scanned.
        whitelist (list of str) - List of non-sensitive pages to excluded from the scan. Default is none.

        Attributes:
        target_url - Equal to provided target_url by user.
        whitelist - Equal to provided whitelist by user.
        viewed_pages (set) - Set containing the viewed pages as the scanner operates.
        sensitive_pages (set) - Set containing links that hit on keywords for potential sensitive pages.
        Keywords (list) - List of words to search for organically and via the crawler. A hit will add the link to the sensitive_pages set.
        """
        self.target_url = target_url
        self.whitelist = whitelist or []
        self.viewed_pages = set()
        self.sensitive_pages = set()
        self.keywords = [
            r"admin",
            r"login",
            r"password",
            r"admin_panel",
            r"dashboard",
            r"control_panel",
            r"members",
            r"secure",
            r"account",
            r"auth",
            r"manager",
            r"confidential",
            r"restricted",
            r"private",
            r"secret",
            r"backup",
            r"config"
        ]

    def scan(self):
        """
        Performs the scanning of the website, both organically and using the web crawler method.

        Creates two files "scan_report.txt" with information regarding the scan, and "sensitive_pages.txt" which is just a list of sensitive links discovered.
        """
        self.scan_organic_pages()
        self.scan_page(self.target_url)

        with open("sensitive_pages.txt", "w") as f:
            for link in self.sensitive_pages:
                f.write(link + "\n")

        with open("scan_report.txt", "w") as f:
            f.write("Website Vulnerability Crawler and Page Search - Created by Jack Haines. Use Responsibly.\n")
            f.write("Scan report for: " + self.target_url + "\n")
            f.write("Sensitive Pages Found:\n")
            for link in self.sensitive_pages:
                f.write(link + "\n")
            f.write("\nTotal Potentially Sensitive Pages Found: " + str(len(self.sensitive_pages)))
            print(("Total Potentially Sensitive Pages Discovered: " + str(len(self.sensitive_pages))))

    def scan_organic_pages(self):
        """
        Scans site "organically" for sensitive pages.

        Iterates over the keywords list, appending each to the target URL. Then checks if page exists (response status code 200). If found, page is added to the "sensitive_pages" set.
        """
        
        for keyword in self.keywords:
            url = self.target_url + "/" + keyword
            response = requests.get(url)
            if response.status_code == 200:
                self.sensitive_pages.add(url)

    def scan_page(self, url):
        """
        Acts practically as a web crawler, looking for potentially hidden/pertinent links on a page that match the specified keywords.
        Use BeautifulSoup to parse HTML code, finds all links on page using "href" and "a" tags. Then filters out external and non-http links using list comprehension.
        Will take into account and filter out any links based on whitelist entry. Will then utilize recurssion to scan again.
        Finally, will add to the "sensitive_pages" set if regular expressions search matches the sensitive links being searched for.

        Args:
        url (str) - The URL of the page to scan, set seperate from target_url in case of use in instance of class. 
        """
        # Ensures URL exists
        try:
            response = requests.get(url, timeout=10)
        except requests.exceptions.RequestException:
            return
        
        # Uses BeautifulSoup to get page content, parses.
        soup = BeautifulSoup(response.text, "html.parser")

        # Find all links on the page
        links = [a.attrs.get("href") for a in soup.find_all("a")]

        # Filter out external links and non-http links
        links = [link for link in links if link and link.startswith("http") and self.target_url in link]

        # Filter out non-sensitive links based on whitelist entry
        links = [link for link in links if not any(w in link for w in self.whitelist)]


        # Scans all links on the page recursively
        for link in links:
            if link not in self.viewed_pages:
                self.viewed_pages.add(link)
                self.scan_page(link)

        sensitive_page = re.search(r"|".join(self.keywords), response.text, re.IGNORECASE)
        if sensitive_page:
            self.sensitive_pages.add(url)

def main():
    """
    Adds arguments to parser in order to be ran from the terminal/command-line. 
    Parses said arguments, ensures the given URL is valid, takes into account potential user error (raising exceptions if so), and then runs the scanner.
    """
    parser = ArgumentParser()
    parser.add_argument("url", type=str, help="Target website URL")
    parser.add_argument("--whitelist", type=str, nargs="*", default=[], help="List of non-sensitive pages to exclude from the scan (e.g. /public /about)")
    args = parser.parse_args()

    try:
        response = requests.get(args.url)
        response.raise_for_status() # Raise exception for non 200 status codes
    except (requests.exceptions.RequestException, requests.exceptions.HTTPError) as e: # Raising HTTP Error if URL not valid.
        print("Failed to access the given URL. Please ensure the URL is valid and can be accessed!!")

    # If valid continue running scanner.
    scanner = Scanner(args.url, args.whitelist)
    scanner.scan()

if __name__ == "__main__":
    main()
