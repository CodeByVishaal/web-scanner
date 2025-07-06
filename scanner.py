import requests
from bs4 import BeautifulSoup
import urllib.parse
import colorama
import re
from concurrent.futures import ThreadPoolExecutor
import sys
from typing import List, Dict, Set

class WebSecurityScanner:
    def __init__(self, target_url: str, max_depth: int = 3):
        """
        Initialize the security scanner with a target URL and maximum crawl depth.

        Args:
            target_url: The base URL to scan
            max_depth: Maximum depth for crawling links (default: 3)
        """
        self.target_url = target_url
        self.max_depth = max_depth
        self.visited_urls: Set[str] = set()
        self.vulnerabilities: List[Dict] = []
        self.session = requests.Session()

        # Initialize colorama for cross-platform colored output
        colorama.init()

    def normalize_url(self, url: str) -> str:
        """Normalize the URL to prevent duplicate checks"""
        parsed = urllib.parse.urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    
    def crawl(self, url: str, depth: int = 0) -> None:
        """
        Crawl the website to discover pages and endpoints.

        Args:
            url: Current URL to crawl
            depth: Current depth in the crawl tree
        """
        if depth > self.max_depth or url in self.visited_urls:
            return

        try:
            self.visited_urls.add(url)
            response = self.session.get(url, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find all links in the page
            links = soup.find_all('a', href=True)
            for link in links:
                next_url = urllib.parse.urljoin(url, link['href'])
                if next_url.startswith(self.target_url):
                    self.crawl(next_url, depth + 1)

            for link in self.visited_urls:
                self.check_sql_injection(link)
                    

        except Exception as e:
            print(f"Error crawling {url}: {str(e)}")

    def check_sql_injection(self, url: str) -> None:
        """Test for potential SQL injection vulnerabilities"""
        sql_payloads = ["'", "1' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--"]

        for payload in sql_payloads:
            try:
                # Test GET parameters
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)

                for param in params:
                    test_url = url.replace(f"{param}={params[param][0]}", 
                                        f"{param}={payload}")
                    response = self.session.get(test_url)

                    # Look for SQL error messages
                    if any(error in response.text.lower() for error in 
                        ['sql', 'mysql', 'sqlite', 'postgresql', 'oracle']):
                        self.vulnerabilities.append({
                            'type': 'SQL Injection',
                            'url': url,
                            'parameter': param,
                            'payload': payload
                        })
                print(self.vulnerabilities)

            except Exception as e:
                print(f"Error testing SQL injection on {url}: {str(e)}")

"""
    | Demo Site                                 | Example URL to Test                                              |
| ----------------------------------------- | ---------------------------------------------------------------- |
| [TestPHP](http://testphp.vulnweb.com)     | `http://testphp.vulnweb.com/artists.php?artist=1`                |
| [WebScanTest](http://www.webscantest.com) | `http://www.webscantest.com/datastore/search_get.php?search=red` |
| [TestFire](https://demo.testfire.net)     | `https://demo.testfire.net/search.aspx?txtSearch=bank`           |

"""

if __name__ == "__main__":
    import urllib3

    urllib3.disable_warnings()  # suppress HTTPS warnings

    scanner = WebSecurityScanner("http://testphp.vulnweb.com")  # Use a safe test site
    print("Normalized URL:", scanner.normalize_url(scanner.target_url))

    scanner = WebSecurityScanner("http://testphp.vulnweb.com/artists.php?artist=1", max_depth=1)
    scanner.crawl(scanner.target_url)
    
    print("\nVisited URLs:")
    for url in scanner.visited_urls:
        print(url)

    print("\nVulnerable URLs:")
    for url in scanner.vulnerabilities:
        print(url)
