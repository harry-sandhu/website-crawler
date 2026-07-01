import requests
from urllib.parse import urljoin


class WebsiteFetcher:

    def __init__(self, timeout=10):
        self.timeout = timeout

    def fetch(self, url):
        try:
            response = requests.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                headers={
                    "User-Agent": "WebsiteAuditor/1.0"
                },
            )

            return {
                "exists": response.status_code == 200,
                "status": response.status_code,
                "content": response.text,
                "headers": dict(response.headers),
            }

        except Exception:
            return {
                "exists": False,
                "status": None,
                "content": "",
                "headers": {},
            }

    def fetch_robots(self, base_url):
        return self.fetch(
            urljoin(base_url, "/robots.txt")
        )

    def fetch_sitemap(self, base_url):
        return self.fetch(
            urljoin(base_url, "/sitemap.xml")
        )