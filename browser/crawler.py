from browser.browser import BrowserManager
from audit.collector import collect_page_data
from audit.website import WebsiteData
from audit.fetcher import WebsiteFetcher

class WebsiteCrawler:
    def __init__(self, headless=True):
        self.browser = BrowserManager(headless=headless)

    def crawl(self, url: str) -> WebsiteData:
        page = self.browser.start()

        page.goto(url, wait_until="networkidle")

        page_data = collect_page_data(page)
        browser_data = self.browser.get_data()

        fetcher = WebsiteFetcher()

        robots = fetcher.fetch_robots(page.url)
        sitemap = fetcher.fetch_sitemap(page.url)

        return WebsiteData(
            title=page.title(),
            page=page_data,
            browser=browser_data,
            robots=robots,
            sitemap=sitemap,
        )

    def close(self):
        self.browser.close()