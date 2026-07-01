from browser.browser import BrowserManager
from browser.screenshots import ScreenshotManager

from audit.collector import collect_page_data
from audit.fetcher import WebsiteFetcher
from audit.website import WebsiteData


class WebsiteCrawler:
    def __init__(self, headless=True):
        self.browser = BrowserManager(headless=headless)

    def crawl(self, url: str):
        # ----------------------------------
        # Open Browser
        # ----------------------------------

        page = self.browser.start()

        page.goto(url, wait_until="networkidle")

        # ----------------------------------
        # Collect Page Data
        # ----------------------------------

        page_data = collect_page_data(page)
        browser_data = self.browser.get_data()

        # ----------------------------------
        # Fetch Extra Resources
        # ----------------------------------

        fetcher = WebsiteFetcher()

        robots = fetcher.fetch_robots(page.url)
        sitemap = fetcher.fetch_sitemap(page.url)

        # ----------------------------------
        # Capture Screenshots
        # ----------------------------------

        screenshot_manager = ScreenshotManager()

        screenshots = screenshot_manager.capture_all(page)

        # Restore desktop viewport so anything
        # after this behaves predictably.
        page.set_viewport_size({
            "width": 1440,
            "height": 900,
        })

        # ----------------------------------
        # Return Website Data
        # ----------------------------------

        website = WebsiteData(
            title=page.title(),
            page=page_data,
            browser=browser_data,
            robots=robots,
            sitemap=sitemap,
            screenshots=screenshots,
        )
        
        return website, page

    def close(self):
        self.browser.close()