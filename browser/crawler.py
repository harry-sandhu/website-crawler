from browser.browser import BrowserManager
from browser.screenshots import ScreenshotManager

from audit.collector import collect_page_data
from audit.fetcher import WebsiteFetcher
from audit.website import WebsiteData


class WebsiteCrawler:

    def __init__(self, headless=True):
        self.browser = BrowserManager(headless=headless)

    def crawl(
        self,
        url: str,
    ) -> WebsiteData:
    
        # ----------------------------------
        # Open Browser
        # ----------------------------------
    
        page = self.browser.start()
    
        # ----------------------------------
        # Navigate
        # ----------------------------------
    
        page.goto(
    
            url,
    
            wait_until="domcontentloaded",
    
            timeout=60000,
    
        )
    
        # Wait for the page to finish loading
    
        try:
    
            page.wait_for_load_state(
                "load",
                timeout=15000,
            )
    
        except Exception:
    
            pass
    
        # Give JS-heavy websites a moment
    
        page.wait_for_timeout(
            3000
        )
    
        # ----------------------------------
        # Collect Page Data
        # ----------------------------------
    
        page_data = collect_page_data(
            page
        )
    
        browser_data = self.browser.get_data()
    
        # ----------------------------------
        # Fetch Resources
        # ----------------------------------
    
        fetcher = WebsiteFetcher()
    
        robots = fetcher.fetch_robots(
            page.url
        )
    
        sitemap = fetcher.fetch_sitemap(
            page.url
        )
    
        # ----------------------------------
        # Screenshots
        # ----------------------------------
    
        screenshot_manager = ScreenshotManager()
    
        screenshots = screenshot_manager.capture_all(
            page
        )
    
        page.set_viewport_size(
            {
                "width": 1440,
                "height": 900,
            }
        )
    
        # ----------------------------------
        # Website Object
        # ----------------------------------
    
        return WebsiteData(
    
            url=page.url,
    
            title=page.title(),
    
            page=page_data,
    
            browser=browser_data,
    
            robots=robots,
    
            sitemap=sitemap,
    
            screenshots=screenshots,
    
            page_object=page,
    
            screenshot_manager=screenshot_manager,
    
        )

    def close(self):
        self.browser.close()