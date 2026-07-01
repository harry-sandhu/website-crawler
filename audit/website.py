from dataclasses import dataclass


@dataclass
class WebsiteData:
    title: str
    page: dict
    browser: dict

    robots: dict
    sitemap: dict