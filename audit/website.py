from dataclasses import dataclass, field


@dataclass
class WebsiteData:
    title: str

    page: dict
    browser: dict

    robots: dict
    sitemap: dict

    screenshots: dict = field(default_factory=dict)