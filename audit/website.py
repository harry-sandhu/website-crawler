from dataclasses import dataclass, field
from typing import Any


@dataclass
class WebsiteData:

    # ----------------------------------
    # Basic Info
    # ----------------------------------

    url: str

    title: str

    # ----------------------------------
    # Collected Data
    # ----------------------------------

    page: dict

    browser: dict

    robots: dict

    sitemap: dict

    screenshots: dict = field(default_factory=dict)

    # ----------------------------------
    # Runtime Objects
    # ----------------------------------

    page_object: Any = None

    screenshot_manager: Any = None

    # ----------------------------------
    # Future
    # ----------------------------------

    lighthouse: Any = None

    accessibility: Any = None