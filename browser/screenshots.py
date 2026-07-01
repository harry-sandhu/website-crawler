from pathlib import Path


class ScreenshotManager:
    DEVICES = {
        "desktop": {
            "width": 1440,
            "height": 900,
        },
        "iphone_se": {
            "width": 375,
            "height": 667,
        },
        "iphone_15": {
            "width": 393,
            "height": 852,
        },
        "galaxy_s23": {
            "width": 360,
            "height": 780,
        },
        "ipad": {
            "width": 820,
            "height": 1180,
        },
    }

    def __init__(self):
        self.output = Path("output/screenshots")
        self.output.mkdir(parents=True, exist_ok=True)

    def capture(self, page, name, full_page=False):
        path = self.output / f"{name}.png"

        page.screenshot(
            path=str(path),
            full_page=full_page,
        )

        return str(path)

    def capture_device(self, page, device_name):
        if device_name not in self.DEVICES:
            raise ValueError(f"Unknown device: {device_name}")

        device = self.DEVICES[device_name]

        # Set viewport
        page.set_viewport_size({
            "width": device["width"],
            "height": device["height"],
        })

        # Scroll to the top before taking screenshots
        page.evaluate("window.scrollTo(0, 0)")

        # Give the layout a moment to settle
        page.wait_for_timeout(500)

        normal = self.capture(
            page,
            device_name,
        )

        full = self.capture(
            page,
            f"{device_name}_full",
            full_page=True,
        )

        return {
            "width": device["width"],
            "height": device["height"],
            "normal": normal,
            "full": full,
        }

    def capture_all(self, page):
        screenshots = {}

        for device_name in self.DEVICES:
            screenshots[device_name] = self.capture_device(
                page,
                device_name,
            )

        # Restore desktop viewport
        desktop = self.DEVICES["desktop"]

        page.set_viewport_size({
            "width": desktop["width"],
            "height": desktop["height"],
        })

        page.evaluate("window.scrollTo(0, 0)")
        page.wait_for_timeout(300)

        return screenshots