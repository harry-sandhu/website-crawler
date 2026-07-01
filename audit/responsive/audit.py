from audit.models import Issue

from .detector import detect


def run_responsive_audit(page, screenshot_manager):
    issues = []

    for device_name in screenshot_manager.DEVICES:

        device = screenshot_manager.DEVICES[device_name]

        page.set_viewport_size({
            "width": device["width"],
            "height": device["height"],
        })

        page.wait_for_timeout(300)

        result = detect(page, device_name)

        # -----------------------------
        # Horizontal Scroll
        # -----------------------------

        if result.scroll_width > result.client_width:
            issues.append(
                Issue(
                    category="Responsive",
                    severity="High",
                    title=f"Horizontal Scrolling ({device_name})",
                    description="Content exceeds viewport width.",
                    recommendation="Ensure all content fits within the viewport.",
                    page="/",
                    screenshot=f"{device_name}.png",
                )
            )

        # -----------------------------
        # Oversized Elements
        # -----------------------------

        if result.oversized:
            evidence = []

            for item in result.oversized[:10]:
                evidence.append(
                    f"{item['tag']} ({item['width']:.0f}px)"
                )

            issues.append(
                Issue(
                    category="Responsive",
                    severity="Medium",
                    title=f"Oversized Elements ({device_name})",
                    description=f"{len(result.oversized)} elements exceed the viewport width.",
                    recommendation="Resize or constrain oversized elements.",
                    evidence="\n".join(evidence),
                    screenshot=f"{device_name}.png",
                )
            )

    return issues