def reveal_content(page, step=600, pause=250):
    """Scroll through the page so scroll-triggered content (AOS, lazy
    images, intersection observers) renders before analysis/screenshots."""

    try:

        height = page.evaluate("document.documentElement.scrollHeight")
        viewport = page.evaluate("window.innerHeight")

        y = 0

        while y < min(height, 30000):

            page.evaluate(f"window.scrollTo(0, {y})")
            page.wait_for_timeout(pause)
            y += step

        page.wait_for_timeout(500)
        page.evaluate("window.scrollTo(0, 0)")
        page.wait_for_timeout(300)

    except Exception:

        pass
