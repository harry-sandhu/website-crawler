from .models import ResponsiveResult
from .dom_inspector import inspect_dom


def detect(page, device_name):

    page_data = page.evaluate("""
    () => ({

        width: window.innerWidth,

        height: window.innerHeight,

        scrollWidth: document.documentElement.scrollWidth,

        clientWidth: document.documentElement.clientWidth

    })
    """)

    elements = inspect_dom(page)

    oversized = [
        e for e in elements
        if e.width > page_data["width"] + 5
    ]

    fixed = [
        e.tag
        for e in elements
        if e.fixed
    ]

    return ResponsiveResult(

        device=device_name,

        width=page_data["width"],

        height=page_data["height"],

        scroll_width=page_data["scrollWidth"],

        client_width=page_data["clientWidth"],

        oversized=oversized,

        fixed_elements=fixed,

        elements=elements,
    )