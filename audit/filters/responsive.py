from audit.responsive.models import ResponsiveElement


# =====================================================
# Ignore Lists
# =====================================================

IGNORE_TAGS = {
    "HTML",
    "HEAD",
    "META",
    "LINK",
    "STYLE",
    "SCRIPT",
    "NOSCRIPT",
    "TITLE",
    "BR",
    "SOURCE",
    "SVG",
    "PATH",
    "DEFS",
    "CLIPPATH",
}


IGNORE_CLASSES = {
    "sr-only",
    "screen-reader",
    "visually-hidden",
}


IGNORE_PREFIXES = (
    "sr7",
    "swiper",
    "slick",
    "owl",
    "elementor",
    "wp-",
)


# =====================================================
# Core Filter
# =====================================================

def should_ignore(
    element: ResponsiveElement,
    ignore_hidden: bool = True,
) -> bool:

    # -----------------------------
    # Ignore HTML infrastructure
    # -----------------------------

    if element.tag.upper() in IGNORE_TAGS:
        return True

    # -----------------------------
    # Ignore tiny elements
    # -----------------------------

    if element.width <= 1 or element.height <= 1:
        return True

    # -----------------------------
    # Ignore hidden elements
    # (optional)
    # -----------------------------

    if ignore_hidden and not element.visible:
        return True

    # -----------------------------
    # Ignore known utility classes
    # -----------------------------

    classes = element.classes.lower()

    for cls in IGNORE_CLASSES:
        if cls in classes:
            return True

    for prefix in IGNORE_PREFIXES:
        if prefix in classes:
            return True

    return False


# =====================================================
# Generic Filters
# =====================================================

def visible_elements(elements):

    return [
        e
        for e in elements
        if not should_ignore(e)
    ]


def all_elements(elements):

    return [
        e
        for e in elements
        if not should_ignore(
            e,
            ignore_hidden=False,
        )
    ]


def interactive_elements(elements):

    tags = {
        "A",
        "BUTTON",
        "INPUT",
        "SELECT",
        "TEXTAREA",
    }

    return [
        e
        for e in visible_elements(elements)
        if e.tag in tags
    ]


def image_elements(elements):

    return [
        e
        for e in visible_elements(elements)
        if e.tag == "IMG"
    ]


def navigation_elements(elements):

    return [
        e
        for e in visible_elements(elements)
        if (
            e.tag in (
                "NAV",
                "HEADER",
            )
            or e.role == "navigation"
        )
    ]