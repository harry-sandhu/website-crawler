from urllib.parse import urljoin, urlparse

from audit.models import Issue

CATEGORY = "Performance"
HEAVY = 300 * 1024
LEGACY = (".jpg", ".jpeg", ".png", ".gif", ".bmp")


def _issue(severity, title, description, recommendation, evidence=""):

    return Issue(
        category=CATEGORY,
        severity=severity,
        title=title,
        description=description,
        recommendation=recommendation,
        evidence=evidence,
        confidence="High",
        verification_method="Image resource inspection",
    )


def run_image_audit(website):

    issues = []

    soup = website.page["soup"]
    images = soup.find_all("img")

    # ---------- weight (from observed responses) ----------

    heavy = []

    for response in website.browser.get("responses", []):

        if not response.get("content_type", "").startswith("image/"):
            continue

        try:
            size = int(response["headers"].get("content-length", 0))
        except (TypeError, ValueError):
            continue

        if size > HEAVY:
            heavy.append((size, response["url"]))

    if heavy:

        heavy.sort(reverse=True)

        issues.append(_issue(
            "High" if heavy[0][0] > 1024 * 1024 else "Medium",
            "Oversized Images",
            f"{len(heavy)} images are larger than 300KB "
            f"(largest {heavy[0][0] / 1024:.0f}KB).",
            "Resize to display size and compress; serve WebP/AVIF.",
            evidence="\n".join(f"{s / 1024:.0f}KB {u}" for s, u in heavy[:8]),
        ))

    # ---------- modern formats ----------

    legacy = []

    for img in images:

        src = (img.get("src") or "").split("?")[0].lower()
        in_picture = img.find_parent("picture") is not None

        if src.endswith(LEGACY) and not in_picture:
            legacy.append(src)

    if len(legacy) >= 3:

        issues.append(_issue(
            "Low",
            "Legacy Image Formats",
            f"{len(legacy)} images use JPEG/PNG/GIF without a modern fallback.",
            "Use WebP or AVIF via <picture> to cut image weight 25–50%.",
            evidence="\n".join(legacy[:8]),
        ))

    # ---------- missing dimensions (layout shift) ----------

    no_size = [
        img.get("src", "")[:80] for img in images
        if img.get("src") and not (img.get("width") and img.get("height"))
        and "aspect-ratio" not in (img.get("style") or "")
    ]

    if len(no_size) >= 3:

        issues.append(_issue(
            "Low",
            "Images Missing Width and Height",
            f"{len(no_size)} images lack width/height attributes, causing "
            "layout shift while loading.",
            "Add width and height (or CSS aspect-ratio) to every image.",
            evidence="\n".join(no_size[:8]),
        ))

    # ---------- responsive images / lazy loading ----------

    large = [img for img in images if int(img.get("width") or 0) >= 600]
    no_srcset = [i for i in large if not i.get("srcset")]

    if len(no_srcset) >= 2:

        issues.append(_issue(
            "Low",
            "No Responsive Image Sources",
            f"{len(no_srcset)} large images have no srcset, so phones "
            "download desktop-size files.",
            "Add srcset and sizes attributes.",
        ))

    below = images[3:]
    eager = [i for i in below if i.get("loading") != "lazy" and i.get("src")]

    if len(eager) >= 6:

        issues.append(_issue(
            "Low",
            "Offscreen Images Not Lazy-Loaded",
            f"{len(eager)} images later in the page load eagerly.",
            'Add loading="lazy" to images below the fold.',
        ))

    return issues
