from pathlib import Path

from audit.models import Issue

from browser.reveal import reveal_content

from .inspector import inspect_page

try:
    from PIL import Image, ImageStat
except ImportError:  # pragma: no cover - Pillow is optional
    Image = None

CATEGORY = "Visual Design"

VIEWPORTS = {
    "desktop": {"width": 1440, "height": 900},
    "mobile": {"width": 393, "height": 852},
}


def _issue(severity, title, description, recommendation, evidence="", device="", **kwargs):

    return Issue(
        category=CATEGORY,
        severity=severity,
        title=title,
        description=description,
        recommendation=recommendation,
        evidence=evidence,
        confidence="High",
        verification_method="Computed style and layout inspection",
        notes=f"Viewport: {device}" if device else "",
        **kwargs,
    )


def _dominant(counter, limit=1):

    return sorted(counter.items(), key=lambda kv: -kv[1])[:limit]


# ----------------------------------
# Pixel checks
# ----------------------------------

def _screenshot_checks(page, screenshot_manager, device):

    issues = []

    if Image is None:
        return issues, None

    path = screenshot_manager.capture(page, f"visual_{device}")

    try:

        with Image.open(path) as shot:

            gray = shot.convert("L")
            stat = ImageStat.Stat(gray)
            stddev = stat.stddev[0]

            if stddev < 3:

                issues.append(_issue(
                    "Critical",
                    "Page Renders Blank",
                    "The first screen is almost a single flat colour, "
                    "so visitors may see an empty page.",
                    "Check for JavaScript failures, blocking overlays or "
                    "missing CSS that stop content from rendering.",
                    device=device,
                    screenshot=path,
                ))

            else:

                # Share of the first screen that is pure background colour.
                small = gray.resize((96, 54))
                pixels = list(small.getdata())
                background = max(set(pixels), key=pixels.count)
                empty = sum(
                    1 for p in pixels if abs(p - background) <= 3
                ) / len(pixels)

                if empty > 0.92 and device == "desktop":

                    issues.append(_issue(
                        "Medium",
                        "First Screen Is Mostly Empty",
                        f"{round(empty * 100)}% of the first screen is blank "
                        "background, which can look unfinished.",
                        "Add a clear headline, supporting visual and call "
                        "to action above the fold.",
                        device=device,
                        screenshot=path,
                    ))

            return issues, path

    except Exception:

        return issues, path


# ----------------------------------
# Per viewport rules
# ----------------------------------

def _rules(data, device):

    issues = []
    desktop = device == "desktop"

    # ---------- horizontal scroll ----------

    if data["scroll"]["width"] > data["viewport"]["width"] + 4:

        issues.append(_issue(
            "High" if not desktop else "Medium",
            "Horizontal Scrolling",
            f"Page is {data['scroll']['width']}px wide in a "
            f"{data['viewport']['width']}px viewport.",
            "Find the element that is wider than the viewport and make it "
            "fluid (max-width: 100%, flex-wrap, overflow handling).",
            device=device,
        ))

    # ---------- typography ----------

    total_chars = sum(data["sizes"].values()) or 1
    weighted = sum(int(size) * n for size, n in data["sizes"].items()) / total_chars

    if weighted < 14:

        issues.append(_issue(
            "Medium",
            "Body Text Too Small",
            f"Average text size is {weighted:.1f}px.",
            "Use at least 16px for body copy.",
            device=device,
        ))

    if data["smallText"]:

        issues.append(_issue(
            "Low",
            "Text Below 12px",
            f"{len(data['smallText'])}+ text elements are smaller than 12px.",
            "Increase tiny text; it is hard to read on every device.",
            evidence="\n".join(data["smallText"]),
            device=device,
        ))

    families = [f for f, n in data["fonts"].items() if n / total_chars > 0.03]

    if len(families) > 3:

        issues.append(_issue(
            "Low",
            "Too Many Typefaces",
            f"{len(families)} font families carry meaningful text.",
            "Limit the design to 1–2 typefaces for a cohesive look.",
            evidence=", ".join(families),
            device=device,
        ))

    if len(data["sizes"]) > 14:

        issues.append(_issue(
            "Low",
            "Inconsistent Type Scale",
            f"{len(data['sizes'])} distinct font sizes are used.",
            "Define a consistent type scale (e.g. 6–8 sizes).",
            device=device,
        ))

    if data["longLines"]:

        issues.append(_issue(
            "Low",
            "Overly Long Text Lines",
            "Paragraphs exceed ~100 characters per line, which hurts readability.",
            "Constrain text containers to 60–80 characters (max-width: 65ch).",
            evidence="\n".join(data["longLines"]),
            device=device,
        ))

    if data["lineHeightTight"]:

        issues.append(_issue(
            "Low",
            "Cramped Line Spacing",
            "Body paragraphs use a line-height below 1.2.",
            "Use a line-height of 1.4–1.6 for paragraph text.",
            evidence="\n".join(data["lineHeightTight"]),
            device=device,
        ))

    # ---------- contrast ----------

    low = data["lowContrast"]

    if low:

        worst = min(low, key=lambda c: c["ratio"])
        share = len(low) / max(data["contrastChecked"], 1)

        severity = "High" if worst["ratio"] < 2 or share > 0.15 else "Medium"

        issues.append(_issue(
            severity,
            "Low Text Contrast",
            f"{len(low)} text elements fail WCAG contrast "
            f"(worst {worst['ratio']}:1).",
            "Darken text or lighten backgrounds to reach 4.5:1 "
            "(3:1 for large text).",
            evidence="\n".join(
                f"{c['selector']} {c['ratio']}:1 (needs {c['need']}): {c['text']}"
                for c in low[:8]
            ),
            device=device,
        ))

    # ---------- palette ----------

    if len(data["textColors"]) > 14:

        issues.append(_issue(
            "Low",
            "Busy Colour Palette",
            f"About {len(data['textColors'])} different text colours are in use.",
            "Reduce the palette to a primary, secondary and neutral set.",
            device=device,
        ))

    # ---------- images ----------

    if data["brokenImages"]:

        issues.append(_issue(
            "High",
            "Broken Images Visible",
            f"{len(data['brokenImages'])} visible images failed to load.",
            "Fix image URLs or remove the elements.",
            evidence="\n".join(data["brokenImages"][:10]),
            device=device,
        ))

    if data["upscaledImages"]:

        issues.append(_issue(
            "Medium",
            "Blurry Upscaled Images",
            f"{len(data['upscaledImages'])} images are displayed larger than "
            "their source resolution.",
            "Serve images at least as large as their display size "
            "(2x for retina).",
            evidence="\n".join(data["upscaledImages"][:8]),
            device=device,
        ))

    if data["distortedImages"]:

        issues.append(_issue(
            "Medium",
            "Stretched or Squashed Images",
            f"{len(data['distortedImages'])} images are shown with a "
            "different aspect ratio than the source.",
            "Use object-fit: cover/contain or correct width/height.",
            evidence="\n".join(data["distortedImages"][:8]),
            device=device,
        ))

    # ---------- overlays / overlap ----------

    for overlay in data["overlays"]:

        if overlay["share"] >= 35:

            issues.append(_issue(
                "High" if not desktop else "Medium",
                "Overlay Covers Large Part of Screen",
                f"{overlay['selector']} ({overlay['position']}) covers "
                f"{overlay['share']}% of the viewport.",
                "Shrink banners/popups and make them easy to dismiss; "
                "avoid blocking content on first load.",
                device=device,
            ))

    if data["overlaps"]:

        issues.append(_issue(
            "Medium",
            "Overlapping Text or Controls",
            "Text elements visually collide with each other.",
            "Fix positioning/z-index so content does not overlap.",
            evidence="\n".join(data["overlaps"]),
            device=device,
        ))

    # ---------- above the fold ----------

    hero = data["hero"]

    if not hero["h1InFold"]:

        issues.append(_issue(
            "Medium",
            "No Headline Above the Fold",
            "No visible H1 headline is on the first screen.",
            "Lead with a clear headline that states what the site offers.",
            device=device,
        ))

    if not hero["ctaInFold"]:

        issues.append(_issue(
            "Medium",
            "No Call to Action Above the Fold",
            "No prominent action button is visible without scrolling.",
            "Add a clear primary call to action in the hero section.",
            device=device,
        ))

    if desktop and not hero["mediaInFold"]:

        issues.append(_issue(
            "Low",
            "No Visual Above the Fold",
            "The first screen has no large image, video or graphic.",
            "Add a strong hero visual to communicate quality quickly.",
            device=device,
        ))

    if data["foldChars"] > 1200:

        issues.append(_issue(
            "Low",
            "Dense First Screen",
            f"~{data['foldChars']} characters of text compete on the first screen.",
            "Reduce copy above the fold; keep the key message short.",
            device=device,
        ))

    if data["textChars"] < 200:

        issues.append(_issue(
            "Medium",
            "Very Little Text Content",
            f"Only ~{data['textChars']} characters of visible text.",
            "Add meaningful content for visitors and search engines.",
            device=device,
        ))

    return issues


# ----------------------------------
# Entry point
# ----------------------------------

def run_visual_audit(page, screenshot_manager):

    issues = []

    for device, size in VIEWPORTS.items():

        page.set_viewport_size(size)
        reveal_content(page)

        try:

            data = inspect_page(page)

        except Exception as error:

            print(f"[Visual Error] {device}: {error}")
            continue

        issues.extend(_rules(data, device))

        pixel_issues, _ = _screenshot_checks(
            page,
            screenshot_manager,
            device,
        )

        issues.extend(pixel_issues)

    page.set_viewport_size(VIEWPORTS["desktop"])
    page.evaluate("window.scrollTo(0, 0)")

    return issues
