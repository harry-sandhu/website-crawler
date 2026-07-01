import re

from bs4 import BeautifulSoup


def collect_page_data(page):
    html = page.content()
    soup = BeautifulSoup(html, "lxml")

    data = {
        "title": page.title(),
        "url": page.url,
        "html": html,
        "soup": soup,

        "meta": {},
        "images": [],
        "links": [],
        "forms": [],
        "buttons": [],
        "scripts": [],
        "stylesheets": [],
        "headings": {},

        "favicon": None,
        "canonical": None,
        "viewport": None,
        "lang": None,

        "emails": [],
        "phones": [],

        "schema": [],
    }

    # ---------------- Meta ---------------- #

    for tag in soup.find_all("meta"):
        if tag.get("name"):
            data["meta"][tag["name"].lower()] = tag.get("content", "")

        if tag.get("property"):
            data["meta"][tag["property"]] = tag.get("content", "")

    # ---------------- HTML ---------------- #

    html_tag = soup.find("html")
    if html_tag:
        data["lang"] = html_tag.get("lang")

    # ---------------- Canonical ---------------- #

    canonical = soup.find("link", rel="canonical")
    if canonical:
        data["canonical"] = canonical.get("href")

    # ---------------- Viewport ---------------- #

    viewport = soup.find("meta", attrs={"name": "viewport"})
    if viewport:
        data["viewport"] = viewport.get("content")

    # ---------------- Favicon ---------------- #

    icon = soup.find(
        "link",
        rel=lambda value: value and "icon" in value.lower()
    )

    if icon:
        data["favicon"] = icon.get("href")

    # ---------------- Images ---------------- #

    for img in soup.find_all("img"):
        data["images"].append({
            "src": img.get("src"),
            "alt": img.get("alt"),
            "loading": img.get("loading"),
            "width": img.get("width"),
            "height": img.get("height"),
        })

    # ---------------- Links ---------------- #

    for link in soup.find_all("a"):
        href = link.get("href")

        data["links"].append({
            "href": href,
            "text": link.get_text(strip=True)
        })

        # Collect emails
        if href and href.startswith("mailto:"):
            data["emails"].append(
                href.replace("mailto:", "")
            )

        # Collect phone numbers
        if href and href.startswith("tel:"):
            data["phones"].append(
                href.replace("tel:", "")
            )

    # ---------------- Text Emails ---------------- #

    emails = set(data["emails"])

    for text in soup.stripped_strings:
        found = re.findall(
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
            text,
        )

        emails.update(found)

    data["emails"] = sorted(emails)

    # Remove duplicate phones
    data["phones"] = sorted(set(data["phones"]))

    # ---------------- Forms ---------------- #

    for form in soup.find_all("form"):
        data["forms"].append({
            "action": form.get("action"),
            "method": form.get("method"),
        })

    # ---------------- Buttons ---------------- #

    for button in soup.find_all("button"):
        data["buttons"].append(
            button.get_text(strip=True)
        )

    # ---------------- Scripts ---------------- #

    for script in soup.find_all("script"):
        if script.get("src"):
            data["scripts"].append(script["src"])

        if script.get("type") == "application/ld+json":
            if script.string:
                data["schema"].append(script.string)

    # ---------------- Stylesheets ---------------- #

    for css in soup.find_all("link", rel="stylesheet"):
        data["stylesheets"].append(
            css.get("href")
        )

    # ---------------- Headings ---------------- #

    for i in range(1, 7):
        tag = f"h{i}"

        data["headings"][tag] = [
            heading.get_text(strip=True)
            for heading in soup.find_all(tag)
        ]

    return data