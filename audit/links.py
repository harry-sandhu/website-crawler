import uuid
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urldefrag, urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from audit.models import Issue

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; WebsiteAuditor/2.0)"}
TIMEOUT = 12
MAX_LINKS = 150
SKIP_EXTENSIONS = (
    ".pdf", ".zip", ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg",
    ".mp4", ".mp3", ".doc", ".docx", ".xls", ".xlsx", ".css", ".js",
)
# Hosts that block bots, so failures there are not meaningful.
BOT_BLOCKERS = (
    "linkedin.com", "facebook.com", "instagram.com", "twitter.com",
    "x.com", "tiktok.com", "google.com", "youtube.com",
)


def _issue(category, severity, title, description, recommendation, evidence="", items=None):

    return Issue(
        category=category,
        severity=severity,
        title=title,
        description=description,
        recommendation=recommendation,
        evidence=evidence,
        affected_items=items or [],
        confidence="High",
        verification_method="HTTP request verification",
    )


def _check(url):

    try:

        response = requests.get(
            url,
            headers=HEADERS,
            timeout=TIMEOUT,
            allow_redirects=True,
            stream=True,
        )

        response.close()

        return {
            "url": url,
            "status": response.status_code,
            "hops": len(response.history),
            "final": response.url,
            "chain": [r.url for r in response.history] + [response.url],
        }

    except requests.RequestException as error:

        return {
            "url": url,
            "status": None,
            "error": type(error).__name__,
            "hops": 0,
            "chain": [],
        }


# ----------------------------------
# Link checks
# ----------------------------------

def _audit_links(website):

    issues = []

    base = website.url
    host = urlparse(base).netloc

    resolved = {}
    empty = []
    unsafe_blank = []
    insecure = []

    soup = website.page["soup"]

    for a in soup.find_all("a"):

        href = (a.get("href") or "").strip()
        text = a.get_text(strip=True) or a.get("aria-label") or ""

        if href in ("", "#") or href.lower().startswith("javascript:"):

            if len(empty) < 15:
                empty.append(text[:40] or "(no text)")

            continue

        if href.startswith(("mailto:", "tel:", "sms:", "whatsapp:")):
            continue

        url = urldefrag(urljoin(base, href))[0]

        if not url.startswith("http"):
            continue

        resolved.setdefault(url, text)

        if (
            a.get("target") == "_blank"
            and urlparse(url).netloc != host
            and "noopener" not in (a.get("rel") or [])
            and "noreferrer" not in (a.get("rel") or [])
        ):
            unsafe_blank.append(url)

        if base.startswith("https://") and url.startswith("http://"):
            insecure.append(url)

    if empty:

        issues.append(_issue(
            "Links", "Low",
            "Dead Links (Empty or Script-Only href)",
            f"{len(empty)} links use an empty, # or javascript: href and go nowhere.",
            "Link to a real URL or use a <button> for in-page actions.",
            evidence="\n".join(empty),
        ))

    if insecure:

        issues.append(_issue(
            "Links", "Medium",
            "Links to Insecure HTTP Pages",
            f"{len(insecure)} links use http:// on an https site.",
            "Update the links to https://.",
            evidence="\n".join(insecure[:10]),
            items=insecure[:10],
        ))

    if unsafe_blank:

        issues.append(_issue(
            "Links", "Low",
            "External Links Missing rel=noopener",
            f"{len(unsafe_blank)} target=_blank links lack rel=noopener.",
            'Add rel="noopener noreferrer" to external new-tab links.',
            evidence="\n".join(unsafe_blank[:10]),
        ))

    targets = list(resolved)[:MAX_LINKS]

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(_check, targets))

    broken_internal, broken_external, chains, unreachable = [], [], [], []

    for result in results:

        internal = urlparse(result["url"]).netloc == host
        status = result["status"]
        label = f"{status or result.get('error')} {result['url']}"

        if status is None:
            (broken_internal if internal else unreachable).append(label)

        elif status in (404, 410) or 500 <= status < 600:
            (broken_internal if internal else broken_external).append(label)

        elif status in (401, 403, 429, 999):
            if internal:
                broken_internal.append(label)

        if result["hops"] >= 3:
            chains.append(" -> ".join(result["chain"]))

    if broken_internal:

        issues.append(_issue(
            "Links", "High",
            "Broken Internal Links",
            f"{len(broken_internal)} internal links return errors.",
            "Fix or remove the links, or add redirects for moved pages.",
            evidence="\n".join(broken_internal[:15]),
            items=broken_internal[:15],
        ))

    broken_external = [
        b for b in broken_external
        if not any(h in b for h in BOT_BLOCKERS)
    ]

    if broken_external:

        issues.append(_issue(
            "Links", "Medium",
            "Broken External Links",
            f"{len(broken_external)} external links return errors.",
            "Update or remove dead outbound links.",
            evidence="\n".join(broken_external[:15]),
            items=broken_external[:15],
        ))

    if unreachable:

        issues.append(_issue(
            "Links", "Low",
            "Unreachable External Links",
            f"{len(unreachable)} external links could not be reached.",
            "Verify these destinations still exist.",
            evidence="\n".join(unreachable[:10]),
        ))

    if chains:

        issues.append(_issue(
            "Links", "Low",
            "Long Redirect Chains",
            f"{len(chains)} links go through 3+ redirects.",
            "Link directly to the final URL.",
            evidence="\n".join(chains[:5]),
        ))

    return issues, [
        r["url"] for r in results
        if urlparse(r["url"]).netloc == host
        and r["status"] == 200
        and not urlparse(r["url"]).path.lower().endswith(SKIP_EXTENSIONS)
    ]


# ----------------------------------
# Site wide pages
# ----------------------------------

def _page_facts(url):

    try:

        response = requests.get(url, headers=HEADERS, timeout=TIMEOUT)

    except requests.RequestException:
        return None

    if "html" not in response.headers.get("content-type", ""):
        return None

    soup = BeautifulSoup(response.text, "lxml")

    title = soup.title.get_text(strip=True) if soup.title else ""
    desc = soup.find("meta", attrs={"name": "description"})
    robots = soup.find("meta", attrs={"name": "robots"})

    return {
        "url": url,
        "title": title,
        "description": (desc.get("content") or "").strip() if desc else "",
        "h1": len(soup.find_all("h1")),
        "noindex": bool(robots and "noindex" in (robots.get("content") or "").lower()),
        "words": len(soup.get_text(" ", strip=True).split()),
    }


def _audit_site(candidates, max_pages):

    issues = []

    pages = []

    with ThreadPoolExecutor(max_workers=8) as pool:
        pages = [p for p in pool.map(_page_facts, candidates[:max_pages]) if p]

    if len(pages) < 2:
        return issues

    def group(key):

        groups = defaultdict(list)

        for page in pages:
            if page[key]:
                groups[page[key].lower()].append(page["url"])

        return {k: v for k, v in groups.items() if len(v) > 1}

    for key, label in (("title", "Titles"), ("description", "Meta Descriptions")):

        dupes = group(key)

        if dupes:

            issues.append(_issue(
                "SEO", "Medium",
                f"Duplicate Page {label}",
                f"{sum(len(v) for v in dupes.values())} pages share "
                f"{len(dupes)} duplicated {label.lower()}.",
                f"Give every page a unique {label.lower().rstrip('s')}.",
                evidence="\n".join(
                    f"'{k[:60]}' -> {', '.join(v[:3])}" for k, v in list(dupes.items())[:5]
                ),
            ))

    checks = (
        ("Pages Missing Title", [p for p in pages if not p["title"]], "High"),
        ("Pages Missing Meta Description", [p for p in pages if not p["description"]], "Medium"),
        ("Pages Missing H1", [p for p in pages if not p["h1"]], "Low"),
        ("Pages Marked noindex", [p for p in pages if p["noindex"]], "Medium"),
        ("Thin Content Pages", [p for p in pages if p["words"] < 150], "Low"),
    )

    for title, found, severity in checks:

        if found:

            issues.append(_issue(
                "SEO", severity,
                title,
                f"{len(found)} of {len(pages)} crawled pages: {title.lower()}.",
                "Review and fix these pages.",
                evidence="\n".join(p["url"] for p in found[:10]),
                items=[p["url"] for p in found[:10]],
            ))

    return issues


def _audit_404(website):

    probe = urljoin(website.url, f"/{uuid.uuid4().hex}-audit-404-check")

    try:
        response = requests.get(probe, headers=HEADERS, timeout=TIMEOUT)
    except requests.RequestException:
        return []

    if response.status_code == 200:

        return [_issue(
            "SEO", "Medium",
            "Soft 404 Pages",
            "Non-existent URLs return HTTP 200 instead of 404.",
            "Return a real 404 status for missing pages so search engines "
            "do not index junk URLs.",
            evidence=probe,
        )]

    if response.status_code == 404 and len(response.text) < 600:

        return [_issue(
            "Usability", "Low",
            "Bare 404 Page",
            "The 404 page is almost empty.",
            "Design a helpful 404 page with navigation and search.",
            evidence=probe,
        )]

    return []


# ----------------------------------
# Entry point
# ----------------------------------

def run_links_audit(website, max_pages=25):

    issues, internal_ok = _audit_links(website)

    issues.extend(_audit_404(website))

    if max_pages > 1:

        seen = {website.url}
        candidates = [website.url]

        for url in internal_ok:
            if url not in seen:
                seen.add(url)
                candidates.append(url)

        issues.extend(_audit_site(candidates, max_pages))

    return issues
