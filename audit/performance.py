from urllib.parse import urlparse

from audit.models import Issue

CATEGORY = "Performance"

VITALS_JS = r"""
() => new Promise((resolve) => {
  const out = { lcp: null, cls: 0, fcp: null, ttfb: null, longTasks: 0, tbt: 0,
                dom: document.getElementsByTagName("*").length, dcl: null, load: null };

  const nav = performance.getEntriesByType("navigation")[0];
  if (nav) {
    out.ttfb = nav.responseStart;
    out.dcl = nav.domContentLoadedEventEnd;
    out.load = nav.loadEventEnd;
  }

  const paint = performance.getEntriesByName("first-contentful-paint")[0];
  if (paint) out.fcp = paint.startTime;

  const observe = (type, fn) => {
    try {
      new PerformanceObserver((list) => list.getEntries().forEach(fn))
        .observe({ type, buffered: true });
    } catch (e) {}
  };

  observe("largest-contentful-paint", (e) => { out.lcp = e.startTime; });
  observe("layout-shift", (e) => { if (!e.hadRecentInput) out.cls += e.value; });
  observe("longtask", (e) => { out.longTasks++; out.tbt += Math.max(0, e.duration - 50); });

  const blocking = [...document.querySelectorAll("head script[src]:not([async]):not([defer]):not([type=module])")]
    .map((s) => s.src);
  out.blockingScripts = blocking;
  out.blockingStyles = document.querySelectorAll("head link[rel=stylesheet]").length;

  setTimeout(() => resolve(out), 600);
})
"""

TEXT_TYPES = (
    "text/html", "text/css", "javascript", "json", "xml", "svg", "text/plain",
)


def _issue(severity, title, description, recommendation, evidence=""):

    return Issue(
        category=CATEGORY,
        severity=severity,
        title=title,
        description=description,
        recommendation=recommendation,
        evidence=evidence,
        confidence="High",
        verification_method="Browser performance timeline",
    )


def _size(response):

    try:
        return int(response["headers"].get("content-length", 0))
    except (TypeError, ValueError):
        return 0


def run_performance_audit(website):

    issues = []
    page = website.page_object

    vitals = page.evaluate(VITALS_JS)

    # ---------- Core Web Vitals ----------

    lcp = vitals.get("lcp")

    if lcp:

        if lcp > 4000:
            sev = "High"
        elif lcp > 2500:
            sev = "Medium"
        else:
            sev = None

        if sev:
            issues.append(_issue(
                sev,
                "Slow Largest Contentful Paint",
                f"LCP is {lcp / 1000:.1f}s (good is under 2.5s).",
                "Optimise the hero image/text: compress, preload, "
                "serve from a CDN and remove render-blocking resources.",
            ))

    cls = vitals.get("cls", 0)

    if cls > 0.1:

        issues.append(_issue(
            "High" if cls > 0.25 else "Medium",
            "Layout Shifts During Load",
            f"Cumulative Layout Shift is {cls:.2f} (good is under 0.1).",
            "Reserve space for images, embeds and ads with width/height "
            "or aspect-ratio; avoid injecting content above existing content.",
        ))

    ttfb = vitals.get("ttfb")

    if ttfb and ttfb > 800:

        issues.append(_issue(
            "High" if ttfb > 1800 else "Medium",
            "Slow Server Response",
            f"Time to first byte is {ttfb:.0f}ms (good is under 800ms).",
            "Add server caching, a CDN, or faster hosting.",
        ))

    fcp = vitals.get("fcp")

    if fcp and fcp > 1800:

        issues.append(_issue(
            "High" if fcp > 3000 else "Medium",
            "Slow First Contentful Paint",
            f"First paint of content takes {fcp / 1000:.1f}s.",
            "Inline critical CSS and defer non-critical scripts.",
        ))

    if vitals.get("tbt", 0) > 300:

        issues.append(_issue(
            "High" if vitals["tbt"] > 600 else "Medium",
            "Main Thread Blocked by JavaScript",
            f"~{vitals['tbt']:.0f}ms of blocking time across "
            f"{vitals['longTasks']} long tasks.",
            "Split bundles, defer third-party scripts and remove unused JS.",
        ))

    if vitals.get("dom", 0) > 1500:

        issues.append(_issue(
            "High" if vitals["dom"] > 3000 else "Low",
            "Large DOM",
            f"The page has {vitals['dom']} DOM elements.",
            "Simplify markup and lazy-render offscreen sections.",
        ))

    blocking = vitals.get("blockingScripts", [])

    if blocking:

        issues.append(_issue(
            "Medium" if len(blocking) > 2 else "Low",
            "Render-Blocking Scripts",
            f"{len(blocking)} scripts in <head> have no async/defer.",
            "Add defer or async to scripts that do not need to run first.",
            evidence="\n".join(blocking[:8]),
        ))

    # ---------- Page weight ----------

    responses = website.browser.get("responses", [])

    total = sum(_size(r) for r in responses)
    count = len(responses)

    if total > 3 * 1024 * 1024:

        issues.append(_issue(
            "High" if total > 6 * 1024 * 1024 else "Medium",
            "Heavy Page Weight",
            f"Page transfers about {total / 1024 / 1024:.1f}MB "
            f"over {count} requests.",
            "Compress images, drop unused libraries and lazy-load media.",
        ))

    if count > 100:

        issues.append(_issue(
            "Medium" if count > 150 else "Low",
            "Too Many Requests",
            f"{count} network requests were made.",
            "Bundle assets and remove unnecessary third-party tags.",
        ))

    # ---------- Compression / caching ----------

    uncompressed = []
    uncached = []

    for r in responses:

        headers = {k.lower(): v for k, v in r["headers"].items()}
        ctype = r.get("content_type", "").lower()
        url = r["url"]

        if not url.startswith("http") or r["status"] != 200:
            continue

        is_text = any(t in ctype for t in TEXT_TYPES)
        is_big = _size(r) > 2048 or r.get("body_length", 0) > 4096

        if is_text and is_big and not headers.get("content-encoding"):
            uncompressed.append(url)

        is_static = any(
            ctype.startswith(t) or t in ctype
            for t in ("image/", "font", "text/css", "javascript")
        )

        if is_static and urlparse(url).netloc == urlparse(website.url).netloc:

            cache = headers.get("cache-control", "")

            if not cache or "no-store" in cache or "max-age=0" in cache:
                uncached.append(url)

    if uncompressed:

        issues.append(_issue(
            "Medium",
            "Text Resources Not Compressed",
            f"{len(uncompressed)} text resources are served without gzip/brotli.",
            "Enable Brotli or gzip compression on the server/CDN.",
            evidence="\n".join(uncompressed[:8]),
        ))

    if len(uncached) > 3:

        issues.append(_issue(
            "Medium",
            "Static Assets Not Cached",
            f"{len(uncached)} same-origin static files have no long-lived "
            "cache headers.",
            "Set Cache-Control: public, max-age=31536000, immutable on "
            "fingerprinted assets.",
            evidence="\n".join(uncached[:8]),
        ))

    return issues
