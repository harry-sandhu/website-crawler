from .models import (
    LighthouseAudit,
    LighthouseCategory,
    LighthouseMetric,
)


# ==========================================
# Core Web Vitals
# ==========================================

METRICS = {
    "first-contentful-paint": ("FCP", "ms"),
    "largest-contentful-paint": ("LCP", "ms"),
    "interaction-to-next-paint": ("INP", "ms"),
    "total-blocking-time": ("TBT", "ms"),
    "cumulative-layout-shift": ("CLS", ""),
    "speed-index": ("Speed Index", "ms"),
}


# ==========================================
# Only keep useful Lighthouse opportunities
# ==========================================

IMPORTANT_AUDITS = {

    "render-blocking-resources",

    "unused-css-rules",

    "unused-javascript",

    "uses-optimized-images",

    "uses-responsive-images",

    "offscreen-images",

    "modern-image-formats",

    "uses-text-compression",

    "uses-long-cache-ttl",

    "server-response-time",

    "redirects",

    "legacy-javascript",

    "unminified-css",

    "unminified-javascript",

    "font-display",

    "uses-rel-preconnect",

    "uses-rel-preload",

    "network-dependency-tree",

    "dom-size",

    "third-party-summary",

}


def parse_lighthouse(data):

    report = LighthouseAudit()

    audits = data.get("audits", {})

    # ==========================================
    # Category Scores
    # ==========================================

    for key, category in data.get("categories", {}).items():

        report.categories.append(

            LighthouseCategory(

                id=key,

                title=category.get("title", key),

                score=round((category.get("score") or 0) * 100),

            )

        )

    # ==========================================
    # Metrics
    # ==========================================

    for audit_id, (name, unit) in METRICS.items():

        audit = audits.get(audit_id)

        if not audit:
            continue

        report.metrics.append(

            LighthouseMetric(

                name=name,

                value=audit.get(
                    "numericValue",
                    audit.get("displayValue", ""),
                ),

                unit=unit,

            )

        )

    # ==========================================
    # Opportunities
    # ==========================================

    for audit_id in IMPORTANT_AUDITS:

        audit = audits.get(audit_id)

        if not audit:
            continue

        score = audit.get("score")

        if score is None:
            continue

        if score >= 0.90:
            continue

        report.opportunities.append({

            "id": audit_id,

            "title": audit.get("title", audit_id),

            "description": audit.get("description", ""),

            "display": audit.get("displayValue", ""),

            "score": score,

            "details": audit.get("details"),

        })

    # ==========================================
    # Diagnostics (optional)
    # ==========================================

    for key in (

        "diagnostics",

        "resource-summary",

    ):

        audit = audits.get(key)

        if audit:

            report.diagnostics.append(audit)

    return report