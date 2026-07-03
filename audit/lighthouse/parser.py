from .models import (
    LighthouseAudit,
    LighthouseCategory,
    LighthouseMetric,
)


METRICS = {
    "first-contentful-paint": ("FCP", "ms"),
    "largest-contentful-paint": ("LCP", "ms"),
    "interactive": ("TTI", "ms"),
    "speed-index": ("Speed Index", "ms"),
    "total-blocking-time": ("TBT", "ms"),
    "cumulative-layout-shift": ("CLS", ""),
    "interaction-to-next-paint": ("INP", "ms"),
}


def parse_lighthouse(data):

    report = LighthouseAudit()

    # ----------------------------------
    # Categories
    # ----------------------------------

    for key, category in data.get("categories", {}).items():

        report.categories.append(

            LighthouseCategory(
                id=key,
                title=category.get("title", key),
                score=(category.get("score") or 0) * 100,
            )

        )

    # ----------------------------------
    # Core Web Vitals
    # ----------------------------------

    audits = data.get("audits", {})

    for audit_id, (name, unit) in METRICS.items():

        audit = audits.get(audit_id)

        if not audit:
            continue

        report.metrics.append(

            LighthouseMetric(
                name=name,
                value=audit.get("numericValue", audit.get("displayValue", "")),
                unit=unit,
            )

        )

    # ----------------------------------
    # Opportunities
    # ----------------------------------

    for audit in audits.values():

        if audit.get("scoreDisplayMode") != "numeric":
            continue

        score = audit.get("score")

        if score is None:
            continue

        if score >= 0.9:
            continue

        report.opportunities.append({

            "title": audit.get("title"),

            "description": audit.get("description"),

            "score": score,

            "display": audit.get("displayValue", ""),

        })

    # ----------------------------------
    # Diagnostics
    # ----------------------------------

    diagnostics = [

        "network-requests",
        "diagnostics",
        "resource-summary",
    ]

    for key in diagnostics:

        audit = audits.get(key)

        if audit:

            report.diagnostics.append(audit)

    return report