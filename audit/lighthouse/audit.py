from audit.models import Issue

from .runner import LighthouseRunner
from .parser import parse_lighthouse


def score_severity(score: float):

    if score < 40:
        return "Critical"

    if score < 60:
        return "High"

    if score < 80:
        return "Medium"

    return "Low"


def metric_severity(name, value):

    limits = {

        "FCP": (1800, 3000),

        "LCP": (2500, 4000),

        "INP": (200, 500),

        "TBT": (200, 600),

        "CLS": (0.1, 0.25),

    }

    if name not in limits:
        return None

    good, poor = limits[name]

    if value <= good:
        return None

    if value >= poor:
        return "High"

    return "Medium"


def run_lighthouse_audit(url: str):

    runner = LighthouseRunner()

    raw = runner.run(url)

    report = parse_lighthouse(raw)

    issues = []

    # =====================================================
    # Lighthouse Scores
    # =====================================================

    for category in report.categories:

        if category.score >= 90:
            continue

        issues.append(

            Issue(

                category="Lighthouse",

                severity=score_severity(category.score),

                title=f"{category.title} Score",

                description=f"{category.title} score is {category.score:.0f}/100.",

                recommendation=f"Improve the {category.title.lower()} score.",

                evidence=f"{category.score:.0f}/100",

            )

        )

    # =====================================================
    # Core Web Vitals
    # =====================================================

    for metric in report.metrics:

        try:
            value = float(metric.value)

        except Exception:
            continue

        severity = metric_severity(
            metric.name,
            value,
        )

        if severity is None:
            continue

        issues.append(

            Issue(

                category="Performance",

                severity=severity,

                title=f"{metric.name} Needs Improvement",

                description=f"{metric.name} measured {value}{metric.unit}.",

                recommendation=f"Improve {metric.name} according to Google's Core Web Vitals guidance.",

                evidence=f"{value}{metric.unit}",

            )

        )

    # =====================================================
    # Lighthouse Opportunities
    # =====================================================

    for opportunity in sorted(

        report.opportunities,

        key=lambda x: x["score"]

    )[:10]:

        score = opportunity["score"]

        if score < 0.50:
            severity = "High"

        elif score < 0.75:
            severity = "Medium"

        else:
            severity = "Low"

        issues.append(

            Issue(

                category="Performance",

                severity=severity,

                title=opportunity["title"],

                description=opportunity["description"],

                recommendation="Apply Lighthouse recommendation.",

                evidence=opportunity["display"],

            )

        )

    return issues