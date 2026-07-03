from audit.models import Issue

from .runner import LighthouseRunner
from .parser import parse_lighthouse


def run_lighthouse_audit(url: str):

    runner = LighthouseRunner()

    raw = runner.run(url)

    report = parse_lighthouse(raw)

    issues = []

    # ----------------------------------------
    # Overall Scores
    # ----------------------------------------

    for category in report.categories:

        if category.score >= 90:
            continue

        severity = "Low"

        if category.score < 50:
            severity = "High"
        elif category.score < 75:
            severity = "Medium"

        issues.append(
            Issue(
                category="Lighthouse",
                severity=severity,
                title=f"{category.title} Score",
                description=f"{category.title} score is {category.score:.0f}/100.",
                recommendation=f"Improve the {category.title.lower()} score.",
                evidence=f"Score: {category.score:.0f}/100",
            )
        )

    # ----------------------------------------
    # Core Web Vitals
    # ----------------------------------------

    thresholds = {
        "FCP": 1800,
        "LCP": 2500,
        "INP": 200,
        "TBT": 200,
        "CLS": 0.1,
    }

    for metric in report.metrics:

        if metric.name not in thresholds:
            continue

        try:
            value = float(metric.value)
        except Exception:
            continue

        if value <= thresholds[metric.name]:
            continue

        issues.append(
            Issue(
                category="Performance",
                severity="Medium",
                title=f"High {metric.name}",
                description=f"{metric.name} is {value}{metric.unit}.",
                recommendation=f"Reduce {metric.name} to improve performance.",
                evidence=f"{metric.name}: {value}{metric.unit}",
            )
        )

    # ----------------------------------------
    # Opportunities
    # ----------------------------------------

    for opportunity in report.opportunities[:10]:

        issues.append(
            Issue(
                category="Performance",
                severity="Low",
                title=opportunity["title"],
                description=opportunity["description"],
                recommendation="Follow Lighthouse recommendation.",
                evidence=opportunity["display"],
            )
        )

    return issues