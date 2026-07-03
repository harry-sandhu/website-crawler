from audit.models import Issue

from .runner import AccessibilityRunner
from .parser import parse_accessibility


IMPACT_TO_SEVERITY = {
    "critical": "Critical",
    "serious": "High",
    "moderate": "Medium",
    "minor": "Low",
}


def run_accessibility_audit(page):

    runner = AccessibilityRunner()

    raw = runner.run(page)

    report = parse_accessibility(raw)

    issues = []

    # ----------------------------------------
    # Accessibility Violations
    # ----------------------------------------

    for violation in report.violations:

        severity = IMPACT_TO_SEVERITY.get(
            violation.impact,
            "Low",
        )

        evidence = []

        for node in violation.nodes[:10]:

            targets = node.get("target", [])

            if targets:

                evidence.append(
                    targets[0]
                )

        issues.append(

            Issue(

                category="Accessibility",

                severity=severity,

                title=violation.help,

                description=violation.description,

                recommendation=(
                    "Follow the WCAG guidance for this accessibility issue."
                ),

                evidence="\n".join(evidence),

                page="/",

            )

        )

    return issues