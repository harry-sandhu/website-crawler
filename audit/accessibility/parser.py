from .models import (
    AccessibilitySummary,
    AccessibilityViolation,
)


def parse_accessibility(data):

    report = AccessibilitySummary()

    report.passes = len(
        data.get("passes", [])
    )

    report.incomplete = len(
        data.get("incomplete", [])
    )

    report.inapplicable = len(
        data.get("inapplicable", [])
    )

    # ---------------------------------------
    # Violations
    # ---------------------------------------

    for violation in data.get("violations", []):

        report.violations.append(

            AccessibilityViolation(

                id=violation.get("id", ""),

                impact=violation.get(
                    "impact",
                    "minor",
                ),

                description=violation.get(
                    "description",
                    "",
                ),

                help=violation.get(
                    "help",
                    "",
                ),

                help_url=violation.get(
                    "helpUrl",
                    "",
                ),

                nodes=violation.get(
                    "nodes",
                    [],
                ),

            )

        )

    return report