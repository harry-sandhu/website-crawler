from collections import defaultdict

from .models import ReportSection


class SectionBuilder:

    CATEGORY_ORDER = [

        "SEO",

        "Performance",

        "Accessibility",

        "Responsive",

        "Security",

        "Network",

        "Console",

        "Lighthouse",

    ]

    @classmethod
    def build(cls, report):

        grouped = defaultdict(list)

        # ----------------------------------
        # Group Issues
        # ----------------------------------

        for issue in report.issues:

            grouped[issue.category].append(issue)

        sections = []

        # ----------------------------------
        # Ordered Categories
        # ----------------------------------

        for category in cls.CATEGORY_ORDER:

            if category not in grouped:
                continue

            issues = sorted(

                grouped[category],

                key=lambda issue: cls.severity_value(
                    issue.severity
                ),

            )

            sections.append(

                ReportSection(

                    title=category,

                    issues=issues,

                )

            )

        # ----------------------------------
        # Any Remaining Categories
        # ----------------------------------

        for category in sorted(grouped):

            if category in cls.CATEGORY_ORDER:
                continue

            sections.append(

                ReportSection(

                    title=category,

                    issues=sorted(

                        grouped[category],

                        key=lambda issue: cls.severity_value(
                            issue.severity
                        ),

                    ),

                )

            )

        return sections

    @staticmethod
    def severity_value(severity):

        order = {

            "Critical": 0,

            "High": 1,

            "Medium": 2,

            "Low": 3,

        }

        return order.get(
            severity,
            99,
        )