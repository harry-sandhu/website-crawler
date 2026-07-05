from .models import PDFSection


class PDFSectionBuilder:

    CATEGORY_ORDER = [
        "Security",
        "Input Validation",
        "HTML Best Practices",
        "Accessibility",
        "SEO",
        "Performance",
        "Networking",
        "Authentication",
        "Business Logic",
        "Usability",
    ]

    @staticmethod
    def build(report):

        grouped = {}

        for issue in report.issues:

            grouped.setdefault(
                issue.category,
                [],
            ).append(issue)

        sections = []

        for category in PDFSectionBuilder.CATEGORY_ORDER:

            if category not in grouped:
                continue

            sections.append(

                PDFSection(

                    title=category,

                    issues=sorted(
                        grouped[category],
                        key=lambda issue: (
                            0 if issue.severity == "Critical" else 1 if issue.severity == "High" else 2 if issue.severity == "Medium" else 3 if issue.severity == "Low" else 4,
                            issue.title,
                        ),
                    ),

                )

            )

        for category in sorted(grouped):

            if category in PDFSectionBuilder.CATEGORY_ORDER:
                continue

            sections.append(

                PDFSection(

                    title=category,

                    issues=sorted(
                        grouped[category],
                        key=lambda issue: (
                            0 if issue.severity == "Critical" else 1 if issue.severity == "High" else 2 if issue.severity == "Medium" else 3 if issue.severity == "Low" else 4,
                            issue.title,
                        ),
                    ),

                )

            )

        return sections
