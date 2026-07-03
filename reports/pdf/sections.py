from .models import PDFSection


class PDFSectionBuilder:

    @staticmethod
    def build(report):

        grouped = {}

        for issue in report.issues:

            grouped.setdefault(
                issue.category,
                [],
            ).append(issue)

        sections = []

        for category, issues in grouped.items():

            sections.append(

                PDFSection(

                    title=category,

                    issues=issues,

                )

            )

        return sections