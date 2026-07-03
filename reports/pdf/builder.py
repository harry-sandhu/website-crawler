from xml.sax.saxutils import escape

from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from reportlab.lib import colors
from reportlab.lib.units import inch

from .models import PDFReportModel
from .sections import PDFSectionBuilder
from .styles import (
    TITLE,
    HEADING,
    BODY,
    SMALL,
)


class PDFReportBuilder:

    def __init__(self):

        self.output_root = Path(
            "output"
        )
    
        self.output_root.mkdir(
            parents=True,
            exist_ok=True,
        )


    # ----------------------------------

    def prepare_output(
        self,
        url: str,
    ):
    
        domain = (
            urlparse(url)
            .netloc
            .replace("www.", "")
            .replace(":", "_")
        )
    
        root = (
            self.output_root
            / domain
        )
    
        root.mkdir(
            parents=True,
            exist_ok=True,
        )
    
        return root

    # ----------------------------------

    def build(
        self,
        website,
        report,
        score,
    ):

        model = PDFReportModel(

            url=website.url,

            title=website.title,

            generated_at=datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

            overall_score=score.overall,

            category_scores=score.categories,

            critical=score.critical,

            high=score.high,

            medium=score.medium,

            low=score.low,

            total_issues=score.total_issues,

            browser=website.browser,

            page=website.page,

            screenshots=website.screenshots,

            sections=PDFSectionBuilder.build(
                report
            ),

        )

        root = self.prepare_output(
    website.url
)

        output = (
            root
            / "report.pdf"
        )

        document = SimpleDocTemplate(
            str(output),
        )

        story = []

        # ----------------------------------
        # Title
        # ----------------------------------

        story.append(
            Paragraph(
                "Website Audit Report",
                TITLE,
            )
        )

        story.append(
            Paragraph(
                escape(model.title),
                HEADING,
            )
        )

        story.append(
            Paragraph(
                escape(model.url),
                BODY,
            )
        )

        story.append(
            Paragraph(
                f"Generated: {model.generated_at}",
                SMALL,
            )
        )

        story.append(
            Spacer(
                1,
                0.3 * inch,
            )
        )

        # ----------------------------------
        # Summary
        # ----------------------------------

        summary = [

            ["Overall Score", f"{model.overall_score:.1f}/100"],

            ["Critical", model.critical],

            ["High", model.high],

            ["Medium", model.medium],

            ["Low", model.low],

            ["Total Issues", model.total_issues],

        ]

        table = Table(summary)

        table.setStyle(

            TableStyle([

                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),

                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),

                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),

            ])

        )

        story.append(table)

        story.append(
            Spacer(
                1,
                0.3 * inch,
            )
        )

        # ----------------------------------
        # Category Scores
        # ----------------------------------

        story.append(
            Paragraph(
                "Category Scores",
                HEADING,
            )
        )

        for category in model.category_scores:

            story.append(

                Paragraph(

                    f"{category.name}: {category.score:.1f}/100",

                    BODY,

                )

            )

        story.append(
            Spacer(
                1,
                0.3 * inch,
            )
        )

        # ----------------------------------
        # Issues
        # ----------------------------------

        for section in model.sections:

            story.append(

                Paragraph(

                    escape(section.title),

                    HEADING,

                )

            )

            for issue in section.issues:

                story.append(

                    Paragraph(

                        f"<b>{escape(issue.title)}</b>",

                        BODY,

                    )

                )

                story.append(

                    Paragraph(

                       escape(issue.description),

                        BODY,

                    )

                )

                story.append(

                    Paragraph(

                        f"<b>Recommendation:</b> {escape(issue.recommendation)}",

                        BODY,

                    )

                )

                if issue.evidence:

                    story.append(

                        Paragraph(

                             f"<b>Evidence:</b> {escape(issue.evidence)}",

                            SMALL,

                        )

                    )

                story.append(
                    Spacer(
                        1,
                        0.15 * inch,
                    )
                )

        document.build(
            story
        )

        return str(output)