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

            info=score.info,

            total_issues=score.total_issues,

            raw_issues=score.raw_issues,

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

            ["Info", model.info],

            ["Unique Findings", model.total_issues],

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

                    f"{escape(category.name)}: {category.score:.1f}/100",

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
        
            story.append(
                Spacer(
                    1,
                    0.10 * inch,
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
                        f"<b>Severity:</b> {escape(issue.severity)}",
                        BODY,
                    )
                )
        
                story.append(
                    Paragraph(
                        f"<b>Category:</b> {escape(issue.category)}",
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

                if getattr(issue, "verification", ""):

                    story.append(
                        Paragraph(
                            f"<b>Verification:</b> {escape(issue.verification)}",
                            SMALL,
                        )
                    )

                if getattr(issue, "occurrences", 0):

                    story.append(
                        Paragraph(
                            f"<b>Occurrences:</b> {issue.occurrences}",
                            SMALL,
                        )
                    )

                affected_items = getattr(
                    issue,
                    "affected_items",
                    [],
                )

                if affected_items:

                    story.append(
                        Paragraph(
                            f"<b>Affected Items:</b> {escape(', '.join(affected_items))}",
                            SMALL,
                        )
                    )

                if getattr(issue, "endpoint", ""):
        
                    story.append(
                        Paragraph(
                            f"<b>Endpoint:</b> {escape(issue.endpoint)}",
                            SMALL,
                        )
                    )
        
                if getattr(issue, "parameter", ""):

                    story.append(
                        Paragraph(
                            f"<b>Parameter:</b> {escape(issue.parameter)}",
                            SMALL,
                        )
                    )

                if getattr(issue, "page", ""):

                    story.append(
                        Paragraph(
                            f"<b>Page:</b> {escape(issue.page)}",
                            SMALL,
                        )
                    )

                if getattr(issue, "selector", ""):

                    story.append(
                        Paragraph(
                            f"<b>Selector:</b> {escape(issue.selector)}",
                            SMALL,
                        )
                    )
        
                if getattr(issue, "payload", ""):
        
                    story.append(
                        Paragraph(
                            f"<b>Payload:</b> {escape(issue.payload)}",
                            SMALL,
                        )
                    )
        
                if getattr(issue, "original_value", ""):
        
                    story.append(
                        Paragraph(
                            f"<b>Original Value:</b> {escape(issue.original_value)}",
                            SMALL,
                        )
                    )
        
                if getattr(issue, "modified_value", ""):
        
                    story.append(
                        Paragraph(
                            f"<b>Modified Value:</b> {escape(issue.modified_value)}",
                            SMALL,
                        )
                    )
        
                if getattr(issue, "response_code", None) is not None:

                    story.append(
                        Paragraph(
                            f"<b>Response Code:</b> {escape(str(issue.response_code))}",
                            SMALL,
                        )
                    )
        
                if getattr(issue, "response_time", None) is not None:
        
                    story.append(
                        Paragraph(
                            f"<b>Response Time:</b> {issue.response_time:.2f} ms",
                            SMALL,
                        )
                    )
        
                if getattr(issue, "impact", ""):
        
                    story.append(
                        Paragraph(
                            f"<b>Impact:</b> {escape(issue.impact)}",
                            SMALL,
                        )
                    )
        
                if getattr(issue, "confidence", ""):
        
                    story.append(
                        Paragraph(
                            f"<b>Confidence:</b> {escape(issue.confidence)}",
                            SMALL,
                        )
                    )
        
                if getattr(issue, "cwe", ""):
        
                    story.append(
                        Paragraph(
                            f"<b>CWE:</b> {escape(issue.cwe)}",
                            SMALL,
                        )
                    )
        
                if getattr(issue, "owasp", ""):
        
                    story.append(
                        Paragraph(
                            f"<b>OWASP:</b> {escape(issue.owasp)}",
                            SMALL,
                        )
                    )
        
                if getattr(issue, "fix_time", ""):
        
                    story.append(
                        Paragraph(
                            f"<b>Estimated Fix:</b> {escape(issue.fix_time)}",
                            SMALL,
                        )
                    )
        
                if getattr(issue, "notes", ""):

                    story.append(
                        Paragraph(
                            f"<b>Notes:</b> {escape(issue.notes)}",
                            SMALL,
                        )
                    )

                if getattr(issue, "screenshot", ""):

                    story.append(
                        Paragraph(
                            f"<b>Screenshot:</b> {escape(issue.screenshot)}",
                            SMALL,
                        )
                    )
        
                if issue.evidence:
        
                    story.append(
                        Paragraph(
                            f"<b>Evidence:</b><br/>{escape(issue.evidence)}",
                            SMALL,
                        )
                    )
        
                story.append(
                    Spacer(
                        1,
                        0.20 * inch,
                    )
                )
        
            story.append(
                Spacer(
                    1,
                    0.30 * inch,
                )
            )
        
        document.build(
            story
        )
        
        return str(output)
