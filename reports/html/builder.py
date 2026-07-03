from pathlib import Path
from datetime import datetime

from .models import ReportModel
from .sections import SectionBuilder


class HTMLReportBuilder:

    def __init__(self):

        self.output_dir = Path("output/reports")
        self.output_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.template = (
            Path(__file__).parent
            / "templates"
            / "report.html"
        )

    def build(
        self,
        website,
        report,
        score,
    ):

        model = ReportModel(

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

            sections=SectionBuilder.build(
                report
            ),

        )

        html = self.render(model)

        output = (
            self.output_dir
            / "report.html"
        )

        output.write_text(
            html,
            encoding="utf-8",
        )

        return str(output)

    # ----------------------------------

    def render(
        self,
        model,
    ):

        html = self.template.read_text(
            encoding="utf-8"
        )

        html = html.replace(
            "{{TITLE}}",
            model.title,
        )

        html = html.replace(
            "{{URL}}",
            model.url,
        )

        html = html.replace(
            "{{DATE}}",
            model.generated_at,
        )

        html = html.replace(
            "{{OVERALL_SCORE}}",
            f"{model.overall_score:.1f}",
        )

        html = html.replace(
            "{{CRITICAL}}",
            str(model.critical),
        )

        html = html.replace(
            "{{HIGH}}",
            str(model.high),
        )

        html = html.replace(
            "{{MEDIUM}}",
            str(model.medium),
        )

        html = html.replace(
            "{{LOW}}",
            str(model.low),
        )

        html = html.replace(
            "{{TOTAL}}",
            str(model.total_issues),
        )

        html = html.replace(
            "{{CATEGORY_SCORES}}",
            self.render_scores(model),
        )

        html = html.replace(
            "{{SECTIONS}}",
            self.render_sections(model),
        )

        return html

    # ----------------------------------

    def render_scores(
        self,
        model,
    ):

        html = ""

        for category in model.category_scores:

            html += f"""
            <div class="score-card">

                <div>{category.name}</div>

                <div>{category.score:.1f}/100</div>

            </div>
            """

        return html

    # ----------------------------------

    def render_sections(
        self,
        model,
    ):

        html = ""

        for section in model.sections:

            html += f"<h2>{section.title}</h2>"

            for issue in section.issues:

                html += f"""
                <div class="issue {issue.severity.lower()}">

                    <h3>{issue.title}</h3>

                    <p><b>Severity:</b> {issue.severity}</p>

                    <p>{issue.description}</p>

                    <p><b>Recommendation:</b></p>

                    <p>{issue.recommendation}</p>
                """

                if issue.evidence:

                    html += f"""

                    <pre>{issue.evidence}</pre>

                    """

                html += "</div>"

        return html