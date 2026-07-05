from pathlib import Path
from datetime import datetime
from html import escape

from .models import ReportModel
from .sections import SectionBuilder

from urllib.parse import urlparse

import shutil



class HTMLReportBuilder:

    def __init__(self):

        self.template = (
            Path(__file__).parent
            / "templates"
            / "report.html"
        )
    
        self.assets_source = (
            Path(__file__).parent
            / "assets"
        )
    
        self.output_root = Path("output")
    
        self.output_root.mkdir(
            parents=True,
            exist_ok=True,
        )

    def prepare_output(
        self,
        url: str,
    ):
    
        domain = (
            urlparse(url)
            .netloc
            .replace(":", "_")
        )
    
        root = (
            self.output_root
            / domain
        )
    
        assets = root / "assets"
    
        screenshots = root / "screenshots"
    
        data = root / "data"
    
        root.mkdir(
            parents=True,
            exist_ok=True,
        )
    
        assets.mkdir(
            exist_ok=True,
        )
    
        screenshots.mkdir(
            exist_ok=True,
        )
    
        data.mkdir(
            exist_ok=True,
        )
    
        return {
    
            "root": root,
    
            "assets": assets,
    
            "screenshots": screenshots,
    
            "data": data,
    
        }   

    def copy_assets(
        self,
        output,
    ):
    
        assets = (
    
            "style.css",
    
            "app.js",
    
            "logo.png",
    
        )
    
        for asset in assets:
    
            source = (
                self.assets_source
                / asset
            )
    
            if not source.is_file():
    
                print(
                    f"[Warning] Missing asset: {source}"
                )
    
                continue
    
            destination = (
                output["assets"]
                / asset
            )
    
            shutil.copy2(
                source,
                destination,
            )

    def copy_screenshots(
        self,
        screenshots,
        output,
    ):
    
        for device, files in screenshots.items():
    
            for key in ("normal", "full"):
    
                path = files.get(key)
    
                if not path:
                    continue
    
                source = Path(path)
    
                if not source.is_file():
    
                    print(
                        f"[Warning] Missing screenshot: {source}"
                    )
    
                    continue
    
                destination = (
                    output["screenshots"]
                    / source.name
                )
    
                shutil.copy2(
                    source,
                    destination,
                )
    
    # ----------------------------------
    
    def build(
        self,
        website,
        report,
        score,
    ):
    
        # ----------------------------------
        # Prepare Output Folder
        # ----------------------------------
    
        output = self.prepare_output(
            website.url
        )
    
        self.copy_assets(
            output
        )
    
        self.copy_screenshots(
            website.screenshots,
            output,
        )
    
        # ----------------------------------
        # Screenshot Paths
        # ----------------------------------
    
        screenshots = {}
    
        for device, files in website.screenshots.items():
    
            screenshots[device] = {}
    
            for key in ("normal", "full"):
    
                path = files.get(key)
    
                if not path:
                    continue
    
                screenshots[device][key] = (
                    "screenshots/"
                    + Path(path).name
                )
    
        # ----------------------------------
        # Report Model
        # ----------------------------------
    
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

            info=score.info,

            total_issues=score.total_issues,

            raw_issues=score.raw_issues,

            browser=website.browser,
    
            page=website.page,
    
            screenshots=screenshots,
    
            sections=SectionBuilder.build(
                report
            ),
    
        )
    
        # ----------------------------------
        # Generate HTML
        # ----------------------------------
    
        html = self.render(
            model
        )
    
        report_path = (
            output["root"]
            / "report.html"
        )
    
        report_path.write_text(
            html,
            encoding="utf-8",
        )
    
        return str(
            report_path
        )
    # ----------------------------------
    
    
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
            "{{INFO}}",
            str(model.info),
        )

        html = html.replace(
            "{{TOTAL}}",
            str(model.total_issues),
        )

        html = html.replace(
            "{{RAW}}",
            str(model.raw_issues),
        )
    
        html = html.replace(
            "{{DESKTOP}}",
            model.screenshots["desktop"]["normal"],
        )
    
        html = html.replace(
            "{{DESKTOP_FULL}}",
            model.screenshots["desktop"]["full"],
        )
    
        html = html.replace(
            "{{MOBILE}}",
            model.screenshots["iphone_15"]["normal"],
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

    def render_scores(
        self,
        model,
    ):

        html = ""

        for category in model.category_scores:

            html += f"""
            <div class="score-card">

                <div>{escape(category.name)}</div>

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

            html += f"<h2>{escape(section.title)}</h2>"

            for issue in section.issues:

                html += f"""
                <div class="issue {escape(issue.severity.lower())}">

                    <h3>{escape(issue.title)}</h3>

                    <p><b>Severity:</b> {escape(issue.severity)}</p>

                    <p><b>Category:</b> {escape(issue.category)}</p>

                    <p>{escape(issue.description)}</p>

                    <p><b>Recommendation:</b></p>

                    <p>{escape(issue.recommendation)}</p>
                """

                details = [
                    ("Verification", issue.verification),
                    ("Verification Method", getattr(issue, "verification_method", "")),
                    ("Occurrences", issue.occurrences if getattr(issue, "occurrences", 0) else ""),
                    (
                        "Affected Items",
                        ", ".join(issue.affected_items)
                        if getattr(issue, "affected_items", [])
                        else "",
                    ),
                    ("Endpoint", issue.endpoint),
                    ("Page", issue.page),
                    ("Selector", issue.selector),
                    ("Parameter", issue.parameter),
                    ("Payload", issue.payload),
                    ("Original Value", issue.original_value),
                    ("Modified Value", issue.modified_value),
                    (
                        "Response Code",
                        "" if issue.response_code is None else issue.response_code,
                    ),
                    (
                        "Response Time",
                        ""
                        if issue.response_time is None
                        else f"{issue.response_time:.2f} ms",
                    ),
                    ("Impact", issue.impact),
                    ("Confidence", issue.confidence),
                    ("CWE", issue.cwe),
                    ("OWASP", issue.owasp),
                    ("Estimated Fix", issue.fix_time),
                    ("Notes", issue.notes),
                    ("Screenshot", issue.screenshot),
                ]

                for label, value in details:

                    if value in ("", None):
                        continue

                    html += f"""
                    <p><b>{escape(label)}:</b> {escape(str(value))}</p>
                    """

                if issue.evidence:

                    html += f"""

                    <pre>{escape(issue.evidence)}</pre>

                    """

                html += "</div>"

        return html
