import webbrowser
from pathlib import Path

from browser.crawler import WebsiteCrawler

from audit.engine import AuditEngine
from audit.scoring import ScoreEngine

from reports.json_report import save_json
from reports.html import HTMLReportBuilder
from reports.pdf import PDFReportBuilder
import argparse


parser = argparse.ArgumentParser()

parser.add_argument(
    "--aggressive",
    action="store_true",
    help="Enable active security testing",
)

parser.add_argument(
    "--headless",
    action="store_true",
    help="Run browser in headless mode",
)

parser.add_argument(
    "--no-open",
    action="store_true",
    help="Don't automatically open the HTML report",
)

args = parser.parse_args()

from utils.logger import (
    console,
    AUTO_OPEN_REPORT,
)

from utils.console_report import (
    print_banner,
    print_summary,
)

from utils.report_logger import (
    save_issue_log,
)


# ----------------------------------
# Load URLs
# ----------------------------------

def load_urls():

    url_file = Path("url.md")

    if url_file.exists():

        urls = []

        for line in url_file.read_text(
            encoding="utf-8",
        ).splitlines():

            line = line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            urls.append(line)

        if urls:
            return urls

    return [
        input("Website URL: ").strip()
    ]


# ----------------------------------
# Main
# ----------------------------------

def main():

    urls = load_urls()

    crawler = WebsiteCrawler(
        headless=False,
    )

    engine = AuditEngine(
        aggressive=args.aggressive,
    )

    score_engine = ScoreEngine()

    html_builder = HTMLReportBuilder()

    pdf_builder = PDFReportBuilder()

    try:

        for index, url in enumerate(
            urls,
            start=1,
        ):

            try:

                # ----------------------------------
                # Banner
                # ----------------------------------

                print_banner(
                    url,
                    index,
                    len(urls),
                )

                # ----------------------------------
                # Crawl Website
                # ----------------------------------

                website = crawler.crawl(
                    url,
                )

                browser_data = website.browser

                # ----------------------------------
                # Save Browser JSON
                # ----------------------------------

                save_json(
                    browser_data,
                )

                # ----------------------------------
                # Run Audit
                # ----------------------------------

                report = engine.run(
                    website,
                )

                score = score_engine.calculate(
                    report,
                )

                # ----------------------------------
                # Generate Reports
                # ----------------------------------

                html_path = html_builder.build(
                    website,
                    report,
                    score,
                )

                pdf_path = pdf_builder.build(
                    website,
                    report,
                    score,
                )

                log_path = save_issue_log(
                    website,
                    report,
                )

                # ----------------------------------
                # Open HTML Report
                # ----------------------------------

                if AUTO_OPEN_REPORT:

                    webbrowser.open(
                        Path(
                            html_path
                        ).resolve().as_uri()
                    )

                # ----------------------------------
                # Console Summary
                # ----------------------------------

                print_summary(
                    website,
                    browser_data,
                    score,
                )

                console.print(
                    "[bold green]Reports Generated[/bold green]\n"
                )

                console.print(
                    f"HTML Report : {html_path}"
                )

                console.print(
                    f"PDF Report  : {pdf_path}"
                )

                console.print(
                    f"Audit Log   : {log_path}"
                )

                console.print()

            except Exception as e:

                console.print()

                console.print(
                    f"[bold red]Failed to audit:[/bold red] {url}"
                )

                console.print(
                    f"[red]{type(e).__name__}: {e}[/red]"
                )

                console.print()

                continue

    except KeyboardInterrupt:

        console.print()

        console.print(
            "[yellow]Audit interrupted by user.[/yellow]"
        )

        console.print()

    finally:

        crawler.close()


# ----------------------------------

if __name__ == "__main__":

    main()
