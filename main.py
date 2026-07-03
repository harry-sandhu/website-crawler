from pathlib import Path

from browser.crawler import WebsiteCrawler

from utils.logger import console
from reports.json_report import save_json

from audit.engine import AuditEngine
from audit.scoring import ScoreEngine
from reports.html import HTMLReportBuilder


def load_urls():

    url_file = Path("url.md")

    if url_file.exists():

        urls = []

        for line in url_file.read_text(
            encoding="utf-8"
        ).splitlines():

            line = line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            urls.append(line)

        if urls:
            return urls

    return [input("Website URL: ").strip()]


def main():

    urls = load_urls()

    crawler = WebsiteCrawler(headless=False)

    engine = AuditEngine()

    score_engine = ScoreEngine()

    html_builder = HTMLReportBuilder()

    for url in urls:

        console.print(f"\n[cyan]Opening {url}[/cyan]\n")

        website = crawler.crawl(url)

        page_data = website.page
        browser_data = website.browser

        # -----------------------------
        # Save Browser Data
        # -----------------------------

        save_json(browser_data)

        # -----------------------------
        # Run Audits
        # -----------------------------

        report = engine.run(website)

        score = score_engine.calculate(report)


        report_path = html_builder.build(
            website,
            report,
            score,
        )

        # -----------------------------
        # Website Health
        # -----------------------------

        console.print(
            "\n[bold green]========== WEBSITE HEALTH ==========[/bold green]\n"
        )

        console.print(
            f"Overall Score    : {score.overall:.1f}/100"
        )

        console.print(
            f"Critical Issues  : {score.critical}"
        )

        console.print(
            f"High Issues      : {score.high}"
        )

        console.print(
            f"Medium Issues    : {score.medium}"
        )

        console.print(
            f"Low Issues       : {score.low}"
        )

        console.print(
            f"Total Issues     : {score.total_issues}"
        )

        console.print()

        console.print("[bold cyan]Category Scores[/bold cyan]\n")

        for category in score.categories:

            console.print(
                f"{category.name:<18} {category.score:>6.1f}/100"
            )

        # -----------------------------
        # Summary
        # -----------------------------

        console.print("\n========== SUMMARY ==========\n")

        console.print(f"Title            : {website.title}")
        console.print(f"Console Messages : {len(browser_data['console'])}")
        console.print(f"JS Errors        : {len(browser_data['js_errors'])}")
        console.print(f"Requests         : {len(browser_data['requests'])}")
        console.print(f"Responses        : {len(browser_data['responses'])}")
        console.print(f"Failed Requests  : {len(browser_data['failed_requests'])}")

        console.print(f"Images           : {len(page_data['images'])}")
        console.print(f"Links            : {len(page_data['links'])}")
        console.print(f"Forms            : {len(page_data['forms'])}")
        console.print(f"Buttons          : {len(page_data['buttons'])}")
        console.print(f"Scripts          : {len(page_data['scripts'])}")
        console.print(f"Stylesheets      : {len(page_data['stylesheets'])}")

        console.print(f"Canonical        : {page_data['canonical']}")
        console.print(f"Viewport         : {'Yes' if page_data['viewport'] else 'No'}")
        console.print(f"Language         : {page_data['lang']}")
        console.print(f"Favicon          : {'Yes' if page_data['favicon'] else 'No'}")
        console.print(f"Emails           : {len(page_data['emails'])}")
        console.print(f"Phones           : {len(page_data['phones'])}")
        console.print(f"Schema           : {len(page_data['schema'])}")
        console.print(f"Robots.txt       : {'Yes' if website.robots['exists'] else 'No'}")
        console.print(f"Sitemap.xml      : {'Yes' if website.sitemap['exists'] else 'No'}")

        console.print(
            f"Desktop Shot     : {website.screenshots['desktop']['normal']}"
        )

        console.print(
            f"Desktop Full     : {website.screenshots['desktop']['full']}"
        )

        console.print(
            f"iPhone 15 Shot   : {website.screenshots['iphone_15']['normal']}"
        )

        console.print()

        for level, headings in page_data["headings"].items():

            console.print(
                f"{level.upper():<5}: {len(headings)}"
            )

        console.print(
            f"\n[bold green]HTML Report Generated[/bold green]"
        )
        
        console.print(
            f"[cyan]{report_path}[/cyan]\n"
        )    

        console.print(
            "\n[bold cyan]Audit Results[/bold cyan]\n"
        )

        if not report.issues:

            console.print(
                "[green]✓ No issues found.[/green]"
            )

        else:

            severity_colors = {

                "Critical": "red",

                "High": "yellow",

                "Medium": "cyan",

                "Low": "green",

            }

            for issue in report.issues:

                color = severity_colors.get(
                    issue.severity,
                    "white",
                )

                console.print(
                    f"[{color}]● {issue.severity:<8}[/{color}] {issue.title}"
                )

                console.print(
                    f"    Category      : {issue.category}"
                )

                console.print(
                    f"    Description   : {issue.description}"
                )

                console.print(
                    f"    Recommendation: {issue.recommendation}"
                )

                if issue.fix_time:

                    console.print(
                        f"    Estimated Fix : {issue.fix_time}"
                    )

                if issue.page:

                    console.print(
                        f"    Page          : {issue.page}"
                    )

                if issue.selector:

                    console.print(
                        f"    Selector      : {issue.selector}"
                    )

                if issue.screenshot:

                    console.print(
                        f"    Screenshot    : {issue.screenshot}"
                    )

                if issue.evidence:

                    console.print(
                        f"    Evidence:\n{issue.evidence}"
                    )

                console.print()

    crawler.close()


if __name__ == "__main__":
    main()