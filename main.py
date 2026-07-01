from browser.crawler import WebsiteCrawler

from utils.logger import console
from reports.json_report import save_json

from audit.engine import AuditEngine


def main():
    url = input("Website URL: ").strip()

    crawler = WebsiteCrawler(headless=False)

    console.print(f"[cyan]Opening {url}[/cyan]")

    website, page = crawler.crawl(url)

    page_data = website.page
    browser_data = website.browser

    # Save browser data
    save_json(browser_data)

    # Run all audits
    engine = AuditEngine()
    report = engine.run(
        website,
        page,
    )

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
        console.print(f"{level.upper():<5}: {len(headings)}")

    console.print("\n[bold cyan]Audit Results[/bold cyan]\n")

    if not report.issues:
        console.print("[green]✓ No issues found.[/green]")
    else:
        severity_colors = {
            "Critical": "red",
            "High": "yellow",
            "Medium": "cyan",
            "Low": "green",
        }

        for issue in report.issues:
            color = severity_colors.get(issue.severity, "white")

            console.print(
                f"[{color}]● {issue.severity:<8}[/{color}] {issue.title}"
            )
            console.print(f"    Category      : {issue.category}")
            console.print(f"    Description   : {issue.description}")
            console.print(f"    Recommendation: {issue.recommendation}")

            if issue.fix_time:
                console.print(f"    Estimated Fix : {issue.fix_time}")

            if issue.page:
                console.print(f"    Page          : {issue.page}")

            if issue.selector:
                console.print(f"    Selector      : {issue.selector}")

            if issue.screenshot:
                console.print(f"    Screenshot    : {issue.screenshot}")

            if issue.evidence:
                console.print(f"    Evidence:\n{issue.evidence}")

            console.print()

    crawler.close()


if __name__ == "__main__":
    main()