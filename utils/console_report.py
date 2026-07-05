from pathlib import Path

from utils.logger import console


def print_banner(
    url: str,
    index: int,
    total: int,
):

    console.rule(
        f"[bold cyan]Website {index}/{total}[/bold cyan]"
    )

    console.print(
        f"[cyan]URL:[/cyan] {url}\n"
    )


# ----------------------------------


def print_summary(
    website,
    browser_data,
    score,
    report=None,
):

    console.print(
        "[bold green]Website Health[/bold green]\n"
    )

    console.print(
        f"Overall Score : {score.overall:.1f}/100"
    )

    console.print(
        f"Critical      : {score.critical}"
    )

    console.print(
        f"High          : {score.high}"
    )

    console.print(
        f"Medium        : {score.medium}"
    )

    console.print(
        f"Low           : {score.low}"
    )

    console.print(
        f"Info          : {getattr(score, 'info', 0)}"
    )

    console.print(
        f"Verified      : {getattr(score, 'verified', 0)}"
    )

    console.print(
        f"High Conf.    : {getattr(score, 'high_confidence', 0)}"
    )

    console.print(
        f"Manual Review : {getattr(score, 'needs_manual_review', 0)}"
    )

    console.print(
        f"Informational  : {getattr(score, 'informational', 0)}"
    )

    console.print(
        f"Score Findings : {score.total_issues}"
    )

    confirmed = sum(
        1
        for issue in getattr(report, "issues", [])
        if getattr(issue, "verification", "") == "Confirmed"
    )

    if confirmed:

        console.print(
            f"Confirmed Exploits: {confirmed}"
        )

    console.print()

    console.print(
        "[bold cyan]Category Scores[/bold cyan]"
    )

    console.print()

    for category in score.categories:

        console.print(
            f"{category.name:<18} {category.score:>6.1f}/100"
        )

    console.print()

    console.print(
        "[bold cyan]Summary[/bold cyan]\n"
    )

    page = website.page

    console.print(
        f"Title            : {website.title}"
    )

    console.print(
        f"Console Messages : {len(browser_data['console'])}"
    )

    console.print(
        f"JS Errors        : {len(browser_data['js_errors'])}"
    )

    console.print(
        f"Requests         : {len(browser_data['requests'])}"
    )

    console.print(
        f"Responses        : {len(browser_data['responses'])}"
    )

    console.print(
        f"Failed Requests  : {len(browser_data['failed_requests'])}"
    )

    console.print(
        f"Images           : {len(page['images'])}"
    )

    console.print(
        f"Links            : {len(page['links'])}"
    )

    console.print(
        f"Forms            : {len(page['forms'])}"
    )

    console.print(
        f"Buttons          : {len(page['buttons'])}"
    )

    console.print(
        f"Scripts          : {len(page['scripts'])}"
    )

    console.print(
        f"Stylesheets      : {len(page['stylesheets'])}"
    )

    console.print()
