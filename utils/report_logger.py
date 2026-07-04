from pathlib import Path
from urllib.parse import urlparse


def save_issue_log(
    website,
    report,
):

    domain = (
        urlparse(website.url)
        .netloc
        .replace("www.", "")
        .replace(":", "_")
    )

    output = (
        Path("output")
        / domain
        / "audit.log"
    )

    lines = []

    lines.append("=" * 80)
    lines.append("WEBSITE AUDIT LOG")
    lines.append("=" * 80)
    lines.append("")

    lines.append(f"Title : {website.title}")
    lines.append(f"URL   : {website.url}")
    lines.append("")

    lines.append("=" * 80)
    lines.append("AUDIT FINDINGS")
    lines.append("=" * 80)
    lines.append("")

    if not report.issues:

        lines.append("No issues found.")

    else:

        for index, issue in enumerate(
            report.issues,
            start=1,
        ):

            lines.append(
                f"{index}. {issue.title}"
            )

            lines.append(
                f"Severity       : {issue.severity}"
            )

            lines.append(
                f"Category       : {issue.category}"
            )

            lines.append(
                f"Description    : {issue.description}"
            )

            lines.append(
                f"Recommendation : {issue.recommendation}"
            )

            if issue.fix_time:

                lines.append(
                    f"Estimated Fix  : {issue.fix_time}"
                )

            if issue.page:

                lines.append(
                    f"Page           : {issue.page}"
                )

            if issue.selector:

                lines.append(
                    f"Selector       : {issue.selector}"
                )

            if issue.screenshot:

                lines.append(
                    f"Screenshot     : {issue.screenshot}"
                )

            if issue.evidence:

                lines.append(
                    "Evidence:"
                )

                lines.append(
                    str(issue.evidence)
                )

            lines.append("")
            lines.append("-" * 80)
            lines.append("")

    output.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    return str(output)