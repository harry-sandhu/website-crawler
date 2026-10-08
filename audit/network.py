from urllib.parse import urlparse

from audit.models import Issue


def run_network_audit(browser_data):
    issues = []

    responses = browser_data["responses"]
    failed = browser_data["failed_requests"]

    # ----------------------------
    # Failed Requests
    # ----------------------------

    if failed:
        evidence = []

        for request in failed[:10]:
            evidence.append(request["url"])

        issues.append(
            Issue(
                category="Network",
                severity="High",
                title="Failed Network Requests",
                description=f"{len(failed)} network requests failed.",
                recommendation="Fix missing or unreachable resources.",
                evidence="\n".join(evidence),
            )
        )

    # ----------------------------
    # HTTP Errors
    # ----------------------------

    errors = []

    for response in responses:
        status = response["status"]

        if status >= 400:
            errors.append(
                f"{status} - {response['url']}"
            )

    if errors:
        issues.append(
            Issue(
                category="Network",
                severity="High",
                title="HTTP Error Responses",
                description=f"{len(errors)} resources returned HTTP errors.",
                recommendation="Investigate and resolve 4xx/5xx responses.",
                evidence="\n".join(errors[:10]),
            )
        )

    # ----------------------------
    # Redirects
    # ----------------------------

    redirects = [
        r for r in responses
        if r["status"] in (301, 302, 307, 308)
    ]

    if redirects:
        issues.append(
            Issue(
                category="Network",
                severity="Low",
                title="Redirects Detected",
                description=f"{len(redirects)} redirects were observed.",
                recommendation="Reduce unnecessary redirects where possible.",
            )
        )

    # ----------------------------
    # Mixed Content
    # ----------------------------

    mixed = []

    page_url = responses[0]["url"] if responses else ""

    if not page_url.lower().startswith("https://"):
        mixed = []
    else:

        for response in responses:
            parsed = urlparse(response["url"])

            if parsed.scheme != "http" or not parsed.netloc:
                continue

            mixed.append(response["url"])

    if mixed:
        issues.append(
            Issue(
                category="Network",
                severity="Critical",
                title="Mixed Content",
                description="HTTP resources were loaded on an HTTPS page.",
                recommendation="Serve all assets over HTTPS.",
                evidence="\n".join(mixed),
                confidence="HIGH_CONFIDENCE",
                verification_method="Browser resource inspection",
            )
        )

    # ----------------------------
    # Third-Party Domains
    # ----------------------------

    if responses:
        base_domain = urlparse(responses[0]["url"]).netloc

        third_party = set()

        for response in responses:
            domain = urlparse(response["url"]).netloc

            if domain and domain != base_domain:
                third_party.add(domain)

        if len(third_party) > 10:
            issues.append(
                Issue(
                    category="Network",
                    severity="Low",
                    title="Many Third-Party Domains",
                    description=f"{len(third_party)} third-party domains were contacted.",
                    recommendation="Review whether all external resources are necessary.",
                    evidence="\n".join(sorted(third_party)),
                )
            )

    return issues
