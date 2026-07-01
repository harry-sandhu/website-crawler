from audit.models import Issue


def run_security_audit(website):
    issues = []

    responses = website.browser["responses"]

    if not responses:
        return issues

    headers = {
        k.lower(): v
        for k, v in responses[0]["headers"].items()
    }

    url = responses[0]["url"]

    # ---------------- HTTPS ---------------- #

    if not url.startswith("https://"):
        issues.append(
            Issue(
                category="Security",
                severity="Critical",
                title="Website Not Using HTTPS",
                description="The website is served over HTTP.",
                recommendation="Redirect all traffic to HTTPS.",
                fix_time="15 minutes",
            )
        )

    # ---------------- HSTS ---------------- #

    if "strict-transport-security" not in headers:
        issues.append(
            Issue(
                category="Security",
                severity="Medium",
                title="Missing HSTS Header",
                description="Strict-Transport-Security header not found.",
                recommendation="Enable HSTS.",
                fix_time="10 minutes",
            )
        )

    # ---------------- CSP ---------------- #

    if "content-security-policy" not in headers:
        issues.append(
            Issue(
                category="Security",
                severity="High",
                title="Missing Content Security Policy",
                description="No CSP header detected.",
                recommendation="Add a Content-Security-Policy header.",
                fix_time="30 minutes",
            )
        )

    # ---------------- X-Frame ---------------- #

    if "x-frame-options" not in headers:
        issues.append(
            Issue(
                category="Security",
                severity="Medium",
                title="Missing X-Frame-Options",
                description="The website can potentially be embedded by other sites.",
                recommendation="Set X-Frame-Options to DENY or SAMEORIGIN.",
                fix_time="5 minutes",
            )
        )

    # ---------------- X-Content-Type ---------------- #

    if "x-content-type-options" not in headers:
        issues.append(
            Issue(
                category="Security",
                severity="Medium",
                title="Missing X-Content-Type-Options",
                description="The browser may MIME-sniff responses.",
                recommendation="Set X-Content-Type-Options: nosniff.",
                fix_time="5 minutes",
            )
        )

    # ---------------- Referrer Policy ---------------- #

    if "referrer-policy" not in headers:
        issues.append(
            Issue(
                category="Security",
                severity="Low",
                title="Missing Referrer Policy",
                description="No Referrer-Policy header detected.",
                recommendation="Add a Referrer-Policy header.",
                fix_time="5 minutes",
            )
        )

    # ---------------- Permissions Policy ---------------- #

    if "permissions-policy" not in headers:
        issues.append(
            Issue(
                category="Security",
                severity="Low",
                title="Missing Permissions Policy",
                description="No Permissions-Policy header detected.",
                recommendation="Restrict browser features with Permissions-Policy.",
                fix_time="10 minutes",
            )
        )

    return issues