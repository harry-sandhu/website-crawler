from audit.models import Issue


THIRD_PARTY_CONSOLE_HINTS = (
    "google",
    "googleapis",
    "gstatic",
    "recaptcha",
    "facebook",
    "fbcdn",
    "paypal",
    "analytics",
    "googletagmanager",
    "gtm",
    "doubleclick",
    "hotjar",
    "segment",
    "mixpanel",
    "amplitude",
    "sentry",
    "datadog",
    "newrelic",
    "cloudflare",
    "browser extension",
    "extension",
)


def _is_third_party_console_text(text):

    lower = str(text or "").lower()

    return any(
        hint in lower
        for hint in THIRD_PARTY_CONSOLE_HINTS
    )


def run_console_audit(browser_data):
    issues = []

    console_messages = browser_data["console"]
    js_errors = browser_data["js_errors"]

    # ----------------------------
    # JavaScript Exceptions
    # ----------------------------

    app_errors = [
        error
        for error in js_errors
        if not _is_third_party_console_text(error)
    ]

    if app_errors:
        issues.append(
            Issue(
                category="Console",
                severity="High",
                title="JavaScript Exceptions",
                description=f"{len(app_errors)} JavaScript exceptions occurred.",
                recommendation="Investigate the stack traces and fix runtime errors.",
                evidence="\n".join(app_errors[:10]),
            )
        )

    # ----------------------------
    # Console Errors
    # ----------------------------

    errors = []

    for message in console_messages:

        if (
            message["type"] == "error"
            and not _is_third_party_console_text(message["text"])
        ):
            errors.append(message["text"])

    if errors:
        issues.append(
            Issue(
                category="Console",
                severity="High",
                title="Console Errors",
                description=f"{len(errors)} console errors were logged.",
                recommendation="Resolve JavaScript and asset loading errors.",
                evidence="\n".join(errors[:10]),
            )
        )

    # ----------------------------
    # Console Warnings
    # ----------------------------

    warnings = []

    for message in console_messages:

        if (
            message["type"] == "warning"
            and not _is_third_party_console_text(message["text"])
        ):
            warnings.append(message["text"])

    if warnings:
        issues.append(
            Issue(
                category="Console",
                severity="Low",
                title="Console Warnings",
                description=f"{len(warnings)} warnings were logged.",
                recommendation="Review warnings and determine whether action is needed.",
                evidence="\n".join(warnings[:10]),
            )
        )

    return issues
