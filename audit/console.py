from audit.models import Issue


def run_console_audit(browser_data):
    issues = []

    console_messages = browser_data["console"]
    js_errors = browser_data["js_errors"]

    # ----------------------------
    # JavaScript Exceptions
    # ----------------------------

    if js_errors:
        issues.append(
            Issue(
                category="Console",
                severity="High",
                title="JavaScript Exceptions",
                description=f"{len(js_errors)} JavaScript exceptions occurred.",
                recommendation="Investigate the stack traces and fix runtime errors.",
                evidence="\n".join(js_errors[:10]),
            )
        )

    # ----------------------------
    # Console Errors
    # ----------------------------

    errors = []

    for message in console_messages:

        if message["type"] == "error":
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

        if message["type"] == "warning":
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