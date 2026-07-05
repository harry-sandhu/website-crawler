from dataclasses import replace
from collections import OrderedDict
import re

from audit.security.shared import normalize_confidence


SEVERITY_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Info": 4,
}

VERIFICATION_ORDER = {
    "Potential": 0,
    "Likely": 1,
    "Confirmed": 2,
}


HTML_BEST_PRACTICE_TOKENS = (
    "autocomplete",
    "pattern",
    "maxlength",
    "minlength",
    "placeholder",
    "optional input field",
    "missing input names",
    "missing name",
    "number field",
    "hidden field contains default value",
    "readonly",
    "disabled",
    "file upload",
    "accept",
)

AUTHENTICATION_TOKENS = (
    "password",
    "login",
    "register",
    "reset",
    "recovery",
    "recover",
    "mfa",
    "2fa",
    "oauth",
    "sso",
    "username",
)

SECURITY_TOKENS = (
    "secret",
    "sensitive",
    "csrf",
    "jwt",
    "token",
    "api key",
    "apikey",
    "private key",
    "server-side file validation",
)

CATEGORY_OVERRIDES = (
    ("Input Validation", "HTML Best Practices"),
    ("Technology", "Detected Technologies"),
    ("Security.txt", "Security Best Practices"),
    ("Headers", "Security"),
    ("Cookies", "Security"),
    ("SSL", "Security"),
    ("Session", "Security"),
    ("JWT", "Security"),
    ("Secrets", "Security"),
    ("Network", "Networking"),
    ("Console", "Performance"),
    ("Lighthouse", "Performance"),
    ("Responsive", "Usability"),
)

TITLE_OVERRIDES = (
    ("Missing H1 Heading", "Missing H1 heading"),
    ("Missing Page Title", "Missing page titles"),
    ("Title Too Short", "Short page titles"),
    ("Title Too Long", "Long page titles"),
    ("Missing Meta Description", "Missing meta descriptions"),
    ("Meta Description Too Short", "Short meta descriptions"),
    ("Multiple H1 Headings", "Multiple H1 headings"),
    ("Missing Canonical Tag", "Missing canonical tags"),
    ("Missing Viewport Meta Tag", "Missing viewport meta tags"),
    ("Missing HTML Language", "Missing HTML lang attributes"),
    ("Missing Favicon", "Missing favicons"),
    ("Missing Structured Data", "Missing structured data"),
    ("Images Missing Alt Text", "Missing image alt text"),
    ("Images Not Using Lazy Loading", "Missing image lazy loading"),
    ("Console Errors", "Console errors"),
    ("JavaScript Exceptions", "JavaScript exceptions"),
    ("Failed Network Requests", "Failed network requests"),
    ("HTTP Error Responses", "HTTP error responses"),
    ("Mixed Content", "Mixed content"),
    ("Many Third-Party Domains", "Third-party dependency concentration"),
    ("Missing Strict-Transport-Security Header", "Missing HSTS"),
    ("Weak Strict-Transport-Security Header", "Weak HSTS"),
    ("Missing Content-Security-Policy Header", "Missing CSP"),
    ("Weak Content-Security-Policy", "Weak CSP"),
    ("Missing X-Frame-Options Header", "Missing X-Frame-Options"),
    ("Frame Embedding Allowed", "Weak frame embedding protection"),
    ("Cookie Missing Secure Attribute", "Missing Secure cookie attributes"),
    ("Cookie Missing HttpOnly Attribute", "Missing HttpOnly cookie attributes"),
    ("Session Cookie Missing Secure Attribute", "Missing Secure session cookie attributes"),
    ("Session Cookie Missing HttpOnly Attribute", "Missing HttpOnly session cookie attributes"),
    ("Cookie Missing SameSite Attribute", "Missing SameSite cookie attributes"),
    ("Session Cookie Missing SameSite Attribute", "Missing SameSite session cookie attributes"),
    ("Password Managers May Be Disabled", "Password manager support disabled"),
    ("Password Field Autocomplete Disabled", "Password manager support disabled"),
    ("Weak Password Policy Inferred", "Weak password policy"),
    ("Password Field Missing Minimum Length", "Weak password policy"),
    ("Password Field Is Readonly", "Readonly password field"),
    ("Password Field Is Disabled", "Disabled password field"),
    ("Sensitive Hidden Field Detected", "Sensitive hidden fields"),
    ("Hidden Field Contains Default Value", "Hidden field default values"),
    ("Form Field Missing Name", "Missing input names"),
    ("Unnamed Input Field", "Missing input names"),
    ("Autocomplete Not Configured", "Missing autocomplete attributes"),
    ("Email Autocomplete Not Configured", "Missing autocomplete attributes"),
    ("Phone Autocomplete Not Configured", "Missing autocomplete attributes"),
    ("Password Autocomplete Not Specified", "Missing password autocomplete hints"),
    ("Phone Field Missing Pattern Validation", "Missing pattern attributes"),
    ("Email Field Missing Pattern Validation", "Missing pattern attributes"),
    ("Phone Field Missing Maximum Length", "Missing maxlength attributes"),
    ("Email Field Missing Maximum Length", "Missing maxlength attributes"),
    ("Text Field Missing Maximum Length", "Missing maxlength attributes"),
    ("Number Field Missing Minimum Value", "Number field limits"),
    ("Number Field Missing Maximum Value", "Number field limits"),
    ("Number Field Missing Step Value", "Number field limits"),
    ("Number Field Has No Limits", "Number field limits"),
    ("Optional Input Field", "Optional input fields"),
    ("Placeholder Missing", "Missing placeholder hints"),
    ("Readonly Field Detected", "Readonly and disabled fields"),
    ("Disabled Field Detected", "Readonly and disabled fields"),
    ("Readonly Text Field", "Readonly and disabled fields"),
    ("Disabled Text Field", "Readonly and disabled fields"),
    ("File Upload Accepts Any File Type", "File upload restrictions"),
    ("Multiple File Upload Enabled", "File upload restrictions"),
    ("Server-side File Validation Required", "File upload restrictions"),
)


def _normalize_text(value):

    return re.sub(
        r"\s+",
        " ",
        str(value or ""),
    ).strip().lower()


def _has_token(text, tokens):

    return any(
        token in text
        for token in tokens
    )


def normalize_title(issue):

    title = issue.title or ""
    lower = title.lower()

    for needle, replacement in TITLE_OVERRIDES:
        if needle.lower() in lower:
            return replacement

    if "autocomplete" in lower:
        return "Missing autocomplete attributes"

    if "pattern" in lower:
        return "Missing pattern attributes"

    if "minlength" in lower or "minimum length" in lower:
        return "Missing minlength attributes"

    if "maxlength" in lower or "maximum length" in lower:
        return "Missing maxlength attributes"

    if "placeholder" in lower:
        return "Missing placeholder hints"

    if "readonly" in lower or "disabled" in lower:
        return "Readonly and disabled fields"

    return title


def normalize_category(issue):

    category = issue.category or ""
    title = normalize_title(issue).lower()

    if any(
        token in title
        for token in (
            "autocomplete",
            "pattern",
            "maxlength",
            "minlength",
            "placeholder",
            "missing input names",
            "optional input fields",
            "readonly and disabled fields",
            "number field limits",
            "file upload restrictions",
            "hidden field default values",
        )
    ):
        return "HTML/UX"

    if any(
        token in title
        for token in (
            "login form detected",
            "registration form detected",
            "password recovery flow detected",
            "multi-factor authentication",
            "oauth",
            "sso",
            "sign-on",
            "jquery detected",
            "wordpress detected",
            "drupal detected",
            "react detected",
            "vue detected",
            "angular detected",
            "next.js detected",
            "nuxt detected",
            "bootstrap detected",
            "tailwind detected",
        )
    ):
        return "Detected Technologies"

    for source, target in CATEGORY_OVERRIDES:
        if category == source:
            if source == "Input Validation":
                if _has_token(title, SECURITY_TOKENS):
                    return "Security"

                if _has_token(title, AUTHENTICATION_TOKENS):
                    return "Authentication"

                return target

            return target

    if category == "SEO" and "alt text" in title:
        return "Accessibility"

    if category == "SEO" and "lazy loading" in title:
        return "Performance"

    if category == "Console":
        return "Performance"

    return category or "Security"


def normalize_severity(issue):

    title = normalize_title(issue).lower()
    category = normalize_category(issue)
    raw_severity = issue.severity or ""

    if "missing h1 heading" in title:
        return "Medium"

    if "hidden field contains default value" in title:
        return "Info"

    if "sensitive hidden fields" in title:
        return "Medium"

    if "missing autocomplete attributes" in title:
        return "Info"

    if "missing password autocomplete hints" in title:
        return "Info"

    if "login form detected" in title:
        return "Info"

    if "registration form detected" in title:
        return "Info"

    if "password recovery flow detected" in title:
        return "Info"

    if "multi-factor authentication indicator detected" in title:
        return "Info"

    if "oauth or sso integration detected" in title:
        return "Info"

    if "jquery detected" in title:
        return "Info"

    if "security.txt" in title:
        return "Info"

    if "missing pattern attributes" in title:
        return "Low"

    if "missing maxlength attributes" in title:
        return "Low"

    if "missing minlength attributes" in title:
        return "Low"

    if "missing placeholder hints" in title:
        return "Info"

    if "optional input fields" in title:
        return "Info"

    if "readonly and disabled fields" in title:
        return "Info"

    if "number field limits" in title:
        return "Info"

    if "file upload restrictions" in title:
        return "Medium"

    if category == "Security" and raw_severity == "Info":
        return "Low"

    return raw_severity or "Info"


def normalize_verification_method(issue):

    title = normalize_title(issue).lower()
    category = normalize_category(issue)

    if getattr(issue, "verification", "") == "Confirmed":
        return "Request replay verification"

    if category == "Security":
        if "header" in title:
            return "HTTP header inspection"

        if "cookie" in title or "session" in title:
            return "Cookie and storage inspection"

        if "jwt" in title:
            return "Token structure and decode verification"

        if "mixed content" in title:
            return "Browser resource inspection"

        if "security.txt" in title:
            return "HTTP fetch verification"

        if "api response" in title:
            return "Structured response inspection"

        return "Static evidence review"

    if category == "Detected Technologies":
        return "Static fingerprint review"

    if category == "HTML/UX" or category == "HTML Best Practices":
        return "Markup inspection"

    if category == "Networking":
        return "Browser network inspection"

    return "Static evidence review"


def issue_scope(issue):

    parts = []

    for value in (
        issue.selector,
        issue.endpoint,
        issue.page,
        issue.parameter,
    ):
        text = _normalize_text(value)
        if text:
            parts.append(text)

    return "|".join(parts)


def issue_key(issue):

    if getattr(issue, "finding_key", ""):
        return issue.finding_key

    parts = [
        _normalize_text(normalize_category(issue)),
        _normalize_text(normalize_title(issue)),
        issue_scope(issue),
    ]

    return "::".join(
        part for part in parts if part
    )


def issue_affected_items(issue):

    items = []

    for value in (
        getattr(issue, "affected_item", ""),
        getattr(issue, "parameter", ""),
    ):
        text = str(value or "").strip()
        if text and text not in items:
            items.append(text)

    if not items and issue.selector:
        items.append(issue.selector)

    if not items and issue.page:
        items.append(issue.page)

    if not items and issue.endpoint:
        items.append(issue.endpoint)

    return items


def _merge_evidence(existing, incoming):

    combined = []

    for value in (
        existing.evidence,
        incoming.evidence,
    ):
        if not value:
            continue

        for line in str(value).splitlines():
            line = line.strip()
            if line and line not in combined:
                combined.append(line)

    if len(combined) > 8:
        combined = combined[:8]

    return "\n".join(combined)


def merge_issue(existing, incoming):

    existing.occurrences += max(1, int(getattr(incoming, "occurrences", 1) or 1))

    for item in issue_affected_items(incoming):
        if item not in existing.affected_items:
            existing.affected_items.append(item)

    if not existing.finding_key:
        existing.finding_key = issue_key(existing)

    if not existing.evidence:
        existing.evidence = incoming.evidence
    else:
        existing.evidence = _merge_evidence(existing, incoming)

    if SEVERITY_ORDER.get(normalize_severity(incoming), 99) < SEVERITY_ORDER.get(existing.severity, 99):
        existing.severity = normalize_severity(incoming)

    if not existing.description and incoming.description:
        existing.description = incoming.description

    if not existing.recommendation and incoming.recommendation:
        existing.recommendation = incoming.recommendation

    if not existing.impact and incoming.impact:
        existing.impact = incoming.impact

    if not existing.confidence and incoming.confidence:
        existing.confidence = incoming.confidence

    if not existing.fix_time and incoming.fix_time:
        existing.fix_time = incoming.fix_time

    if not existing.verification_method and getattr(
        incoming,
        "verification_method",
        "",
    ):
        existing.verification_method = incoming.verification_method

    if VERIFICATION_ORDER.get(
        getattr(incoming, "verification", "Potential"),
        0,
    ) > VERIFICATION_ORDER.get(
        getattr(existing, "verification", "Potential"),
        0,
    ):
        existing.verification = incoming.verification

    return existing


def normalize_issues(issues):

    grouped = OrderedDict()

    for issue in issues:

        category = normalize_category(issue)
        title = normalize_title(issue)
        severity = normalize_severity(issue)
        key = issue_key(issue)

        normalized = replace(
            issue,
            category=category,
            title=title,
            severity=severity,
            confidence=normalize_confidence(
                getattr(issue, "confidence", ""),
                getattr(issue, "verification", ""),
                title,
                category,
            ),
            finding_key=key,
            affected_items=list(
                dict.fromkeys(
                    issue_affected_items(issue)
                )
            ),
            occurrences=max(
                1,
                int(getattr(issue, "occurrences", 1) or 1),
            ),
            verification=getattr(
                issue,
                "verification",
                "Potential",
            ),
            verification_method=normalize_verification_method(
                issue,
            ),
        )

        if key in grouped:
            merge_issue(
                grouped[key],
                normalized,
            )
        else:
            grouped[key] = normalized

    return list(grouped.values())
