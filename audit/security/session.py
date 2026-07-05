from .models import SecurityIssue
from .shared import (
    is_framework_token_name,
    looks_sensitive_token_name,
    looks_sensitive_token_value,
    parse_set_cookie_headers,
    text_snippet,
)


class SessionTester:

    SESSION_NAMES = {
        "session",
        "sessionid",
        "session_id",
        "sid",
        "phpsessid",
        "jsessionid",
        "asp.net_sessionid",
        "aspnet_sessionid",
        "connect.sid",
        "laravel_session",
        "django_session",
        "auth",
        "jwt",
    }

    WEAK_NAMES = {
        "session",
        "auth",
        "sid",
        "user",
        "login",
    }

    DEFAULT_NAMES = {
        "phpsessid",
        "jsessionid",
        "asp.net_sessionid",
        "aspnet_sessionid",
        "connect.sid",
        "sessionid",
        "session_id",
        "laravel_session",
        "django_session",
    }

    def _add_issue(
        self,
        report,
        **kwargs,
    ):

        report.issues.append(
            SecurityIssue(
                **kwargs,
            )
        )

    def _is_session_cookie(
        self,
        cookie,
    ):

        name = (
            cookie.get("name")
            or ""
        ).lower()

        if name in self.SESSION_NAMES:
            return True

        if name == "token":
            return looks_sensitive_token_value(
                cookie.get("value", "")
            )

        return not (
            cookie.get("expires")
            or cookie.get("max-age")
        )

    def _cookie_name(
        self,
        cookie,
    ):

        return (
            cookie.get("name")
            or ""
        ).lower()

    def _report_cookie_issue(
        self,
        report,
        website,
        request,
        cookie,
        title,
        description,
        recommendation,
        severity="Info",
        confidence="HIGH_CONFIDENCE",
        impact="",
        cwe="CWE-613",
        fix_time="5 minutes",
        notes="",
        verification_method="Set-Cookie inspection",
    ):

        self._add_issue(
            report,
            severity=severity,
            title=title,
            category="Session",
            description=description,
            recommendation=recommendation,
            endpoint=request.url,
            page=website.url,
            parameter=self._cookie_name(
                cookie
            ),
            evidence=text_snippet(
                cookie.get("raw", "")
            ),
            confidence=confidence,
            impact=impact,
            cwe=cwe,
            owasp="A07:2021 - Identification and Authentication Failures",
            fix_time=fix_time,
            notes=notes,
            response_code=request.response_status,
            verification_method=verification_method,
        )

    def _browser_storage_text(
        self,
        website,
    ):

        browser = getattr(
            website,
            "browser",
            {},
        ) or {}

        parts = []

        for key in (
            "local_storage",
            "session_storage",
            "storage",
            "localStorage",
            "sessionStorage",
        ):

            value = browser.get(
                key,
            )

            if isinstance(value, dict):

                for item_key, item_value in value.items():

                    parts.append(
                        f"{item_key}={item_value}"
                    )

            elif isinstance(value, list):

                for item in value:

                    parts.append(
                        str(item)
                    )

            elif value:

                parts.append(
                    str(value)
                )

        return " ".join(
            parts
        ).lower()

    def _html_text(
        self,
        website,
    ):

        page = website.page or {}

        html = (
            page.get("html", "")
            or ""
        )

        return html.lower()

    def run(
        self,
        website,
        report,
    ):

        session_cookies = {}

        for request in report.requests:

            for cookie in parse_set_cookie_headers(
                request.response_headers
            ):

                if not self._is_session_cookie(
                    cookie
                ):
                    continue

                name = self._cookie_name(
                    cookie
                )

                session_cookies.setdefault(
                    name,
                    [],
                ).append(
                    (
                        request,
                        cookie,
                    )
                )

                if not cookie.get("secure"):

                    self._report_cookie_issue(
                        report,
                        website,
                        request,
                        cookie,
                        "Session Cookie Missing Secure Attribute",
                        f"Session cookie '{name}' is missing the Secure attribute.",
                        "Mark session cookies as Secure so browsers only send them over HTTPS.",
                        severity="Medium",
                        confidence="HIGH_CONFIDENCE",
                        impact=(
                            "Session cookies without Secure can be exposed on "
                            "cleartext connections."
                        ),
                        cwe="CWE-614",
                    )

                if not cookie.get("httponly"):

                    self._report_cookie_issue(
                        report,
                        website,
                        request,
                        cookie,
                        "Session Cookie Missing HttpOnly Attribute",
                        f"Session cookie '{name}' is missing the HttpOnly attribute.",
                        "Mark session cookies as HttpOnly to reduce JavaScript access.",
                        severity="Medium",
                        confidence="HIGH_CONFIDENCE",
                        impact=(
                            "JavaScript running in the browser can access the "
                            "session cookie."
                        ),
                        cwe="CWE-1004",
                    )

                if not (
                    cookie.get("samesite") or ""
                ).strip():

                    self._report_cookie_issue(
                        report,
                        website,
                        request,
                        cookie,
                        "Session Cookie Missing SameSite Attribute",
                        f"Session cookie '{name}' does not define SameSite.",
                        "Set SameSite to Lax or Strict unless cross-site sending is required.",
                        severity="Medium",
                        confidence="HIGH_CONFIDENCE",
                        impact=(
                            "Session cookies without SameSite are easier to "
                            "include in cross-site requests."
                        ),
                        cwe="CWE-352",
                    )

                if name in self.DEFAULT_NAMES:

                    self._report_cookie_issue(
                        report,
                        website,
                        request,
                        cookie,
                        "Default Session Cookie Name Detected",
                        f"Session cookie '{name}' uses a common framework default name.",
                        "Consider whether the default name reveals unnecessary stack details.",
                        severity="Low",
                        confidence="HIGH_CONFIDENCE",
                        impact=(
                            "Default names can reveal the underlying framework "
                            "or platform."
                        ),
                        cwe="CWE-200",
                    )

                elif name == "token" or is_framework_token_name(name):
                    pass

                elif name in self.WEAK_NAMES or any(
                    token in name
                    for token in ("session", "auth", "token")
                ):

                    self._report_cookie_issue(
                        report,
                        website,
                        request,
                        cookie,
                        "Weak Session Cookie Name Detected",
                        f"Session cookie '{name}' uses a generic or sensitive-looking name.",
                        "Use explicit names that do not leak unnecessary semantics.",
                        severity="Info",
                        confidence="HIGH_CONFIDENCE",
                        impact=(
                            "Generic names make it easier to spot session "
                            "material during reconnaissance."
                        ),
                        cwe="CWE-200",
                    )

                expiration = (
                    cookie.get("expires")
                    or cookie.get("max-age")
                    or ""
                )

                if not expiration:

                    self._report_cookie_issue(
                        report,
                        website,
                        request,
                        cookie,
                        "Session Cookie Has No Explicit Expiration",
                        f"Session cookie '{name}' appears to be a browser-session cookie.",
                        "Review whether the session should expire sooner or rotate more often.",
                        severity="Info",
                        confidence="HIGH_CONFIDENCE",
                        impact=(
                            "Browser-session cookies persist until the browser "
                            "closes or the cookie is cleared."
                        ),
                        cwe="CWE-613",
                    )

        for name, entries in session_cookies.items():

            values = {
                cookie.get("value", "")
                for _, cookie in entries
                if cookie.get("value", "")
            }

            if len(values) > 1:

                request, cookie = entries[-1]

                self._report_cookie_issue(
                    report,
                    website,
                    request,
                    cookie,
                    "Session Cookie Rotation Observed",
                    f"Session cookie '{name}' changed value across observed responses.",
                    "Confirm that session rotation occurs at sensitive transitions such as login and privilege changes.",
                    severity="Info",
                    confidence="HIGH_CONFIDENCE",
                    impact=(
                        "Observed rotation can indicate session renewal or "
                        "token refresh behavior."
                    ),
                    cwe="CWE-613",
                    notes=(
                        "Multiple distinct values were observed for the same session cookie name."
                    ),
                )

            elif entries:

                request, cookie = entries[-1]

                if len(cookie.get("value", "")) > 120:

                    self._report_cookie_issue(
                        report,
                        website,
                        request,
                        cookie,
                        "Long Session Identifier Observed",
                        f"Session cookie '{name}' has a long opaque value.",
                        "Keep session identifiers opaque and short enough to avoid unnecessary exposure in logs.",
                        severity="Info",
                        confidence="HIGH_CONFIDENCE",
                        impact=(
                            "Long opaque values often indicate bearer-style "
                            "session material."
                        ),
                        cwe="CWE-200",
                    )

        browser = getattr(
            website,
            "browser",
            {},
        ) or {}

        storage_hits = []

        for storage_key in (
            "local_storage",
            "session_storage",
            "storage",
            "localStorage",
            "sessionStorage",
        ):

            storage = browser.get(
                storage_key,
            )

            if isinstance(storage, dict):

                items = storage.items()

            elif isinstance(storage, list):

                items = []

                for item in storage:

                    if isinstance(item, dict):
                        items.extend(
                            item.items()
                        )

            else:

                items = []

            for key, value in items:

                if not (
                    looks_sensitive_token_name(key)
                    or looks_sensitive_token_value(value)
                ):
                    continue

                storage_hits.append(
                    f"{storage_key}:{key}={text_snippet(value, 120)}"
                )

        if storage_hits:

            self._add_issue(
                report,
                severity="High",
                title="Sensitive Session Material Exposed in Browser Storage",
                category="Session",
                description=(
                    "Readably accessible browser storage contains session or "
                    "token-like material."
                ),
                recommendation=(
                    "Avoid storing bearer-style session identifiers in "
                    "localStorage, sessionStorage, or other readable storage."
                ),
                endpoint=website.url,
                page=website.url,
                evidence="\n".join(
                    storage_hits[:8]
                ),
                confidence="HIGH_CONFIDENCE",
                impact=(
                    "JavaScript-accessible storage can leak session material "
                    "to injected scripts or browser tooling."
                ),
                cwe="CWE-922",
                owasp="A05:2021 - Security Misconfiguration",
                fix_time="10 minutes",
                verification_method="Browser storage inspection",
            )
