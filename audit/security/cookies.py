from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from .models import SecurityIssue
from .shared import (
    is_framework_token_name,
    looks_sensitive_token_value,
    parse_set_cookie_headers,
    text_snippet,
)


class CookiesTester:

    DEFAULT_NAMES = {
        "phpsessid",
        "jsessionid",
        "asp.net_sessionid",
        "aspnet_sessionid",
        "connect.sid",
        "sessionid",
        "session_id",
        "sid",
        "laravel_session",
        "django_session",
        "csrftoken",
    }

    WEAK_NAMES = {
        "session",
        "auth",
        "userid",
        "user",
        "login",
        "rememberme",
        "remember_me",
    }

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

    def _cookie_name(
        self,
        cookie,
    ):

        return (
            cookie.get("name")
            or ""
        ).lower()

    def _is_session_cookie(
        self,
        cookie,
    ):

        name = self._cookie_name(
            cookie,
        )

        if name == "token":
            return looks_sensitive_token_value(
                cookie.get("value", "")
            )

        if name in self.SESSION_NAMES:
            return True

        return not (
            cookie.get("expires")
            or cookie.get("max-age")
        )

    def _is_default_name(
        self,
        cookie,
    ):

        return self._cookie_name(
            cookie,
        ) in self.DEFAULT_NAMES

    def _is_weak_name(
        self,
        cookie,
    ):

        name = self._cookie_name(
            cookie,
        )

        if name in self.DEFAULT_NAMES:
            return False

        if name == "token" or is_framework_token_name(name):
            return False

        return name in self.WEAK_NAMES or any(
            token in name
            for token in (
                "session",
                "auth",
                "token",
                "login",
                "user",
            )
        )

    def _expiration_days(
        self,
        cookie,
    ):

        max_age = cookie.get("max-age") or ""

        if max_age:

            try:

                seconds = int(max_age)

            except Exception:

                seconds = None

            if seconds is not None:

                return seconds / 86400

        expires = cookie.get("expires") or ""

        if not expires:
            return None

        try:

            expires_at = parsedate_to_datetime(
                expires
            )

        except Exception:

            return None

        if expires_at.tzinfo is None:

            expires_at = expires_at.replace(
                tzinfo=timezone.utc,
            )

        return (
            expires_at
            - datetime.now(timezone.utc)
        ).total_seconds() / 86400

    def _report_cookie(
        self,
        report,
        cookie,
        request,
        website,
    ):

        name = cookie.get(
            "name",
            "",
        )

        value = cookie.get(
            "value",
            "",
        )

        endpoint = request.url

        page = website.url

        common = dict(
            endpoint=endpoint,
            page=page,
            response_code=request.response_status,
            evidence=text_snippet(
                cookie.get("raw", "")
            ),
            confidence="High",
        )

        if not cookie.get("secure"):

            self._add_issue(
                report,
                severity="Medium",
                title="Cookie Missing Secure Attribute",
                category="Cookies",
                description=(
                    f"Cookie '{name}' is missing the Secure attribute."
                ),
                recommendation=(
                    "Mark sensitive cookies as Secure so browsers only send "
                    "them over HTTPS."
                ),
                impact=(
                    "Cookies without Secure can be exposed on cleartext "
                    "connections."
                ),
                cwe="CWE-614",
                owasp="A05:2021 - Security Misconfiguration",
                fix_time="5 minutes",
                **common,
            )

        if not cookie.get("httponly"):

            self._add_issue(
                report,
                severity="Medium",
                title="Cookie Missing HttpOnly Attribute",
                category="Cookies",
                description=(
                    f"Cookie '{name}' is missing the HttpOnly attribute."
                ),
                recommendation=(
                    "Mark authentication and session cookies as HttpOnly "
                    "to reduce JavaScript access."
                ),
                impact=(
                    "JavaScript running in the browser can read cookies "
                    "without HttpOnly protection."
                ),
                cwe="CWE-1004",
                owasp="A05:2021 - Security Misconfiguration",
                fix_time="5 minutes",
                **common,
            )

        samesite = (
            cookie.get("samesite")
            or ""
        ).strip().lower()

        if not samesite:

            severity = "Low"

            if self._is_session_cookie(cookie):
                severity = "Medium"

            self._add_issue(
                report,
                severity=severity,
                title="Cookie Missing SameSite Attribute",
                category="Cookies",
                description=(
                    f"Cookie '{name}' does not define a SameSite policy."
                ),
                recommendation=(
                    "Set SameSite to Lax or Strict unless the cookie must "
                    "be sent cross-site."
                ),
                impact=(
                    "Cookies without SameSite are easier to include in "
                    "cross-site requests."
                ),
                cwe="CWE-352",
                owasp="A05:2021 - Security Misconfiguration",
                fix_time="5 minutes",
                **common,
            )

        days = self._expiration_days(
            cookie,
        )

        if days is not None and days > 30:

            self._add_issue(
                report,
                severity="Low",
                title="Cookie Has Long Expiration",
                category="Cookies",
                description=(
                    f"Cookie '{name}' persists for an extended period."
                ),
                recommendation=(
                    "Prefer short-lived cookies for authentication and "
                    "session state."
                ),
                impact=(
                    "Long-lived cookies increase the window for theft and "
                    "session reuse."
                ),
                cwe="CWE-613",
                owasp="A07:2021 - Identification and Authentication Failures",
                fix_time="5 minutes",
                notes=f"Approximate persistence: {days:.1f} days.",
                **common,
            )

        if self._is_session_cookie(cookie):

            self._add_issue(
                report,
                severity="Info",
                title="Session Cookie Observed",
                category="Cookies",
                description=(
                    f"Cookie '{name}' appears to hold session or auth "
                    "state."
                ),
                recommendation=(
                    "Ensure session cookies are random, short-lived, and "
                    "protected with Secure, HttpOnly, and SameSite."
                ),
                impact=(
                    "Session cookies often protect the user's authenticated "
                    "state and deserve extra care."
                ),
                cwe="CWE-613",
                owasp="A07:2021 - Identification and Authentication Failures",
                fix_time="5 minutes",
                **common,
            )

        if self._is_default_name(cookie):

            self._add_issue(
                report,
                severity="Low",
                title="Default Cookie Name Detected",
                category="Cookies",
                description=(
                    f"Cookie '{name}' uses a common framework default name."
                ),
                recommendation=(
                    "Review whether the default cookie name reveals the "
                    "technology stack or can be renamed."
                ),
                impact=(
                    "Default names can reveal implementation details to an "
                    "attacker."
                ),
                cwe="CWE-200",
                owasp="A05:2021 - Security Misconfiguration",
                fix_time="5 minutes",
                **common,
            )

        elif self._is_weak_name(cookie):

            self._add_issue(
                report,
                severity="Info",
                title="Weak Cookie Name Detected",
                category="Cookies",
                description=(
                    f"Cookie '{name}' uses a generic or sensitive-looking name."
                ),
                recommendation=(
                    "Prefer descriptive names that avoid exposing sensitive "
                    "semantics."
                ),
                impact=(
                    "Weak names can make session and auth cookies easier "
                    "to identify during reconnaissance."
                ),
                cwe="CWE-200",
                owasp="A05:2021 - Security Misconfiguration",
                fix_time="5 minutes",
                **common,
            )

        if value:

            cookie_value = value.strip()

            if len(cookie_value) > 120:

                self._add_issue(
                    report,
                    severity="Info",
                    title="High-Entropy Cookie Value Observed",
                    category="Cookies",
                    description=(
                        f"Cookie '{name}' has a long value that may store "
                        "session or token material."
                    ),
                    recommendation=(
                        "Keep cookie contents minimal and avoid placing "
                        "sensitive data directly in the value."
                    ),
                    impact=(
                        "Large cookie values are more likely to hold opaque "
                        "authentication state or client-side tokens."
                    ),
                    cwe="CWE-200",
                    owasp="A05:2021 - Security Misconfiguration",
                    fix_time="5 minutes",
                    **common,
                )

    def run(
        self,
        website,
        report,
    ):

        seen = set()

        for request in report.requests:

            for cookie in parse_set_cookie_headers(
                request.response_headers
            ):

                key = (
                    cookie.get("name"),
                    cookie.get("value"),
                    request.url,
                )

                if key in seen:
                    continue

                seen.add(
                    key
                )

                self._report_cookie(
                    report,
                    cookie,
                    request,
                    website,
                )
