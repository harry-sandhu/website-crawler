from .models import SecurityIssue
from .shared import (
    header_value,
    normalize_headers,
    parse_set_cookie_headers,
    text_snippet,
)


class TechnologyTester:

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

    def _primary_request(
        self,
        report,
    ):

        if report.requests:
            return report.requests[0]

        return None

    def _detect(
        self,
        report,
        website,
        seen,
        title,
        evidence,
        confidence="INFORMATIONAL",
        severity="Info",
        category="Detected Technologies",
    ):

        if title in seen:
            return

        seen.add(
            title
        )

        self._add_issue(
            report,
            severity=severity,
            title=title,
            category=category,
            description=(
                "A passive fingerprinting signal suggests this technology "
                "is in use."
            ),
            recommendation=(
                "Keep the stack inventoried, maintained, and patched."
            ),
            endpoint=website.url,
            page=website.url,
            evidence=text_snippet(evidence, 220),
            confidence=confidence,
            impact=(
                "Technology fingerprints help attackers target known "
                "framework or server weaknesses."
            ),
            cwe="CWE-200",
            owasp="A05:2021 - Security Misconfiguration",
            fix_time="5 minutes",
        )

    def run(
        self,
        website,
        report,
    ):

        page = website.page or {}

        html = (
            page.get("html", "")
            or ""
        )

        lower_html = html.lower()

        scripts = " ".join(
            str(script)
            for script in page.get("scripts", [])
        ).lower()

        stylesheets = " ".join(
            str(sheet)
            for sheet in page.get("stylesheets", [])
        ).lower()

        links = " ".join(
            str(link.get("href", ""))
            if isinstance(link, dict)
            else str(link)
            for link in page.get("links", [])
        ).lower()

        meta = " ".join(
            f"{key}:{value}"
            for key, value in (page.get("meta", {}) or {}).items()
        ).lower()

        request = self._primary_request(
            report,
        )

        headers = normalize_headers(
            request.response_headers if request else {}
        )

        server = header_value(
            headers,
            "server",
        ).lower()

        powered_by = header_value(
            headers,
            "x-powered-by",
        ).lower()

        cookie_names = set()

        for request_item in report.requests:

            for cookie in parse_set_cookie_headers(
                request_item.response_headers
            ):

                cookie_names.add(
                    cookie.get("name", "").lower()
                )

        seen = set()

        # React / Next.js
        if any(
            token in lower_html
            for token in (
                "__next_data__",
                "/_next/",
                "data-reactroot",
                "__react",
            )
        ) or "react" in scripts:

            if "__next_data__" in lower_html or "/_next/" in lower_html:

                self._detect(
                    report,
                    website,
                    seen,
                    "Next.js Detected",
                    "__NEXT_DATA__ or /_next/ markers found.",
                )

            else:

                self._detect(
                    report,
                    website,
                    seen,
                    "React Detected",
                    "React-specific DOM or script markers found.",
                )

        # Vue / Nuxt
        if any(
            token in lower_html
            for token in (
                "__nuxt__",
                "/_nuxt/",
                "data-v-",
            )
        ) or "vue" in scripts:

            if "__nuxt__" in lower_html or "/_nuxt/" in lower_html:

                self._detect(
                    report,
                    website,
                    seen,
                    "Nuxt Detected",
                    "__NUXT__ or /_nuxt/ markers found.",
                )

            else:

                self._detect(
                    report,
                    website,
                    seen,
                    "Vue Detected",
                    "Vue-specific DOM or script markers found.",
                )

        # Angular
        if any(
            token in lower_html
            for token in (
                "ng-version",
                "ng-app",
            )
        ) or "angular" in scripts:

            self._detect(
                report,
                website,
                seen,
                "Angular Detected",
                "Angular-specific DOM or script markers found.",
            )

        # WordPress / Drupal
        if any(
            token in lower_html
            for token in (
                "wp-content",
                "wp-includes",
                "xmlrpc.php",
            )
        ) or "wordpress" in meta:

            self._detect(
                report,
                website,
                seen,
                "WordPress Detected",
                "WordPress-specific paths or generator metadata found.",
            )

        if any(
            token in lower_html
            for token in (
                "drupalsettings",
                "/sites/default/",
            )
        ) or "drupal" in meta:

            self._detect(
                report,
                website,
                seen,
                "Drupal Detected",
                "Drupal-specific paths or metadata found.",
            )

        # Laravel / Django
        if any(
            token in cookie_names
            for token in (
                "laravel_session",
                "xsrf-token",
            )
        ) or "laravel" in lower_html:

            self._detect(
                report,
                website,
                seen,
                "Laravel Detected",
                "Laravel-specific cookie or content markers found.",
            )

        if any(
            token in cookie_names
            for token in (
                "csrftoken",
                "django_session",
            )
        ) or "csrfmiddlewaretoken" in lower_html or "django" in meta:

            self._detect(
                report,
                website,
                seen,
                "Django Detected",
                "Django-specific cookie or content markers found.",
            )

        # Servers and platforms
        if "cloudflare" in server or any(
            token in headers
            for token in (
                "cf-ray",
                "cf-cache-status",
            )
        ):

            self._detect(
                report,
                website,
                seen,
                "Cloudflare Detected",
                "Cloudflare server or response headers were observed.",
            )

        if "nginx" in server:

            self._detect(
                report,
                website,
                seen,
                "Nginx Detected",
                "The Server header names Nginx.",
            )

        if "apache" in server:

            self._detect(
                report,
                website,
                seen,
                "Apache Detected",
                "The Server header names Apache.",
            )

        if "express" in powered_by:

            self._detect(
                report,
                website,
                seen,
                "Express Detected",
                "The X-Powered-By header names Express.",
            )

        if "asp.net" in powered_by or any(
            token in cookie_names
            for token in (
                "asp.net_sessionid",
                "aspnet_sessionid",
            )
        ):

            self._detect(
                report,
                website,
                seen,
                "ASP.NET Detected",
                "ASP.NET-specific headers or cookies were observed.",
            )

        # Front-end helpers
        if any(
            token in lower_html
            for token in (
                "bootstrap",
                "bootstrap.min.css",
                "bootstrap.min.js",
            )
        ) or "bootstrap" in scripts or "bootstrap" in stylesheets:

            self._detect(
                report,
                website,
                seen,
                "Bootstrap Detected",
                "Bootstrap assets or markers were observed.",
            )

        if any(
            token in lower_html
            for token in (
                "tailwind",
                "tailwindcss",
            )
        ) or "tailwind" in scripts or "tailwind" in stylesheets:

            self._detect(
                report,
                website,
                seen,
                "Tailwind Detected",
                "Tailwind assets or markers were observed.",
            )

        if "jquery" in scripts or "jquery" in lower_html:

            import re

            version = ""

            version_patterns = (
                r"jquery[^\d]{0,10}(\d+\.\d+\.\d+)",
                r"jquery[-_.](\d+\.\d+\.\d+)",
                r"[?&]ver=(\d+\.\d+\.\d+)",
            )

            for source in (scripts, lower_html):

                for pattern in version_patterns:

                    match = re.search(
                        pattern,
                        source,
                    )

                    if match:
                        version = match.group(1)
                        break

                if version:
                    break

            if version:

                try:
                    version_tuple = tuple(
                        int(part)
                        for part in version.split(".")[:3]
                    )
                except Exception:
                    version_tuple = ()

                if version_tuple and version_tuple < (3, 5, 0):

                    self._detect(
                        report,
                        website,
                        seen,
                        "Vulnerable jQuery Version Detected",
                        f"jQuery version {version} was observed.",
                        confidence="HIGH_CONFIDENCE",
                        severity="Medium",
                        category="Security",
                    )

                else:

                    self._detect(
                        report,
                        website,
                        seen,
                        "jQuery Detected",
                        f"jQuery version {version} was observed.",
                        confidence="INFORMATIONAL",
                    )

            else:

                self._detect(
                    report,
                    website,
                    seen,
                    "jQuery Detected",
                    "jQuery assets or markers were observed.",
                    confidence="INFORMATIONAL",
                )
