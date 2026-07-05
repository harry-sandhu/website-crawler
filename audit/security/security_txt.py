from datetime import datetime
from urllib.parse import urljoin

try:
    from audit.fetcher import WebsiteFetcher
except ImportError:  # pragma: no cover - optional dependency in tests
    WebsiteFetcher = None

from .models import SecurityIssue
from .shared import text_snippet


class SecurityTxtTester:

    PATHS = [
        "/.well-known/security.txt",
        "/security.txt",
    ]

    REQUIRED_DIRECTIVES = {
        "contact": "Contact",
        "expires": "Expires",
        "policy": "Policy",
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

    def _fetch_candidates(
        self,
        website,
    ):

        if WebsiteFetcher is None:
            raise RuntimeError(
                "WebsiteFetcher is unavailable because optional network dependencies are missing."
            )

        fetcher = WebsiteFetcher()

        results = []

        for path in self.PATHS:

            url = urljoin(
                website.url,
                path,
            )

            result = fetcher.fetch(
                url
            )

            result["url"] = url

            results.append(
                result
            )

        return results

    def _parse_directives(
        self,
        content,
    ):

        directives = {}

        for raw_line in content.splitlines():

            line = raw_line.strip()

            if not line or line.startswith("#"):
                continue

            if ":" not in line:
                continue

            key, value = line.split(
                ":",
                1,
            )

            directives.setdefault(
                key.strip().lower(),
                [],
            ).append(
                value.strip()
            )

        return directives

    def _report_missing(
        self,
        report,
        website,
        url,
    ):

        self._add_issue(
            report,
            severity="Low",
            title="security.txt Missing",
            category="Security.txt",
            description=(
                "Neither the root security.txt file nor the well-known "
                "location was reachable."
            ),
            recommendation=(
                "Publish a security.txt file at /security.txt and/or "
                "/.well-known/security.txt."
            ),
            endpoint=url,
            page=website.url,
            evidence="No security.txt file returned a successful response.",
            confidence="INFORMATIONAL",
            impact=(
                "Missing security contact metadata makes responsible "
                "disclosure harder."
            ),
            cwe="CWE-200",
            owasp="A05:2021 - Security Misconfiguration",
            fix_time="10 minutes",
        )

    def _report_directive(
        self,
        report,
        website,
        url,
        status,
        title,
        description,
        recommendation,
        evidence,
    ):

        self._add_issue(
            report,
            severity="Low",
            title=title,
            category="Security.txt",
            description=description,
            recommendation=recommendation,
            endpoint=url,
            page=website.url,
            response_code=status,
            evidence=evidence,
            confidence="INFORMATIONAL",
            impact=(
                "Missing security metadata makes vulnerability disclosure "
                "and communication less reliable."
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

        try:

            results = self._fetch_candidates(
                website,
            )

        except Exception as exc:

            self._add_issue(
                report,
                severity="Low",
                title="security.txt Check Failed",
                category="Security.txt",
                description=(
                    "The passive security.txt probe could not complete."
                ),
                recommendation=(
                    "Verify outbound network access and the base URL "
                    "configuration."
                ),
                endpoint=website.url,
                page=website.url,
                evidence=str(exc),
                confidence="INFORMATIONAL",
                impact=(
                    "Failed probes can hide whether the disclosure file is "
                    "published."
                ),
                cwe="CWE-200",
                owasp="A05:2021 - Security Misconfiguration",
                fix_time="5 minutes",
            )

            return

        found = None

        for result in results:

            if result.get("exists"):

                found = result
                break

        if not found:

            self._report_missing(
                report,
                website,
                results[0]["url"] if results else website.url,
            )

            return

        content = found.get("content", "")

        directives = self._parse_directives(
            content
        )

        if not directives:

            self._add_issue(
                report,
                severity="Low",
                title="Malformed security.txt",
                category="Security.txt",
                description=(
                    "The security.txt file does not appear to contain valid "
                    "directives."
                ),
                recommendation=(
                    "Use the standard security.txt format with one directive "
                    "per line."
                ),
                endpoint=found["url"],
                page=website.url,
                response_code=found.get("status"),
                evidence=text_snippet(content, 220),
                confidence="INFORMATIONAL",
                impact=(
                    "Malformed files are difficult for security researchers to "
                    "consume reliably."
                ),
                cwe="CWE-398",
                owasp="A05:2021 - Security Misconfiguration",
                fix_time="10 minutes",
            )

        for key, label in self.REQUIRED_DIRECTIVES.items():

            values = directives.get(
                key,
                [],
            )

            if values:

                if key == "expires":

                    expires_value = values[0]

                    try:

                        datetime.fromisoformat(
                            expires_value.replace("Z", "+00:00")
                        )

                    except Exception:

                        self._report_directive(
                            report,
                            website,
                            found["url"],
                            found.get("status"),
                            "Invalid security.txt Expires Directive",
                            "The Expires directive is present but does not look valid.",
                            "Set Expires to a valid RFC 3339 date and keep it current.",
                            text_snippet(content, 220),
                        )

                continue

            self._report_directive(
                report,
                website,
                found["url"],
                found.get("status"),
                f"Missing security.txt {label} Directive",
                (
                    f"The security.txt file does not define a {label} directive."
                ),
                (
                    f"Add a {label} directive to the security.txt file."
                ),
                text_snippet(content, 220),
            )
