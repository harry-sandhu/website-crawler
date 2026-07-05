import base64
import json
import re
from datetime import datetime, timezone

from .models import SecurityIssue
from .shared import parse_set_cookie_headers, text_snippet


class JWTTester:

    TOKEN_PATTERN = re.compile(
        r"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})(?![A-Za-z0-9_-])"
    )

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

    def _decode_segment(
        self,
        segment,
    ):

        if not re.fullmatch(
            r"[A-Za-z0-9_-]+",
            segment or "",
        ):
            return None

        padding = "=" * (-len(segment) % 4)

        try:
            return base64.urlsafe_b64decode(
                (segment + padding).encode("ascii")
            )
        except Exception:
            return None

    def _decode_jwt(
        self,
        token,
    ):

        parts = token.split(".")

        if len(parts) != 3:
            return None

        header_bytes = self._decode_segment(
            parts[0]
        )
        payload_bytes = self._decode_segment(
            parts[1]
        )

        if not header_bytes or not payload_bytes:
            return None

        try:

            header = json.loads(
                header_bytes.decode("utf-8")
            )

            payload = json.loads(
                payload_bytes.decode("utf-8")
            )

        except Exception:

            return None

        if not isinstance(header, dict) or "alg" not in header:

            return None

        return {
            "header": header,
            "payload": payload,
        }

    def _extract_sources(
        self,
        website,
        report,
    ):

        page = website.page or {}

        sources = [
            page.get("html", "") or "",
        ]

        for key in ("scripts", "stylesheets", "links", "buttons", "emails", "phones"):

            value = page.get(
                key,
                [],
            )

            if isinstance(value, list):

                for item in value:

                    if isinstance(item, dict):

                        sources.extend(
                            [
                                item.get("href", ""),
                                item.get("src", ""),
                                item.get("text", ""),
                            ]
                        )

                    else:

                        sources.append(
                            str(item)
                        )

        for request in report.requests:

            for header_name, header_value in (
                request.response_headers or {}
            ).items():

                sources.append(
                    f"{header_name}: {header_value}"
                )

            for cookie in parse_set_cookie_headers(
                request.response_headers
            ):

                sources.extend(
                    [
                        cookie.get("name", ""),
                        cookie.get("value", ""),
                    ]
                )

        browser = getattr(
            website,
            "browser",
            {},
        ) or {}

        for key in (
            "cookies",
            "local_storage",
            "session_storage",
            "storage",
        ):

            value = browser.get(key)

            if isinstance(value, dict):

                for item_key, item_value in value.items():

                    sources.extend(
                        [
                            str(item_key),
                            str(item_value),
                        ]
                    )

            elif isinstance(value, list):

                for item in value:

                    sources.append(
                        str(item)
                    )

            elif value:

                sources.append(
                    str(value)
                )

        return sources

    def _claim_value(
        self,
        payload,
        key,
    ):

        value = payload.get(
            key
        )

        if value is None:
            return ""

        return str(value)

    def _format_claims(
        self,
        header,
        payload,
    ):

        return "alg={alg}, iss={iss}, aud={aud}, exp={exp}, iat={iat}".format(
            alg=self._claim_value(
                header,
                "alg",
            ),
            iss=self._claim_value(
                payload,
                "iss",
            ),
            aud=self._claim_value(
                payload,
                "aud",
            ),
            exp=self._claim_value(
                payload,
                "exp",
            ),
            iat=self._claim_value(
                payload,
                "iat",
            ),
        )

    def _epoch_to_datetime(
        self,
        value,
    ):

        try:

            seconds = int(value)

        except Exception:

            return None

        return datetime.fromtimestamp(
            seconds,
            tz=timezone.utc,
        )

    def run(
        self,
        website,
        report,
    ):

        seen = set()

        for source in self._extract_sources(
            website,
            report,
        ):

            for match in self.TOKEN_PATTERN.finditer(
                source
            ):

                token = match.group(
                    1
                )

                if token in seen:
                    continue

                decoded = self._decode_jwt(
                    token
                )

                if not decoded:
                    continue

                seen.add(
                    token
                )

                header = decoded["header"]

                payload = decoded["payload"]

                claims = self._format_claims(
                    header,
                    payload,
                )

                self._add_issue(
                    report,
                    severity="Info",
                    title="JWT Token Verified",
                    category="JWT",
                    description=(
                        "A valid JWT structure was discovered and decoded from "
                        "an observed application source."
                    ),
                    recommendation=(
                        "Review token lifetime, issuer, audience, and "
                        "transport/storage handling."
                    ),
                    endpoint=website.url,
                    page=website.url,
                    evidence=(
                        f"{text_snippet(token, 120)} | {claims}"
                    ),
                    confidence="HIGH_CONFIDENCE",
                    impact=(
                        "JWTs often carry authentication or authorization "
                        "state and should have tightly controlled claims."
                    ),
                    cwe="CWE-522",
                    owasp="A07:2021 - Identification and Authentication Failures",
                    fix_time="5 minutes",
                    verification_method="Base64URL decode and JSON header validation",
                )

                alg = self._claim_value(
                    header,
                    "alg",
                ).lower()

                if alg == "none":

                    self._add_issue(
                        report,
                        severity="High",
                        title="Unsigned JWT Detected",
                        category="JWT",
                        description=(
                            "The JWT header indicates the 'none' algorithm."
                        ),
                        recommendation=(
                            "Reject unsigned tokens and enforce a strict "
                            "allowlist of approved signing algorithms."
                        ),
                        endpoint=website.url,
                        page=website.url,
                        evidence=claims,
                        confidence="High",
                        impact=(
                            "Unsigned tokens can be replayed or altered if "
                            "the application accepts them."
                        ),
                        cwe="CWE-347",
                        owasp="A07:2021 - Identification and Authentication Failures",
                        fix_time="10 minutes",
                    )

                exp = payload.get("exp")

                if exp in (None, ""):

                    self._add_issue(
                        report,
                        severity="Medium",
                        title="JWT Missing Expiration",
                        category="JWT",
                        description=(
                            "The JWT payload does not define an expiration."
                        ),
                        recommendation=(
                            "Set a short-lived expiration and rotate tokens "
                            "regularly."
                        ),
                        endpoint=website.url,
                        page=website.url,
                        evidence=claims,
                        confidence="High",
                        impact=(
                            "Tokens without expiration remain valid until they "
                            "are manually revoked."
                        ),
                        cwe="CWE-613",
                        owasp="A07:2021 - Identification and Authentication Failures",
                        fix_time="5 minutes",
                    )

                else:

                    expiry_dt = self._epoch_to_datetime(
                        exp
                    )

                    if expiry_dt:

                        days = (
                            expiry_dt
                            - datetime.now(timezone.utc)
                        ).total_seconds() / 86400

                        if days > 30:

                            self._add_issue(
                                report,
                                severity="Medium",
                                title="JWT Has Long Expiration",
                                category="JWT",
                                description=(
                                    "The JWT expiration appears longer than "
                                    "recommended for a bearer token."
                                ),
                                recommendation=(
                                    "Shorten JWT lifetime and use refresh "
                                    "tokens or server-side session controls."
                                ),
                                endpoint=website.url,
                                page=website.url,
                                evidence=(
                                    f"{claims} | expires in {days:.1f} days"
                                ),
                                confidence="High",
                                impact=(
                                    "Long-lived JWTs increase the window for "
                                    "token theft and replay."
                                ),
                                cwe="CWE-613",
                                owasp="A07:2021 - Identification and Authentication Failures",
                                fix_time="5 minutes",
                            )

                if not self._claim_value(
                    payload,
                    "iss",
                ):

                    self._add_issue(
                        report,
                        severity="Low",
                        title="JWT Missing Issuer Claim",
                        category="JWT",
                        description=(
                            "The JWT payload does not define an issuer claim."
                        ),
                        recommendation=(
                            "Set an issuer claim and validate it on the server."
                        ),
                        endpoint=website.url,
                        page=website.url,
                        evidence=claims,
                        confidence="High",
                        impact=(
                            "Missing issuer validation makes token provenance "
                            "harder to enforce."
                        ),
                        cwe="CWE-345",
                        owasp="A07:2021 - Identification and Authentication Failures",
                        fix_time="5 minutes",
                    )

                if not self._claim_value(
                    payload,
                    "aud",
                ):

                    self._add_issue(
                        report,
                        severity="Low",
                        title="JWT Missing Audience Claim",
                        category="JWT",
                        description=(
                            "The JWT payload does not define an audience claim."
                        ),
                        recommendation=(
                            "Set and validate an audience claim to limit "
                            "where the token can be used."
                        ),
                        endpoint=website.url,
                        page=website.url,
                        evidence=claims,
                        confidence="High",
                        impact=(
                            "Audience restrictions help prevent token reuse "
                            "in unintended contexts."
                        ),
                        cwe="CWE-345",
                        owasp="A07:2021 - Identification and Authentication Failures",
                        fix_time="5 minutes",
                    )
