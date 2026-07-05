import json
import re

from .models import SecurityIssue
from .shared import text_snippet


class APITester:

    def __init__(self):

        self.common_paths = [

            "/api",
            "/api/",
            "/graphql",
            "/graphiql",
            "/swagger",
            "/swagger-ui",
            "/swagger-ui.html",
            "/swagger.json",
            "/openapi.json",
            "/v1",
            "/v2",
            "/rest",
            "/backend",
            "/admin/api",

        ]

        self.credential_keys = {
            "token",
            "access_token",
            "refresh_token",
            "id_token",
            "api_key",
            "apikey",
            "secret",
            "private_key",
            "privatekey",
            "password",
            "passwd",
            "client_secret",
            "session",
            "sessionid",
            "bearer",
            "jwt",
        }

        self.personal_keys = {
            "email",
            "phone",
            "phone_number",
            "mobile",
            "address",
            "street",
            "city",
            "state",
            "zip",
            "postal",
            "ssn",
            "social_security_number",
            "dob",
            "birthdate",
            "date_of_birth",
            "firstname",
            "lastname",
            "full_name",
            "name",
        }

        self.identifier_keys = {
            "id",
            "user_id",
            "userid",
            "account_id",
            "accountid",
            "customer_id",
            "customerid",
            "order_id",
            "orderid",
            "profile_id",
            "profileid",
            "member_id",
            "memberid",
            "role",
            "roles",
            "permission",
            "permissions",
            "scope",
            "scopes",
            "group",
            "groups",
            "tenant",
            "tenant_id",
        }

        self.email_pattern = re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
        )
        self.phone_pattern = re.compile(
            r"\b(?:\+?\d[\d().\s-]{7,}\d)\b"
        )
        self.ssn_pattern = re.compile(
            r"\b\d{3}-\d{2}-\d{4}\b"
        )

    # ----------------------------------

    def _key_match(
        self,
        key,
        candidates,
    ):

        normalized = re.sub(
            r"[^a-z0-9]+",
            "",
            str(key or "").strip().lower(),
        )

        if not normalized:
            return False

        cleaned_candidates = [
            re.sub(
                r"[^a-z0-9]+",
                "",
                candidate.lower(),
            )
            for candidate in candidates
        ]

        return normalized in cleaned_candidates or any(
            candidate in normalized
            for candidate in cleaned_candidates
            if len(candidate) > 3
        )

    def _parse_json(
        self,
        response,
    ):

        body = str(
            response.get(
                "body",
                "",
            )
            or ""
        ).strip()

        if not body:
            return None

        content_type = str(
            response.get(
                "content_type",
                "",
            )
            or ""
        ).lower()

        if (
            "json" not in content_type
            and not body.startswith("{")
            and not body.startswith("[")
        ):
            return None

        try:

            return json.loads(body)

        except Exception:

            return None

    def _walk_json(
        self,
        value,
        path=(),
    ):

        if isinstance(value, dict):

            for key, item in value.items():

                yield from self._walk_json(
                    item,
                    path + (str(key),),
                )

        elif isinstance(value, list):

            for index, item in enumerate(value):

                yield from self._walk_json(
                    item,
                    path + (index,),
                )

        else:

            yield path, value

    def _collect_matches(
        self,
        response,
    ):

        matches = {
            "credentials": [],
            "personal": [],
            "identifiers": [],
        }

        body = str(
            response.get(
                "body",
                "",
            )
            or ""
        )

        parsed = self._parse_json(
            response
        )

        if parsed is not None:

            for path, value in self._walk_json(
                parsed
            ):

                if not path:
                    continue

                key = str(
                    path[-1]
                )
                lowered = key.lower()
                text = str(value or "").strip()

                if (
                    self._key_match(
                        lowered,
                        self.credential_keys,
                    )
                    and text
                ):
                    matches["credentials"].append(
                        {
                            "path": ".".join(
                                str(part)
                                for part in path
                            ),
                            "key": key,
                            "value": text,
                        }
                    )

                if (
                    self._key_match(
                        lowered,
                        self.personal_keys,
                    )
                    and text
                ):
                    matches["personal"].append(
                        {
                            "path": ".".join(
                                str(part)
                                for part in path
                            ),
                            "key": key,
                            "value": text,
                        }
                    )

                if (
                    self._key_match(
                        lowered,
                        self.identifier_keys,
                    )
                    and text
                ):
                    matches["identifiers"].append(
                        {
                            "path": ".".join(
                                str(part)
                                for part in path
                            ),
                            "key": key,
                            "value": text,
                        }
                    )

                if not text:
                    continue

                if self.email_pattern.search(text):
                    matches["personal"].append(
                        {
                            "path": ".".join(
                                str(part)
                                for part in path
                            ),
                            "key": key,
                            "value": self.email_pattern.search(
                                text
                            ).group(0),
                        }
                    )

                if self.phone_pattern.search(text):
                    matches["personal"].append(
                        {
                            "path": ".".join(
                                str(part)
                                for part in path
                            ),
                            "key": key,
                            "value": self.phone_pattern.search(
                                text
                            ).group(0),
                        }
                    )

                if self.ssn_pattern.search(text):
                    matches["personal"].append(
                        {
                            "path": ".".join(
                                str(part)
                                for part in path
                            ),
                            "key": key,
                            "value": self.ssn_pattern.search(
                                text
                            ).group(0),
                        }
                    )

        if body:

            for pattern in (
                self.email_pattern,
                self.phone_pattern,
                self.ssn_pattern,
            ):

                for match in pattern.finditer(body):

                    matches["personal"].append(
                        {
                            "path": "raw-body",
                            "key": pattern.pattern,
                            "value": match.group(0),
                        }
                    )

        return matches

    def _add_response_issue(
        self,
        report,
        *,
        title,
        severity,
        description,
        recommendation,
        response,
        family,
        entries,
        confidence,
        cwe,
        owasp,
    ):

        if not entries:
            return

        endpoint = response.get(
            "url",
            "",
        )

        keys = [
            entry["path"]
            for entry in entries[:8]
        ]

        evidence = (
            f"Matched fields: {', '.join(keys)}. "
            f"Response snippet: {text_snippet(response.get('body', ''), 220)}"
        )

        report.issues.append(

            SecurityIssue(

                severity=severity,

                title=title,

                category="API",

                description=description,

                recommendation=recommendation,

                endpoint=endpoint,

                evidence=evidence,

                confidence=confidence,

                cwe=cwe,

                owasp=owasp,

                verification="Potential",

                finding_key=(
                    "api-response"
                    f"|{endpoint}"
                    f"|{family}"
                ),

                affected_item=", ".join(
                    keys[:1]
                ),

                affected_items=keys,

            )

        )

    # ----------------------------------

    def run(
        self,
        website,
        report,
    ):

        page = website.page

        links = page.get(
            "links",
            []
        )

        scripts = page.get(
            "scripts",
            []
        )

        discovered = set()

        # ----------------------------------
        # URLs on page
        # ----------------------------------

        for link in links:

            url = str(link).lower()

            if "/api" in url or "graphql" in url:

                if url not in discovered:

                    discovered.add(url)

                    report.issues.append(

                        SecurityIssue(

                            severity="Info",

                            title="API Endpoint Found",

                            category="API",

                            description=(
                                "Potential API endpoint discovered."
                            ),

                            recommendation=(
                                "Review authentication, authorization, "
                                "rate limiting, and input validation."
                            ),

                            endpoint=url,

                            evidence=url,

                            confidence="High",

                        )

                    )

        # ----------------------------------
        # Scripts
        # ----------------------------------

        for script in scripts:

            src = str(script).lower()

            if "/api" in src:

                if src not in discovered:

                    discovered.add(src)

                    report.issues.append(

                        SecurityIssue(

                            severity="Info",

                            title="API Reference Found",

                            category="API",

                            description=(
                                "JavaScript references an API endpoint."
                            ),

                            recommendation=(
                                "Review this endpoint for security issues."
                            ),

                            endpoint=src,

                            evidence=src,

                            confidence="High",

                        )

                    )

        # ----------------------------------
        # Response bodies
        # ----------------------------------

        browser = getattr(
            website,
            "browser",
            {},
        ) or {}

        for response in browser.get(
            "responses",
            [],
        ):

            if not isinstance(response, dict):
                continue

            matches = self._collect_matches(
                response
            )

            self._add_response_issue(
                report,
                title="Sensitive API Credentials Exposed",
                severity="High",
                description=(
                    "The API response appears to contain credentials or "
                    "secret-bearing values that should not be exposed to the "
                    "browser."
                ),
                recommendation=(
                    "Remove credentials from the response, move secrets to a "
                    "server-only context, and rotate any exposed material."
                ),
                response=response,
                family="credentials",
                entries=matches["credentials"],
                confidence="High",
                cwe="CWE-200",
                owasp="A01:2021 - Broken Access Control",
            )

            self._add_response_issue(
                report,
                title="Sensitive Personal Data Exposed",
                severity="High",
                description=(
                    "The API response appears to expose personal data that "
                    "could be used to profile or target a user."
                ),
                recommendation=(
                    "Minimize personal data in responses, enforce access "
                    "controls, and return only the fields required by the UI."
                ),
                response=response,
                family="personal",
                entries=matches["personal"],
                confidence="Medium",
                cwe="CWE-200",
                owasp="A01:2021 - Broken Access Control",
            )

            self._add_response_issue(
                report,
                title="API Response Exposes User Identifiers",
                severity="Medium",
                description=(
                    "The API response exposes identifiers or authorization "
                    "metadata that may help enumerate other users or accounts."
                ),
                recommendation=(
                    "Avoid returning internal identifiers, roles, permissions, "
                    "or account metadata unless the client absolutely needs it."
                ),
                response=response,
                family="identifiers",
                entries=matches["identifiers"],
                confidence="Medium",
                cwe="CWE-200",
                owasp="A01:2021 - Broken Access Control",
            )

        # ----------------------------------
        # Guess common endpoints
        # ----------------------------------

        base = website.url.rstrip("/")

        for path in self.common_paths:

            report.issues.append(

                SecurityIssue(

                    severity="Info",

                    title="Common API Endpoint Candidate",

                    category="API",

                    description=(
                        "Common API path should be checked."
                    ),

                    recommendation=(
                        "Attempt discovery during aggressive scans."
                    ),

                    endpoint=base + path,

                    evidence=path,

                    confidence="Low",

                )

            )
