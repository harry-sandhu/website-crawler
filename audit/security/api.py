from .models import SecurityIssue


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