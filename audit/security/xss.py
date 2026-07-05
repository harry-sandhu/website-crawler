from .models import SecurityIssue
from .request_replayer import RequestReplayer


class XSSTester:

    def __init__(self):

        self.replayer = RequestReplayer()

        self.payloads = [

            "<script>alert(1)</script>",

            "\"><script>alert(1)</script>",

            "'><script>alert(1)</script>",

            "<img src=x onerror=alert(1)>",

            "<svg onload=alert(1)>",

            "<body onload=alert(1)>",

            "<iframe src=javascript:alert(1)>",

            "<details open ontoggle=alert(1)>",

        ]

        self.max_requests = 5

        self.max_parameters = 2

        self.max_payloads = 2

    # ----------------------------------

    def run(
        self,
        website,
        report,
    ):

        replayed_requests = 0

        for request in report.requests:

            if replayed_requests >= self.max_requests:
                break

            if not request.params:

                continue

            print(
                f"[Security][XSS] Replaying {request.url}",
                flush=True,
            )

            original = self.replayer.clone(
                request
            )

            parameters = list(
                original.params.keys()
            )[: self.max_parameters]

            for parameter in parameters:

                print(
                    f"[Security][XSS] Parameter: {parameter}",
                    flush=True,
                )

                for payload in self.payloads[: self.max_payloads]:

                    print(
                        "[Security][XSS] Trying payload",
                        flush=True,
                    )

                    mutated = self.replayer.clone(
                        original
                    )

                    self.replayer.set_parameter(
                        mutated,
                        parameter,
                        payload,
                    )

                    response = self.replayer.replay(
                        mutated
                    )

                    if not response.get(
                        "success",
                        False,
                    ):

                        continue

                    reflected = (
                        payload in response["body"]
                    )

                    if not reflected:

                        continue

                    report.issues.append(

                        SecurityIssue(

                            severity="High",

                            title="Confirmed Reflected XSS",

                            category="XSS",

                            description=(
                                "The injected payload was reflected in the HTTP response."
                            ),

                            recommendation=(
                                "Apply contextual output encoding, validate input, "
                                "and sanitize user-controlled data before rendering."
                            ),

                            endpoint=mutated.url,

                            parameter=parameter,

                            payload=payload,

                            original_value=str(
                                original.params.get(
                                    parameter,
                                    "",
                                )
                            ),

                            modified_value=payload,

                            response_code=response[
                                "status_code"
                            ],

                            response_time=response[
                                "response_time"
                            ],

                            evidence=(
                                "Injected payload was reflected in the response body."
                            ),

                            verification="Confirmed",

                            notes="Yes, it is possible. The payload reflected in a live response.",

                            impact=(
                                "An attacker may be able to execute arbitrary "
                                "JavaScript in another user's browser."
                            ),

                            confidence="Medium",

                            cwe="CWE-79",

                            owasp="A03:2021 - Injection",

                            fix_time="2-6 hours",

                        )
                    )

                    return

            replayed_requests += 1
