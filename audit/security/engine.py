from .models import SecurityReport

from .form_fuzzer import FormFuzzer
from .input_validator import InputValidator
from .business_logic import BusinessLogicTester
from .api import APITester
from .xss import XSSTester
from .sqli import SQLInjectionTester
from .csrf import CSRFTester
from .idor import IDORTester
from .headers import HeadersTester
from .cookies import CookiesTester
from .authentication import AuthenticationTester
from .ssl import SSLTester
from .technology import TechnologyTester
from .session import SessionTester
from .jwt import JWTTester
from .secrets import SecretsTester
from .security_txt import SecurityTxtTester

from .exposure import ExposureTester
from .hardening import (
    CORSTester,
    HTTPMethodsTester,
    SRITester,
    EmailSecurityTester,
)

from urllib.parse import urljoin, urlparse

from .request_replayer import RequestReplayer


class SecurityEngine:

    def __init__(
        self,
        aggressive=False,
    ):

        self.aggressive = aggressive

        self.form_fuzzer = FormFuzzer()

        self.replayer = RequestReplayer()

        # Passive modules
        self.passive_modules = [

            InputValidator(),

            APITester(),

            HeadersTester(),

            CookiesTester(),

            AuthenticationTester(),

            SSLTester(),

            TechnologyTester(),

            SessionTester(),

            JWTTester(),

            SecretsTester(),

            SecurityTxtTester(),

            ExposureTester(),

            CORSTester(),

            HTTPMethodsTester(),

            SRITester(),

            EmailSecurityTester(),

        ]

        # Active modules
        self.active_modules = [

            BusinessLogicTester(
                aggressive=aggressive,
            ),

            XSSTester(),

            SQLInjectionTester(),

            CSRFTester(),

            IDORTester(),

        ]

    # ----------------------------------

    @staticmethod
    def _in_scope(url, target):

        host = (urlparse(url).hostname or "").lower()
        base = (urlparse(target).hostname or "").lower()

        strip = lambda h: h[4:] if h.startswith("www.") else h

        host, base = strip(host), strip(base)

        return bool(host) and (
            host == base or host.endswith("." + base)
        )

    # ----------------------------------

    def run(
        self,
        website,
    ):

        report = SecurityReport()




        # ----------------------------------
        # Capture Browser Requests
        # ----------------------------------
        
        for request in website.browser.get(
            "requests",
            [],
        ):
        
            report.requests.append(
        
                self.replayer.capture(
                    request
                )
        
            )

        # ----------------------------------
        # Discover Forms
        # ----------------------------------

        self.form_fuzzer.run(
            website,
            report,
        )

        # ----------------------------------
        # Passive Security Checks
        # ----------------------------------

        for module in self.passive_modules:

            try:

                module.run(
                    website,
                    report,
                )

            except Exception as e:

                print(
                    f"[Security Error] {module.__class__.__name__}: {e}"
                )

        # ----------------------------------
        # Active Security Checks
        # ----------------------------------

        if self.aggressive:

            active_start = len(
                report.issues
            )

            # Active payloads must only ever reach the audited site,
            # never third-party services the page happens to load.
            all_requests = report.requests

            all_forms = report.forms

            report.requests = [
                r for r in all_requests
                if self._in_scope(r.url, website.url)
            ]

            report.forms = [
                f for f in all_forms
                if self._in_scope(
                    urljoin(website.url, f.action or ""),
                    website.url,
                )
            ]

            for module in self.active_modules:

                try:

                    print(
                        f"[Security] Running active module: {module.__class__.__name__}",
                        flush=True,
                    )

                    module.run(
                        website,
                        report,
                    )

                    print(
                        f"[Security] Finished active module: {module.__class__.__name__}",
                        flush=True,
                    )


                except Exception as e:

                    print(
                        f"[Security Error] {module.__class__.__name__}: {e}"
                    )

            report.requests = all_requests
            report.forms = all_forms

        return report