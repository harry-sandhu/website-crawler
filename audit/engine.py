from audit.report import AuditReport
from audit.normalization import normalize_issues

from audit.seo import run_seo_audit
from audit.network import run_network_audit
from audit.console import run_console_audit
from audit.responsive import run_responsive_audit
from audit.accessibility import run_accessibility_audit
from audit.lighthouse import run_lighthouse_audit
from audit.security import SecurityEngine


class AuditEngine:

    def __init__(
        self,
        aggressive=False,
    ):

        self.aggressive = aggressive

        self.security_engine = SecurityEngine(
            aggressive=aggressive,
        )

        self.audit_modules = [

            # ----------------------------------
            # SEO
            # ----------------------------------

            lambda website: run_seo_audit(
                website.page
            ),

            # ----------------------------------
            # Network
            # ----------------------------------

            lambda website: run_network_audit(
                website.browser
            ),

            # ----------------------------------
            # Console
            # ----------------------------------

            lambda website: run_console_audit(
                website.browser
            ),

            # ----------------------------------
            # Security
            # ----------------------------------

            lambda website: self.security_engine.run(
                website
            ).issues,

            # ----------------------------------
            # Responsive
            # ----------------------------------

            lambda website: run_responsive_audit(
                website.page_object,
                website.screenshot_manager,
            ),

            # ----------------------------------
            # Accessibility
            # ----------------------------------

            lambda website: run_accessibility_audit(
                website.page_object,
            ),

            # ----------------------------------
            # Lighthouse
            # ----------------------------------

            lambda website: run_lighthouse_audit(
                website.url
            ),

        ]

    def run(
        self,
        website,
    ):

        report = AuditReport()

        for module in self.audit_modules:

            try:

                report.issues.extend(
                    module(website)
                )

            except Exception as e:

                print(
                    f"[Audit Error] {module}: {e}"
                )

        report.raw_issues = len(report.issues)
        report.issues = normalize_issues(
            report.issues
        )
        report.unique_issues = len(report.issues)

        return report
