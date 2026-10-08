from audit.report import AuditReport
from audit.normalization import normalize_issues

from audit.seo import run_seo_audit
from audit.network import run_network_audit
from audit.console import run_console_audit
from audit.responsive import run_responsive_audit
from audit.accessibility import run_accessibility_audit
from audit.lighthouse import run_lighthouse_audit
from audit.security import SecurityEngine
from audit.visual import run_visual_audit, run_ai_review
from audit.performance import run_performance_audit
from audit.links import run_links_audit
from audit.images import run_image_audit
from audit.forms import run_form_audit
from audit.contact import run_contact_audit


class AuditEngine:

    def __init__(
        self,
        aggressive=False,
        ai_review=False,
        max_pages=25,
    ):

        self.aggressive = aggressive
        self.ai_review = ai_review
        self.max_pages = max_pages

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
            # Visual Design
            # ----------------------------------

            lambda website: run_visual_audit(
                website.page_object,
                website.screenshot_manager,
            ),

            # ----------------------------------
            # Performance / Images
            # ----------------------------------

            run_performance_audit,
            run_image_audit,

            # ----------------------------------
            # Links and site-wide checks
            # ----------------------------------

            lambda website: run_links_audit(
                website,
                self.max_pages,
            ),

            # ----------------------------------
            # Forms / Contact / Trust
            # ----------------------------------

            run_form_audit,
            run_contact_audit,

            # ----------------------------------
            # Lighthouse
            # ----------------------------------

            lambda website: run_lighthouse_audit(
                website.url
            ),

        ]

        if ai_review:

            self.audit_modules.append(
                run_ai_review
            )

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

                name = getattr(
                    module,
                    "__name__",
                    "module",
                )

                print(
                    f"[Audit Error] {name}: {type(e).__name__}: {e}"
                )

        report.raw_issues = len(report.issues)
        report.issues = normalize_issues(
            report.issues
        )
        report.unique_issues = len(report.issues)

        return report
