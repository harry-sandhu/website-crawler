import importlib.util
from pathlib import Path
import unittest

from audit.models import Issue
from audit.normalization import normalize_issues


def _load_shared_module():

    path = (
        Path(__file__)
        .resolve()
        .parents[1]
        / "audit"
        / "security"
        / "shared.py"
    )

    spec = importlib.util.spec_from_file_location(
        "audit_security_shared_test",
        path,
    )

    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


shared = _load_shared_module()


class NormalizationTests(unittest.TestCase):

    def test_groups_form_level_autocomplete_issues(self):

        issues = [
            Issue(
                category="Input Validation",
                severity="Info",
                title="Email Autocomplete Not Configured",
                description="Email field is missing autocomplete.",
                recommendation="Use autocomplete where appropriate.",
                endpoint="/submit",
                page="https://example.com/login",
                selector="form:login",
                parameter="email",
                evidence="autocomplete=''",
                finding_key="HTML Best Practices|login-form|autocomplete",
                affected_item="email",
            ),
            Issue(
                category="Input Validation",
                severity="Info",
                title="Phone Autocomplete Not Configured",
                description="Phone field is missing autocomplete.",
                recommendation="Use autocomplete where appropriate.",
                endpoint="/submit",
                page="https://example.com/login",
                selector="form:login",
                parameter="phone",
                evidence="autocomplete=''",
                finding_key="HTML Best Practices|login-form|autocomplete",
                affected_item="phone",
            ),
        ]

        normalized = normalize_issues(issues)

        self.assertEqual(len(normalized), 1)
        issue = normalized[0]
        self.assertEqual(issue.category, "HTML/UX")
        self.assertEqual(issue.title, "Missing autocomplete attributes")
        self.assertEqual(issue.occurrences, 2)
        self.assertCountEqual(issue.affected_items, ["email", "phone"])

    def test_missing_h1_is_not_critical(self):

        issues = [
            Issue(
                category="SEO",
                severity="Critical",
                title="Missing H1 Heading",
                description="No H1 heading was found.",
                recommendation="Add one descriptive H1 heading.",
            )
        ]

        normalized = normalize_issues(issues)

        self.assertEqual(normalized[0].severity, "Medium")

    def test_framework_tokens_are_not_flagged(self):

        self.assertFalse(
            shared.looks_sensitive_token_name("csrf_token")
        )
        self.assertFalse(
            shared.looks_sensitive_token_name("token")
        )
        self.assertTrue(
            shared.looks_sensitive_token_name("stripe_secret")
        )
        self.assertTrue(
            shared.looks_sensitive_token_value(
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoxfQ"
            )
        )


if __name__ == "__main__":
    unittest.main()
