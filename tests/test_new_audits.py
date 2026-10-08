import unittest
from types import SimpleNamespace

from bs4 import BeautifulSoup

from audit.contact import run_contact_audit
from audit.forms import run_form_audit
from audit.security.exposure import CHECKS
from audit.visual.audit import _rules


def site(html, url="https://example.com/"):

    soup = BeautifulSoup(html, "lxml")

    return SimpleNamespace(
        url=url,
        page={
            "soup": soup,
            "html": html,
            "emails": [],
            "phones": [],
            "links": [
                {"href": a.get("href"), "text": a.get_text(strip=True)}
                for a in soup.find_all("a")
            ],
        },
    )


def titles(issues):
    return {i.title for i in issues}


class FormTests(unittest.TestCase):

    def test_flags_unlabeled_contact_form_without_consent(self):

        issues = run_form_audit(site(
            '<form action="http://x.com/s"><input name="email" placeholder="Email">'
            "</form>"
        ))

        found = titles(issues)

        self.assertIn("Form Fields Without Labels", found)
        self.assertIn("Form Has No Submit Button", found)
        self.assertIn("Form Submits Over HTTP", found)
        self.assertIn("Form Collects Data Without Privacy Consent", found)

    def test_clean_form_has_no_findings(self):

        issues = run_form_audit(site(
            '<form action="/s"><label for="e">Email</label>'
            '<input id="e" name="email" type="email" required>'
            '<label><input type="checkbox"> I accept the privacy policy</label>'
            '<div class="g-recaptcha"></div><button>Send</button></form>'
        ))

        self.assertEqual(issues, [])


class ContactTests(unittest.TestCase):

    def test_missing_contact_and_privacy(self):

        found = titles(run_contact_audit(site("<p>hello</p>")))

        self.assertIn("No Way to Contact the Business", found)
        self.assertIn("No Privacy Policy Link", found)

    def test_tracking_without_consent(self):

        found = titles(run_contact_audit(site(
            "<script src='https://www.googletagmanager.com/gtm.js'></script>"
        )))

        self.assertIn("Tracking Without Cookie Consent Banner", found)


class ExposureTests(unittest.TestCase):

    def matcher(self, path):
        return next(c[3] for c in CHECKS if c[0] == path)

    def test_signatures_reject_html_soft_404(self):

        html = "<html><body>Not found</body></html>"

        for path, *_ , matcher, _cwe in [(c[0], c[3], c[4]) for c in CHECKS]:
            self.assertFalse(matcher(html, "text/html"), path)

    def test_env_and_git_signatures_match(self):

        self.assertTrue(self.matcher("/.env")("DB_PASSWORD=hunter2\n", ""))
        self.assertTrue(self.matcher("/.git/HEAD")("ref: refs/heads/main", ""))


class VisualRuleTests(unittest.TestCase):

    def data(self, **overrides):

        base = {
            "viewport": {"width": 1440, "height": 900},
            "scroll": {"width": 1440, "height": 3000},
            "fonts": {"Inter": 1000}, "sizes": {16: 1000},
            "textColors": {}, "bgColors": {}, "smallText": [],
            "lowContrast": [], "contrastChecked": 10, "longLines": [],
            "brokenImages": [], "upscaledImages": [], "distortedImages": [],
            "overlays": [], "overlaps": [], "lineHeightTight": [],
            "hero": {"h1InFold": True, "ctaInFold": True, "mediaInFold": True},
            "textChars": 5000, "foldChars": 300,
        }
        base.update(overrides)
        return base

    def test_clean_page_has_no_findings(self):
        self.assertEqual(_rules(self.data(), "desktop"), [])

    def test_detects_problems(self):

        found = titles(_rules(self.data(
            scroll={"width": 2000, "height": 3000},
            brokenImages=["a.png"],
            lowContrast=[{"selector": "p", "ratio": 1.5, "need": 4.5, "text": "x"}],
            sizes={10: 1000},
        ), "mobile"))

        self.assertTrue({
            "Horizontal Scrolling", "Broken Images Visible",
            "Low Text Contrast", "Body Text Too Small",
        } <= found)


if __name__ == "__main__":
    unittest.main()
