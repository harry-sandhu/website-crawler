import unittest
from unittest.mock import patch

from audit.security.api import APITester
from audit.security.business_logic import BusinessLogicTester
from audit.security.models import RequestData, SecurityReport


class WebsiteStub:

    def __init__(self, url="https://example.com", page=None, browser=None):

        self.url = url
        self.page = page or {
            "links": [],
            "scripts": [],
        }
        self.browser = browser or {
            "responses": [],
            "requests": [],
        }


class SecurityDetectionTests(unittest.TestCase):

    def test_api_tester_flags_sensitive_json_response_fields(self):

        website = WebsiteStub(
            browser={
                "responses": [
                    {
                        "url": "https://example.com/api/profile",
                        "body": (
                            '{"userId":"42","accessToken":"abc123xyz123xyz123",'
                            '"profile":{"email":"alice@example.com"}}'
                        ),
                        "content_type": "application/json",
                    }
                ]
            }
        )

        report = SecurityReport()

        APITester().run(
            website,
            report,
        )

        titles = {
            issue.title
            for issue in report.issues
        }

        self.assertIn(
            "Sensitive API Credentials Exposed",
            titles,
        )
        self.assertIn(
            "Sensitive Personal Data Exposed",
            titles,
        )
        self.assertIn(
            "API Response Exposes User Identifiers",
            titles,
        )

    def test_business_logic_tester_stops_after_confirmed_tamper(self):

        website = WebsiteStub()

        report = SecurityReport(
            requests=[
                RequestData(
                    method="POST",
                    url="https://example.com/checkout",
                    headers={},
                    params={
                        "price": "19.99",
                    },
                    body="",
                    cookies={},
                    content_type="application/x-www-form-urlencoded",
                )
            ]
        )

        tester = BusinessLogicTester(
            aggressive=True,
        )

        with patch.object(
            tester.replayer,
            "replay",
            return_value={
                "success": True,
                "status_code": 200,
                "body": "Order accepted. Total: 0.01",
                "response_time": 42.0,
            },
        ) as mocked_replay:

            tester.run(
                website,
                report,
            )

        self.assertEqual(
            mocked_replay.call_count,
            1,
        )

        confirmed = [
            issue
            for issue in report.issues
            if issue.title == "Confirmed Price or Fee Manipulation"
        ]

        self.assertEqual(
            len(confirmed),
            1,
        )
        self.assertEqual(
            confirmed[0].verification,
            "Confirmed",
        )


if __name__ == "__main__":
    unittest.main()
