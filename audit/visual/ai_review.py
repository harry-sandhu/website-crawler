"""Optional AI design review (opt-in via --ai-review).

Sends first-screen screenshots to the Anthropic API and asks for a design
critique. Findings are advisory (they are not scored); the numeric ratings
are returned as one informational issue. Needs ANTHROPIC_API_KEY.
"""

import base64
import json
import os
import re

import requests

from audit.models import Issue

API_URL = "https://api.anthropic.com/v1/messages"
MODEL = os.environ.get("AUDITOR_AI_MODEL", "claude-sonnet-5-5")

PROMPT = """You are a senior web designer reviewing a website from screenshots
(desktop first, mobile second). Judge only what is visible.

Return ONLY JSON:
{
  "ratings": {"visual_hierarchy": 1-10, "typography": 1-10, "colour_and_branding": 1-10,
              "spacing_and_layout": 1-10, "imagery": 1-10, "trust_and_professionalism": 1-10,
              "mobile_experience": 1-10, "overall": 1-10},
  "summary": "two sentences",
  "findings": [
    {"severity": "High|Medium|Low", "title": "short", "description": "what is wrong and where",
     "recommendation": "specific fix"}
  ]
}
Give at most 8 findings, most important first. Be specific and concrete; do not
praise. If something looks dated, cluttered or untrustworthy, say so."""


def _encode(path):

    with open(path, "rb") as handle:

        return base64.standard_b64encode(handle.read()).decode()


def run_ai_review(website):

    key = os.environ.get("ANTHROPIC_API_KEY")

    if not key:

        print("[AI Review] ANTHROPIC_API_KEY not set; skipping.")
        return []

    shots = []

    for device in ("desktop", "iphone_15"):

        data = website.screenshots.get(device) or {}

        for kind in ("normal", "full"):

            path = data.get(kind)

            if path:
                shots.append((f"{device} {kind}", path))

    shots = shots[:4]

    if not shots:
        return []

    content = []

    for label, path in shots:

        content.append({"type": "text", "text": label})
        content.append({
            "type": "image",
            "source": {
                "type": "base64",
                "media_type": "image/png",
                "data": _encode(path),
            },
        })

    content.append({"type": "text", "text": PROMPT})

    response = requests.post(
        API_URL,
        headers={
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json={
            "model": MODEL,
            "max_tokens": 2000,
            "messages": [{"role": "user", "content": content}],
        },
        timeout=120,
    )

    response.raise_for_status()

    text = "".join(
        block.get("text", "")
        for block in response.json().get("content", [])
    )

    match = re.search(r"\{.*\}", text, re.S)

    if not match:
        return []

    review = json.loads(match.group(0))

    issues = []

    ratings = review.get("ratings", {})

    issues.append(Issue(
        category="Visual Design",
        severity="Info",
        title="AI Design Review Ratings",
        description=review.get("summary", ""),
        recommendation="Use the ratings to prioritise design work.",
        evidence="\n".join(f"{k}: {v}/10" for k, v in ratings.items()),
        confidence="Info",
        verification_method="AI visual review (advisory)",
    ))

    for finding in review.get("findings", [])[:8]:

        issues.append(Issue(
            category="Visual Design",
            severity=finding.get("severity", "Low"),
            title=f"AI Review: {finding.get('title', 'Design issue')}",
            description=finding.get("description", ""),
            recommendation=finding.get("recommendation", ""),
            confidence="Low",
            verification_method="AI visual review (advisory)",
        ))

    return issues
