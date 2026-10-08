from http.cookies import SimpleCookie
import math
import re


FRAMEWORK_TOKEN_NAMES = {
    "csrf_token",
    "form_token",
    "prestashop_token",
    "wordpress_nonce",
    "nonce",
    "session_token",
    "framework_token",
    "_token",
    "__requestverificationtoken",
}

SENSITIVE_NAME_HINTS = {
    "secret",
    "private_key",
    "privatekey",
    "api_key",
    "apikey",
    "client_secret",
    "oauth_secret",
    "access_token",
    "refresh_token",
    "id_token",
    "jwt",
    "bearer",
    "aws",
    "stripe",
    "github_pat",
    "ghp_",
    "google_api",
    "firebase",
}

SENSITIVE_VALUE_PATTERNS = [
    re.compile(
        r"-----BEGIN [A-Z0-9 ]+ PRIVATE KEY-----"
    ),
    re.compile(
        r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"
    ),
    re.compile(
        r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b"
    ),
    re.compile(
        r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"
    ),
    re.compile(
        r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b"
    ),
    re.compile(
        r"\bpk_(?:live|test)_[A-Za-z0-9]{16,}\b"
    ),
    re.compile(
        r"\bBearer\s+[A-Za-z0-9\-._~+/=]{20,}\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
    ),
]

CONFIDENCE_LEVELS = {
    "VERIFIED",
    "HIGH_CONFIDENCE",
    "NEEDS_MANUAL_REVIEW",
    "INFORMATIONAL",
}


def normalize_headers(headers):

    normalized = {}

    if not headers:

        return normalized

    try:

        items = headers.items() if hasattr(headers, "items") else headers

    except Exception:

        return normalized

    for key, value in items:

        if key is None:
            continue

        name = str(key).lower()

        if name in normalized:

            existing = normalized[name]

            if isinstance(existing, list):

                existing.append(value)

            else:

                normalized[name] = [existing, value]

        else:

            normalized[name] = value

    return normalized


def header_values(headers, name):

    normalized = normalize_headers(headers)

    value = normalized.get(
        name.lower()
    )

    if value is None:

        return []

    if isinstance(value, (list, tuple, set)):

        return [
            str(item)
            for item in value
            if item is not None
        ]

    return [
        str(value)
    ]


def header_value(headers, name, default=""):

    values = header_values(
        headers,
        name,
    )

    if not values:

        return default

    return ", ".join(values)


def parse_set_cookie_headers(headers):

    cookies = []

    for raw_header in header_values(
        headers,
        "set-cookie",
    ):

        cookie = SimpleCookie()

        try:

            cookie.load(raw_header)

        except Exception:

            continue

        for name, morsel in cookie.items():

            cookies.append(

                {

                    "name": name,

                    "value": morsel.value,

                    "secure": bool(morsel["secure"]),

                    "httponly": bool(morsel["httponly"]),

                    "samesite": morsel["samesite"] or "",

                    "expires": morsel["expires"] or "",

                    "max-age": morsel["max-age"] or "",

                    "path": morsel["path"] or "",

                    "domain": morsel["domain"] or "",

                    "raw": raw_header,

                }

            )

    return cookies


def text_snippet(value, limit=160):

    text = re.sub(
        r"\s+",
        " ",
        str(value),
    ).strip()

    if len(text) <= limit:

        return text

    return text[: max(0, limit - 3)].rstrip() + "..." 


def is_framework_token_name(name):

    normalized = (
        str(name or "")
        .strip()
        .lower()
    )

    return normalized in FRAMEWORK_TOKEN_NAMES


def looks_sensitive_token_name(name):

    normalized = (
        str(name or "")
        .strip()
        .lower()
    )

    if not normalized:
        return False

    if is_framework_token_name(
        normalized,
    ):
        return False

    if normalized == "token":
        return False

    return any(
        hint in normalized
        for hint in SENSITIVE_NAME_HINTS
    )


def looks_sensitive_token_value(value):

    text = str(value or "").strip()

    if not text:
        return False

    if any(
        pattern.search(text)
        for pattern in SENSITIVE_VALUE_PATTERNS
    ):
        return True

    compact = re.sub(
        r"[^A-Za-z0-9+/=_-]",
        "",
        text,
    )

    if len(compact) < 24:
        return False

    char_classes = sum(
        bool(
            re.search(
                pattern,
                compact,
            )
        )
        for pattern in (
            r"[a-z]",
            r"[A-Z]",
            r"[0-9]",
            r"[-_+/=]",
        )
    )

    if char_classes < 3:
        return False

    unique_ratio = len(
        set(compact)
    ) / max(
        1,
        len(compact),
    )

    return unique_ratio >= 0.45


def first_nonempty(*values):

    for value in values:

        if value:

            return value

    return ""


def normalize_confidence(
    value,
    verification="",
    title="",
    category="",
):

    if str(verification or "").strip().lower() in (
        "confirmed",
        "verified",
    ):
        return "VERIFIED"

    lowered_title = str(title or "").lower()
    lowered_category = str(category or "").lower()

    informational_tokens = (
        "login form detected",
        "registration form detected",
        "password recovery flow detected",
        "multi-factor authentication",
        "oauth or sso integration detected",
        "api endpoint found",
        "api reference found",
        "common api endpoint candidate",
        "password managers may be disabled",
        "password manager support disabled",
        "password field autocomplete disabled",
        "client-side password validation not observed",
        "client-side session identifier observed",
        "default session cookie name detected",
        "weak session cookie name detected",
        "session cookie has no explicit expiration",
        "session cookie rotation observed",
        "long session identifier observed",
        "http to https redirect observed",
        "password autocomplete",
        "security.txt",
        "jquery detected",
        "react detected",
        "vue detected",
        "angular detected",
        "next.js detected",
        "nuxt detected",
        "wordpress detected",
        "drupal detected",
        "bootstrap detected",
        "tailwind detected",
        "console warnings",
    )

    review_tokens = (
        "potential missing csrf protection",
        "potential sql injection entry point",
        "database input missing client validation",
        "potential idor parameter",
        "potential idor url parameter",
        "hidden business logic field detected",
        "missing h1 heading",
        "weak password policy",
        "missing autocomplete",
        "missing pattern",
        "missing maxlength",
        "missing minlength",
        "optional input field",
        "readonly",
        "disabled",
    )

    high_tokens = (
        "mixed content",
        "sensitive hidden field detected",
        "sensitive session material exposed in browser storage",
        "jwt token verified",
        "confirmed reflected xss",
        "confirmed price or fee manipulation",
        "sensitive api credentials exposed",
        "sensitive personal data exposed",
        "api response exposes user identifiers",
        "missing hsts",
        "weak hsts",
        "missing csp",
        "weak csp",
        "weak tls version observed",
        "weak tls cipher observed",
        "tls certificate expires soon",
        "vulnerable jquery version detected",
        "site does not use https",
        "https site missing hsts",
        "session cookie missing secure attribute",
        "session cookie missing httponly attribute",
        "session cookie missing samesite attribute",
        "cookie missing secure attribute",
        "cookie missing httponly attribute",
        "cookie missing samesite attribute",
        "aws access key id exposed",
        "google api key exposed",
        "stripe secret key exposed",
        "github token exposed",
        "github fine-grained token exposed",
        "private key block exposed",
        "bearer token exposed",
    )

    if any(token in lowered_title for token in informational_tokens):
        return "INFORMATIONAL"

    if any(token in lowered_title for token in review_tokens):
        return "NEEDS_MANUAL_REVIEW"

    if any(token in lowered_title for token in high_tokens):
        return "HIGH_CONFIDENCE"

    if lowered_category in {
        "html/ux",
        "html best practices",
        "detected technologies",
        "security best practices",
        "networking",
    }:
        return "INFORMATIONAL"

    normalized = str(value or "").strip().upper().replace("-", "_")

    # Deterministic checks (measured, not guessed) count by default.
    if not normalized and lowered_category in {
        "seo",
        "performance",
        "accessibility",
        "responsive",
        "lighthouse",
        "network",
        "console",
        "usability",
        "visual design",
        "links",
        "forms",
        "trust & compliance",
    }:
        return "HIGH_CONFIDENCE"

    mapping = {
        "HIGH": "HIGH_CONFIDENCE",
        "HIGH_CONFIDENCE": "HIGH_CONFIDENCE",
        "MEDIUM": "NEEDS_MANUAL_REVIEW",
        "LOW": "NEEDS_MANUAL_REVIEW",
        "NEEDS_MANUAL_REVIEW": "NEEDS_MANUAL_REVIEW",
        "INFO": "INFORMATIONAL",
        "INFORMATIONAL": "INFORMATIONAL",
        "POTENTIAL": "NEEDS_MANUAL_REVIEW",
        "LIKELY": "HIGH_CONFIDENCE",
        "CONFIRMED": "VERIFIED",
        "VERIFIED": "VERIFIED",
    }

    return mapping.get(
        normalized,
        "NEEDS_MANUAL_REVIEW",
    )


def confidence_is_scoreworthy(
    value,
    verification="",
    title="",
    category="",
):

    return normalize_confidence(
        value,
        verification,
        title,
        category,
    ) in {
        "VERIFIED",
        "HIGH_CONFIDENCE",
    }


def shannon_entropy(text):

    text = str(text or "")

    if not text:
        return 0.0

    counts = {}

    for char in text:
        counts[char] = counts.get(char, 0) + 1

    length = len(text)

    entropy = 0.0

    for count in counts.values():

        probability = count / length

        entropy -= probability * math.log2(probability)

    return entropy


def looks_like_public_oauth_endpoint(url):

    text = str(url or "").lower()

    if not text:
        return False

    allowed = (
        "/.well-known/",
        "openid-configuration",
        "fedcm",
        "accounts.google.com",
        "oauth-authorization-server",
        "authorization-server",
        "jwks",
    )

    if any(token in text for token in allowed):
        return True

    return False
