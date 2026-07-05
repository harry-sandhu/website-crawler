from http.cookies import SimpleCookie
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
