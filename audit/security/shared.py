from http.cookies import SimpleCookie
import re


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


def first_nonempty(*values):

    for value in values:

        if value:

            return value

    return ""
