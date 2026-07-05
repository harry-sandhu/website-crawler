from importlib import import_module

from .models import (
    RequestData,
    FormField,
    FormData,
    SecurityIssue,
    SecurityReport,
)

__all__ = [
    "SecurityEngine",
    "RequestData",
    "FormField",
    "FormData",
    "SecurityIssue",
    "SecurityReport",
    "APITester",
    "HeadersTester",
    "CookiesTester",
    "AuthenticationTester",
    "SSLTester",
    "TechnologyTester",
    "SessionTester",
    "JWTTester",
    "SecretsTester",
    "SecurityTxtTester",
    "BusinessLogicTester",
]

_LAZY_IMPORTS = {
    "SecurityEngine": "audit.security.engine",
    "APITester": "audit.security.api",
    "HeadersTester": "audit.security.headers",
    "CookiesTester": "audit.security.cookies",
    "AuthenticationTester": "audit.security.authentication",
    "SSLTester": "audit.security.ssl",
    "TechnologyTester": "audit.security.technology",
    "SessionTester": "audit.security.session",
    "JWTTester": "audit.security.jwt",
    "SecretsTester": "audit.security.secrets",
    "SecurityTxtTester": "audit.security.security_txt",
    "BusinessLogicTester": "audit.security.business_logic",
}


def __getattr__(name):

    module_name = _LAZY_IMPORTS.get(
        name
    )

    if not module_name:
        raise AttributeError(
            name
        )

    module = import_module(
        module_name
    )

    value = getattr(
        module,
        name,
    )

    globals()[name] = value

    return value
