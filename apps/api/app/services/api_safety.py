from __future__ import annotations

import re
from typing import Iterable


SECRET_FIELD_NAMES = {
    "aws_access_key_id",
    "aws_secret_access_key",
    "aws_session_token",
    "github_token",
    "private_key",
    "client_secret",
    "access_token",
    "refresh_token",
    "id_token",
    "password",
    "token",
    "api_key",
    "vault_reference_id",
    "raw_finding_data",
    "raw_payload",
    "raw_provider_payload",
}


SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.I | re.S),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(
        r"\b(?:aws_secret_access_key|aws_session_token|github_token|private_key|"
        r"client_secret|access_token|refresh_token|id_token|password|api[_-]?key|token)\s*"
        r"[:=]\s*['\"]?[^'\"\s,;]+",
        re.I,
    ),
    re.compile(
        r"\b(?:aws_secret_access_key|aws_session_token|github_token|private_key|"
        r"client_secret|access_token|refresh_token|id_token|password|api[_-]?key|token|"
        r"raw_finding_data|raw_payload|raw_provider_payload)\b",
        re.I,
    ),
]


def sanitize_text(value: object, extra_secret_values: Iterable[str] | None = None) -> str:
    text = " ".join(str(value).replace("\x00", " ").split())
    for secret in extra_secret_values or []:
        if secret and len(secret) >= 4:
            text = text.replace(str(secret), "[redacted]")
    for pattern in SECRET_PATTERNS:
        text = pattern.sub("[redacted]", text)
    return text


def collect_secret_values(value: object) -> list[str]:
    values: list[str] = []

    def walk(item: object) -> None:
        if isinstance(item, dict):
            for key, nested in item.items():
                if str(key).lower() in SECRET_FIELD_NAMES and isinstance(nested, str):
                    values.append(nested)
                walk(nested)
        elif isinstance(item, (list, tuple, set)):
            for nested in item:
                walk(nested)

    walk(value)
    return values
