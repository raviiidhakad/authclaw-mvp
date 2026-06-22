"""
Provider Contract Testing - Shared Fixtures & Credential Guards
===============================================================
Tests skip cleanly when environment credentials are absent.
No test failures due to missing provider API keys.
"""
import os
import uuid
import json
import pytest
import httpx
from typing import Optional
from unittest.mock import MagicMock

# ---------------------------------------------------------------------------
# Credential detection helpers
# ---------------------------------------------------------------------------

def _get_env(key: str) -> Optional[str]:
    """Read an env var; return None if absent or looks like a placeholder."""
    val = os.getenv(key, "").strip()
    if not val or val.startswith("sk-your") or val == "your-key-here":
        return None
    return val


# ---------------------------------------------------------------------------
# Per-provider skip marks (evaluated lazily at collection time)
# ---------------------------------------------------------------------------

OPENAI_KEY   = _get_env("OPENAI_API_KEY")
ANTHROPIC_KEY = _get_env("ANTHROPIC_API_KEY")
GROQ_KEY     = _get_env("GROQ_API_KEY")
GEMINI_KEY   = _get_env("GEMINI_API_KEY")
COHERE_KEY   = _get_env("COHERE_API_KEY")
AZURE_KEY    = _get_env("AZURE_OPENAI_API_KEY")

requires_openai   = pytest.mark.skipif(not OPENAI_KEY,   reason="OPENAI_API_KEY not set")
requires_anthropic = pytest.mark.skipif(not ANTHROPIC_KEY, reason="ANTHROPIC_API_KEY not set")
requires_groq     = pytest.mark.skipif(not GROQ_KEY,     reason="GROQ_API_KEY not set")
requires_gemini   = pytest.mark.skipif(not GEMINI_KEY,   reason="GEMINI_API_KEY not set")
requires_cohere   = pytest.mark.skipif(not COHERE_KEY,   reason="COHERE_API_KEY not set")
requires_azure    = pytest.mark.skipif(not AZURE_KEY,    reason="AZURE_OPENAI_API_KEY not set")


# ---------------------------------------------------------------------------
# Fake Provider model for unit / contract tests that don't hit the network
# ---------------------------------------------------------------------------

class FakeProvider:
    """Minimal Provider object for adapter unit tests."""
    def __init__(self, provider_type, api_key="test-key", config=None):
        self.id = uuid.uuid4()
        self.name = f"fake-{provider_type.value}"
        self.type = provider_type
        self.api_key_encrypted = _encrypt_test_key(api_key)
        self.config = config or {}
        self.is_active = True


def _encrypt_test_key(raw_key: str) -> str:
    """
    Encrypt a raw key using Fernet directly — avoids KMS/Vault dependency in tests.
    The OpenAI adapter's decrypt_value() accepts both Fernet and v1 envelope payloads.
    """
    from cryptography.fernet import Fernet
    from app.core.config import settings
    f = Fernet(settings.ENCRYPTION_KEY.encode())
    return f.encrypt(raw_key.encode()).decode()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_provider_factory():
    """Returns FakeProvider constructor for use in tests."""
    return FakeProvider


@pytest.fixture
def openai_api_key():
    if not OPENAI_KEY:
        pytest.skip("OPENAI_API_KEY not set")
    return OPENAI_KEY


@pytest.fixture
def anthropic_api_key():
    if not ANTHROPIC_KEY:
        pytest.skip("ANTHROPIC_API_KEY not set")
    return ANTHROPIC_KEY


@pytest.fixture
def groq_api_key():
    if not GROQ_KEY:
        pytest.skip("GROQ_API_KEY not set")
    return GROQ_KEY


@pytest.fixture
def gemini_api_key():
    if not GEMINI_KEY:
        pytest.skip("GEMINI_API_KEY not set")
    return GEMINI_KEY


@pytest.fixture
def cohere_api_key():
    if not COHERE_KEY:
        pytest.skip("COHERE_API_KEY not set")
    return COHERE_KEY


@pytest.fixture
def azure_api_key():
    if not AZURE_KEY:
        pytest.skip("AZURE_OPENAI_API_KEY not set")
    return AZURE_KEY
