"""
Fernet-based symmetric encryption for provider API keys.
Uses the ENCRYPTION_KEY from settings (must be a valid Fernet key).
"""
from cryptography.fernet import Fernet
from app.core.config import settings

_fernet = Fernet(settings.ENCRYPTION_KEY.encode())


def encrypt_value(plaintext: str) -> str:
    """Encrypt a plaintext string and return the ciphertext as a UTF-8 string."""
    return _fernet.encrypt(plaintext.encode()).decode()


def decrypt_value(ciphertext: str) -> str:
    """Decrypt a ciphertext string and return the plaintext."""
    return _fernet.decrypt(ciphertext.encode()).decode()
