import os
from cryptography.fernet import Fernet
from app.core.config import settings
from app.core.encryption.provider import EncryptionProvider

class LocalEncryptionProvider(EncryptionProvider):
    def __init__(self):
        if not hasattr(settings, 'ENCRYPTION_KEY') or not settings.ENCRYPTION_KEY:
            raise ValueError("ENCRYPTION_KEY must be set in the environment when using ENCRYPTION_PROVIDER=local")
        self.fernet = Fernet(settings.ENCRYPTION_KEY.encode())

    def encrypt_dek(self, plaintext_dek: bytes) -> str:
        encrypted = self.fernet.encrypt(plaintext_dek)
        return encrypted.decode('utf-8')

    def decrypt_dek(self, encrypted_dek: str) -> bytes:
        return self.fernet.decrypt(encrypted_dek.encode('utf-8'))

    def generate_data_key(self) -> tuple[bytes, str]:
        # Generate 32 bytes (256 bits) for AES-256
        plaintext_dek = os.urandom(32)
        encrypted_dek = self.encrypt_dek(plaintext_dek)
        return plaintext_dek, encrypted_dek
