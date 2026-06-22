"""
AES-256-GCM Envelope Encryption implementation.
Provides `encrypt_value` and `decrypt_value` compatible with the versioned JSON payload.
Supports legacy Fernet payloads for backward compatibility.
"""
import os
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from app.core.config import settings

# Temporary legacy fallback
_legacy_fernet = Fernet(settings.ENCRYPTION_KEY.encode()) if hasattr(settings, 'ENCRYPTION_KEY') else None

# Active provider instance (Singleton or lazy-loaded)
_provider = None

def get_encryption_provider():
    global _provider
    if _provider is None:
        provider_type = getattr(settings, 'ENCRYPTION_PROVIDER', 'kms').lower()
        if provider_type == 'vault':
            from app.core.encryption.vault import VaultEncryptionProvider
            _provider = VaultEncryptionProvider()
        elif provider_type == 'local':
            from app.core.encryption.local import LocalEncryptionProvider
            _provider = LocalEncryptionProvider()
        else:
            from app.core.encryption.kms import KmsEncryptionProvider
            _provider = KmsEncryptionProvider()
    return _provider


def encrypt_value(plaintext: str) -> str:
    """
    Encrypt a plaintext string using Envelope Encryption.
    Returns a JSON string containing the ciphertext, IV, tag, and encrypted DEK.
    """
    provider = get_encryption_provider()
    provider_name = getattr(settings, 'ENCRYPTION_PROVIDER', 'kms').lower()
    
    # 1. Generate DEK
    plaintext_dek, encrypted_dek = provider.generate_data_key()
    
    try:
        # 2. Local AES-256-GCM Encryption
        aesgCM = AESGCM(plaintext_dek)
        iv = os.urandom(12)  # 96-bit nonce
        
        # encrypt() returns ciphertext with the 16-byte authentication tag appended
        ct_and_tag = aesgCM.encrypt(iv, plaintext.encode('utf-8'), None)
        
        ciphertext = ct_and_tag[:-16]
        tag = ct_and_tag[-16:]
        
        # 3. Format payload
        payload = {
            "version": 1,
            "provider": provider_name,
            "enc_dek": encrypted_dek,
            "iv": base64.b64encode(iv).decode('utf-8'),
            "ct": base64.b64encode(ciphertext).decode('utf-8'),
            "tag": base64.b64encode(tag).decode('utf-8')
        }
        
        return json.dumps(payload)
        
    finally:
        # 4. DEK Destruction: Actively scrub the plaintext DEK from memory
        # In Python, byte strings are immutable, but we can overwrite a bytearray if we made one.
        # Since boto/hvac return immutable bytes, we delete the reference immediately.
        # Python's GC will handle the memory, but `del` ensures it falls out of scope *now*.
        del plaintext_dek


def decrypt_value(ciphertext_string: str) -> str:
    """
    Decrypt a ciphertext string.
    Handles legacy Fernet strings and v1 JSON envelope payloads.
    """
    try:
        payload = json.loads(ciphertext_string)
        if payload.get("version") == 1:
            return _decrypt_v1(payload)
    except (json.JSONDecodeError, TypeError):
        pass

    # Fallback to legacy Fernet
    if _legacy_fernet:
        decrypted = _legacy_fernet.decrypt(ciphertext_string.encode()).decode()
        # Auto-migration strategy: we decrypt with Fernet and return plaintext.
        # The caller/repository would need to save it to trigger re-encryption.
        return decrypted
    raise ValueError("Legacy encrypted payload found but ENCRYPTION_KEY not configured")


def _decrypt_v1(payload: dict) -> str:
    # Resolve provider dynamically based on the payload metadata,
    # or fallback to the current active provider if it can handle it.
    provider_name = payload.get("provider", "kms")
    if provider_name == 'vault':
        from app.core.encryption.vault import VaultEncryptionProvider
        provider = VaultEncryptionProvider()
    elif provider_name == 'local':
        from app.core.encryption.local import LocalEncryptionProvider
        provider = LocalEncryptionProvider()
    else:
        from app.core.encryption.kms import KmsEncryptionProvider
        provider = KmsEncryptionProvider()

    encrypted_dek = payload["enc_dek"]
    iv = base64.b64decode(payload["iv"])
    ct = base64.b64decode(payload["ct"])
    tag = base64.b64decode(payload["tag"])
    
    # Reconstruct the AESGCM expected format: ciphertext + tag
    ct_and_tag = ct + tag
    
    plaintext_dek = provider.decrypt_dek(encrypted_dek)
    try:
        aesgCM = AESGCM(plaintext_dek)
        plaintext = aesgCM.decrypt(iv, ct_and_tag, None)
        return plaintext.decode('utf-8')
    except InvalidTag:
        raise ValueError("Ciphertext tampered or authentication tag invalid")
    finally:
        del plaintext_dek
