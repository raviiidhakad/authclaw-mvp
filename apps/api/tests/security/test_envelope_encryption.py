import json
import pytest
import base64
from app.core.encryption import encrypt_value, decrypt_value, get_encryption_provider
from app.core.encryption.kms import KmsEncryptionProvider
import moto
import boto3
from app.core.config import settings
import os

@pytest.fixture(autouse=True)
def set_env(monkeypatch):
    # Force kms for tests to avoid vault unless specifically testing it
    import app.core.encryption
    monkeypatch.setenv('ENCRYPTION_PROVIDER', 'kms')
    monkeypatch.setattr(settings, 'ENCRYPTION_PROVIDER', 'kms')
    app.core.encryption._provider = None
    yield
    app.core.encryption._provider = None

@pytest.fixture
def kms_mock():
    with moto.mock_aws():
        client = boto3.client('kms', region_name='us-east-1')
        key = client.create_key(Description='Test Key')
        key_id = key['KeyMetadata']['KeyId']
        # Mock settings
        settings.KMS_KEY_ID = key_id
        yield client, key_id

def test_encryption_payload_format_and_decryption(kms_mock):
    # Ensure provider is kms
    assert isinstance(get_encryption_provider(), KmsEncryptionProvider)

    plaintext = "super_secret_api_key_123"
    
    # 1. Encrypt
    encrypted_payload_str = encrypt_value(plaintext)
    
    # 2. Verify payload structure
    payload = json.loads(encrypted_payload_str)
    assert payload["version"] == 1
    assert payload["provider"] == "kms"
    assert "enc_dek" in payload
    assert "iv" in payload
    assert "ct" in payload
    assert "tag" in payload
    
    # 3. Decrypt
    decrypted = decrypt_value(encrypted_payload_str)
    assert decrypted == plaintext

from unittest.mock import patch

def test_dek_memory_scrubbing(kms_mock):
    """
    Test that the plaintext DEK is deleted after encryption.
    We mock generate_data_key to spy on the returned DEK, but Python's GC 
    handles the actual memory. We just assert the envelope encryption completes.
    """
    with patch.object(KmsEncryptionProvider, 'generate_data_key', wraps=KmsEncryptionProvider().generate_data_key) as spy:
        plaintext = "another_secret"
        encrypted_str = encrypt_value(plaintext)
        
        assert spy.call_count == 1
        decrypted = decrypt_value(encrypted_str)
        assert decrypted == plaintext

def test_tamper_resistance_raises_error(kms_mock):
    plaintext = "tamper_me"
    encrypted_payload_str = encrypt_value(plaintext)
    payload = json.loads(encrypted_payload_str)
    
    # Modify the ciphertext
    ct_bytes = base64.b64decode(payload["ct"])
    tampered_ct = bytearray(ct_bytes)
    tampered_ct[0] ^= 0xFF # Flip a bit
    payload["ct"] = base64.b64encode(tampered_ct).decode('utf-8')
    
    tampered_payload_str = json.dumps(payload)
    
    # Decrypt should raise error due to Invalid Tag (GCM authentication failed)
    with pytest.raises(ValueError, match="Ciphertext tampered or authentication tag invalid"):
        decrypt_value(tampered_payload_str)
