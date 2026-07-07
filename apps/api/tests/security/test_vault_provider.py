import pytest
import os
import time
import requests
from app.core.encryption.vault import VaultEncryptionProvider
from app.core.config import settings
import json
from app.core.encryption import encrypt_value, decrypt_value, get_encryption_provider

def wait_for_vault(url="http://vault:8200/v1/sys/health", timeout=15):
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(url, verify=False)
            if r.status_code in (200, 429, 472, 473, 501, 503): # Vault health endpoints return these
                return True
        except requests.exceptions.RequestException:
            pass
        time.sleep(1)
    return False

@pytest.fixture(autouse=True)
def skip_if_no_vault():
    vault_url = os.getenv('VAULT_ADDR', 'http://vault:8200')
    if not wait_for_vault(f"{vault_url}/v1/sys/health"):
        pytest.skip("Vault dev server not available. Skipping Vault integration tests.")

@pytest.fixture(autouse=True)
def set_vault_env(monkeypatch):
    # Force vault provider for these tests
    # Clear the singleton to reload provider
    import app.core.encryption
    monkeypatch.setenv('ENCRYPTION_PROVIDER', 'vault')
    monkeypatch.setenv('ENVIRONMENT', 'development')
    monkeypatch.setattr(settings, 'ENCRYPTION_PROVIDER', 'vault')
    app.core.encryption._provider = None
    yield
    app.core.encryption._provider = None

def test_vault_provider_generate_and_decrypt():
    provider = VaultEncryptionProvider()
    
    plaintext_dek, encrypted_dek = provider.generate_data_key()
    assert len(plaintext_dek) == 32 # 256 bits
    assert isinstance(encrypted_dek, str)
    assert encrypted_dek.startswith("vault:v")

    decrypted_dek = provider.decrypt_dek(encrypted_dek)
    assert decrypted_dek == plaintext_dek

def test_vault_envelope_encryption_flow():
    assert isinstance(get_encryption_provider(), VaultEncryptionProvider)

    plaintext = "super_secret_db_password"
    
    # 1. Encrypt
    encrypted_payload_str = encrypt_value(plaintext)
    
    # 2. Verify payload structure
    payload = json.loads(encrypted_payload_str)
    assert payload["version"] == 1
    assert payload["provider"] == "vault"
    assert payload["enc_dek"].startswith("vault:v")
    
    # 3. Decrypt
    decrypted = decrypt_value(encrypted_payload_str)
    assert decrypted == plaintext


def test_vault_rotation_keeps_old_ciphertext_decryptable():
    provider = VaultEncryptionProvider()
    plaintext_dek, encrypted_dek = provider.generate_data_key()
    old_version = int(encrypted_dek.split(":")[1].removeprefix("v"))

    provider.client.secrets.transit.rotate_key(name=provider.key_name, mount_point=provider.mount_point)
    rotated_plaintext_dek, rotated_encrypted_dek = provider.generate_data_key()
    new_version = int(rotated_encrypted_dek.split(":")[1].removeprefix("v"))

    assert new_version > old_version
    assert provider.decrypt_dek(encrypted_dek) == plaintext_dek
    assert provider.decrypt_dek(rotated_encrypted_dek) == rotated_plaintext_dek
