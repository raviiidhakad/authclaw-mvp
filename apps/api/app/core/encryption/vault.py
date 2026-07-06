import base64
import os
import hvac
from app.core.encryption.provider import EncryptionProvider
from app.core.config import settings

class VaultEncryptionProvider(EncryptionProvider):
    """
    HashiCorp Vault implementation of EncryptionProvider.
    Uses hvac to interface with Vault's Transit Secrets Engine.
    """

    def __init__(self):
        # Vault URL and Token should be in settings/env
        vault_url = getattr(settings, 'VAULT_ADDR', os.getenv('VAULT_ADDR', 'http://vault:8200'))
        vault_token = getattr(settings, 'VAULT_TOKEN', os.getenv('VAULT_TOKEN', 'root'))
        
        self.client = hvac.Client(url=vault_url, token=vault_token)
        self.key_name = getattr(settings, 'VAULT_TRANSIT_KEY', 'authclaw-key')
        self.mount_point = getattr(settings, 'VAULT_TRANSIT_MOUNT', 'transit')

        if os.getenv('ENVIRONMENT', 'development') != 'production':
            self._ensure_dev_transit_key()

    def _ensure_dev_transit_key(self) -> None:
        try:
            self.client.secrets.transit.read_key(name=self.key_name, mount_point=self.mount_point)
            return
        except hvac.exceptions.InvalidPath:
            pass

        try:
            self.client.sys.enable_secrets_engine(backend_type='transit', path=self.mount_point)
        except hvac.exceptions.InvalidRequest as exc:
            if "path is already in use" not in str(exc).lower():
                raise

        try:
            self.client.secrets.transit.read_key(name=self.key_name, mount_point=self.mount_point)
        except hvac.exceptions.InvalidPath:
            self.client.secrets.transit.create_key(name=self.key_name, mount_point=self.mount_point)

    def generate_data_key(self) -> tuple[bytes, str]:
        """
        Calls Vault Transit Generate Data Key endpoint.
        Returns (plaintext_bytes, ciphertext_string)
        Note: Vault returns plaintext as base64 string, so we must decode to bytes.
        """
        response = self.client.secrets.transit.generate_data_key(
            name=self.key_name,
            key_type='plaintext',
            bits=256,
            mount_point=self.mount_point,
        )
        plaintext_b64 = response['data']['plaintext']
        ciphertext = response['data']['ciphertext']  # vault format: vault:v1:...
        
        plaintext_dek = base64.b64decode(plaintext_b64)
        # We can store the vault ciphertext string as is since it's already encoded
        return plaintext_dek, ciphertext

    def encrypt_dek(self, plaintext_dek: bytes) -> str:
        """
        Calls Vault Encrypt.
        """
        plaintext_b64 = base64.b64encode(plaintext_dek).decode('utf-8')
        response = self.client.secrets.transit.encrypt_data(
            name=self.key_name,
            plaintext=plaintext_b64,
            mount_point=self.mount_point,
        )
        return response['data']['ciphertext']

    def decrypt_dek(self, encrypted_dek: str) -> bytes:
        """
        Calls Vault Decrypt.
        """
        response = self.client.secrets.transit.decrypt_data(
            name=self.key_name,
            ciphertext=encrypted_dek,
            mount_point=self.mount_point,
        )
        plaintext_b64 = response['data']['plaintext']
        return base64.b64decode(plaintext_b64)
