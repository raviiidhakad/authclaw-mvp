import base64
import boto3
from app.core.encryption.provider import EncryptionProvider
from app.core.config import settings

class KmsEncryptionProvider(EncryptionProvider):
    """
    AWS KMS implementation of EncryptionProvider.
    Uses boto3 to interface with AWS KMS.
    """
    
    def __init__(self):
        # In a real environment, region and credentials would be configured via env vars or IAM roles.
        # For our test environment or moto, we let boto3 resolve it from the environment.
        self.client = boto3.client('kms', region_name=settings.AWS_REGION if hasattr(settings, 'AWS_REGION') else 'us-east-1')
        self.key_id = settings.KMS_KEY_ID if hasattr(settings, 'KMS_KEY_ID') else 'alias/authclaw-master-key'

    def generate_data_key(self) -> tuple[bytes, str]:
        """
        Calls KMS GenerateDataKey.
        Returns (plaintext_bytes, base64_encrypted_str)
        """
        response = self.client.generate_data_key(
            KeyId=self.key_id,
            KeySpec='AES_256'
        )
        plaintext_dek = response['Plaintext']
        encrypted_dek = base64.b64encode(response['CiphertextBlob']).decode('utf-8')
        return plaintext_dek, encrypted_dek

    def encrypt_dek(self, plaintext_dek: bytes) -> str:
        """
        Calls KMS Encrypt on an existing DEK (useful if we generated the DEK locally).
        """
        response = self.client.encrypt(
            KeyId=self.key_id,
            Plaintext=plaintext_dek
        )
        return base64.b64encode(response['CiphertextBlob']).decode('utf-8')

    def decrypt_dek(self, encrypted_dek: str) -> bytes:
        """
        Calls KMS Decrypt.
        """
        ciphertext_blob = base64.b64decode(encrypted_dek)
        response = self.client.decrypt(
            CiphertextBlob=ciphertext_blob
        )
        return response['Plaintext']
