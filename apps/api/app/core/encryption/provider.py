import abc

class EncryptionProvider(abc.ABC):
    """
    Abstract base class for Data Encryption Key (DEK) encryption/decryption.
    Providers implementations (e.g. KMS, Vault) must override these methods.
    """

    @abc.abstractmethod
    def encrypt_dek(self, plaintext_dek: bytes) -> str:
        """
        Encrypt the given plaintext DEK.
        
        Args:
            plaintext_dek: Raw bytes of the Data Encryption Key.
            
        Returns:
            A Base64-encoded string representing the encrypted DEK.
        """
        pass

    @abc.abstractmethod
    def decrypt_dek(self, encrypted_dek: str) -> bytes:
        """
        Decrypt the given encrypted DEK.
        
        Args:
            encrypted_dek: A Base64-encoded string representing the encrypted DEK.
            
        Returns:
            Raw bytes of the decrypted Data Encryption Key.
        """
        pass

    @abc.abstractmethod
    def generate_data_key(self) -> tuple[bytes, str]:
        """
        Generate a new Data Encryption Key (DEK).
        
        Returns:
            A tuple containing (plaintext_dek, encrypted_dek).
            - plaintext_dek: Raw bytes, MUST BE SECURELY SCRUBBED after use.
            - encrypted_dek: Base64-encoded string to be persisted.
        """
        pass
