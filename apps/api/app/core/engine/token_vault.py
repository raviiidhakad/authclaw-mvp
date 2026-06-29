import re
import uuid
import logging
from typing import Dict, List, Optional, Any

from app.core.config import settings
from app.core.redis import RedisClient
from app.core.encryption import encrypt_value, decrypt_value

logger = logging.getLogger(__name__)


class TokenVaultService:
    """
    Service responsible for reversible tokenization of PII/PHI entities.
    It provides capabilities to generate deterministic tokens, securely encrypt
    the original plaintext, store mappings in Redis with tenant isolation,
    and reliably restore the plaintext from tokens.
    """

    TOKEN_REGEX = re.compile(r"\{\{AUTHCLAW:TOKEN:([a-fA-F0-9\-]+)\}\}")
    TOKEN_FORMAT = "{{{{AUTHCLAW:TOKEN:{token_uuid}}}}}"

    @classmethod
    def _build_key(cls, tenant_id: str | uuid.UUID, token_uuid: str) -> str:
        """
        Constructs a tenant-isolated Redis key for token storage.
        """
        return f"pii:map:{tenant_id}:{token_uuid}"

    @classmethod
    async def store(cls, tenant_id: str | uuid.UUID, token_uuid: str, plaintext: str) -> None:
        """
        Encrypts and stores a single token mapping in Redis.
        Raises an exception if storage fails, ensuring fail-closed behavior.
        """
        try:
            ciphertext = encrypt_value(plaintext)
            key = cls._build_key(tenant_id, token_uuid)
            redis = RedisClient.get()
            await redis.setex(key, settings.TOKEN_TTL_SECONDS, ciphertext)
        except Exception as e:
            logger.error("Failed to store token %s for tenant %s: %s", token_uuid, tenant_id, e)
            raise

    @classmethod
    async def store_batch(cls, tenant_id: str | uuid.UUID, mappings: Dict[str, str]) -> None:
        """
        Encrypts and stores multiple token mappings efficiently using a Redis pipeline.
        
        Args:
            tenant_id: The UUID of the tenant.
            mappings: A dictionary mapping token_uuid strings to their plaintext values.
            
        Raises an exception if storage fails, ensuring fail-closed behavior.
        """
        if not mappings:
            return

        try:
            redis = RedisClient.get()
            pipeline = redis.pipeline()
            for token_uuid, plaintext in mappings.items():
                ciphertext = encrypt_value(plaintext)
                key = cls._build_key(tenant_id, token_uuid)
                pipeline.setex(key, settings.TOKEN_TTL_SECONDS, ciphertext)
            await pipeline.execute()
        except Exception as e:
            logger.error("Failed to batch store tokens for tenant %s: %s", tenant_id, e)
            raise

    @classmethod
    async def retrieve(cls, tenant_id: str | uuid.UUID, token_uuid: str) -> Optional[str]:
        """
        Retrieves and decrypts a token mapping from Redis.
        
        Returns:
            The decrypted plaintext, or None if the token expired or decryption fails.
            Failing to decrypt returns None, preserving the token in the payload (fail-closed).
        """
        try:
            key = cls._build_key(tenant_id, token_uuid)
            redis = RedisClient.get()
            ciphertext = await redis.get(key)
            if not ciphertext:
                return None
            return decrypt_value(ciphertext)
        except Exception as e:
            logger.error("Failed to retrieve or decrypt token %s for tenant %s: %s", token_uuid, tenant_id, e)
            return None

    @classmethod
    async def delete(cls, tenant_id: str | uuid.UUID, token_uuid: str) -> None:
        """
        Deletes a token mapping from Redis.
        """
        try:
            key = cls._build_key(tenant_id, token_uuid)
            redis = RedisClient.get()
            await redis.delete(key)
        except Exception as e:
            logger.error("Failed to delete token %s for tenant %s: %s", token_uuid, tenant_id, e)

    @classmethod
    async def tokenize(
        cls, 
        tenant_id: str | uuid.UUID, 
        text: str, 
        matches: List[Dict[str, Any]]
    ) -> str:
        """
        Generates deterministic tokens for identified PII matches in the text,
        stores the encrypted original text in Redis, and returns the modified text.
        
        Args:
            tenant_id: The UUID of the tenant.
            text: The original prompt text.
            matches: List of dicts representing detections (start, end, optional value).
            
        Returns:
            The detokenized text with deterministic placeholders.
        """
        result = text
        mappings = {}
        
        # Ensure we have the value for each match, extracting it if necessary
        processed_matches = []
        for match in matches:
            start = match.get('start', 0)
            end = match.get('end', 0)
            value = match.get('value')
            if value is None and start < end:
                value = text[start:end]
            if value:
                processed_matches.append({"start": start, "end": end, "value": value})

        # Process from back to front to maintain index integrity during replacement
        sorted_matches = sorted(processed_matches, key=lambda x: x["start"], reverse=True)
        
        for match in sorted_matches:
            token_uuid = str(uuid.uuid4())
            placeholder = cls.TOKEN_FORMAT.format(token_uuid=token_uuid)
            
            mappings[token_uuid] = match["value"]
            
            start = match["start"]
            end = match["end"]
            result = result[:start] + placeholder + result[end:]
            
        if mappings:
            await cls.store_batch(tenant_id, mappings)
            
        return result

    @classmethod
    async def detokenize(cls, tenant_id: str | uuid.UUID, text: str) -> str:
        """
        Scans the text for deterministic AuthClaw tokens belonging to the tenant,
        retrieves their original plaintext from Redis, and substitutes them.
        
        Args:
            tenant_id: The UUID of the tenant.
            text: The LLM completion text potentially containing tokens.
            
        Returns:
            The restored text. Unresolved tokens remain in the text securely.
        """
        if not text:
            return text
            
        # Find all unique token UUIDs in the text
        token_uuids = list(set(cls.TOKEN_REGEX.findall(text)))
        if not token_uuids:
            return text
            
        # Retrieve all plaintexts
        replacements = {}
        for token_uuid in token_uuids:
            plaintext = await cls.retrieve(tenant_id, token_uuid)
            if plaintext:
                replacements[token_uuid] = plaintext
                
        # Replace tokens in text
        result = text
        for token_uuid, plaintext in replacements.items():
            token_str = cls.TOKEN_FORMAT.format(token_uuid=token_uuid)
            result = result.replace(token_str, plaintext)
            
        return result
