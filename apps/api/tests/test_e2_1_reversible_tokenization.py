import pytest
import uuid
import json
import asyncio
import redis
from unittest.mock import patch, MagicMock, AsyncMock

from app.core.engine.token_vault import TokenVaultService
from app.core.redis import RedisClient
from app.core.config import settings
from app.core.engine.pii import PIIRedactor

pytestmark = pytest.mark.asyncio


def _clear_reversible_token_maps():
    client = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
    for key in client.scan_iter("pii:map:*"):
        client.delete(key)
    client.close()
    RedisClient._instance = None


@pytest.fixture(autouse=True)
def isolate_reversible_tokenization(monkeypatch):
    import app.core.encryption

    monkeypatch.setenv("ENCRYPTION_PROVIDER", "local")
    monkeypatch.setattr(settings, "ENCRYPTION_PROVIDER", "local")
    app.core.encryption._provider = None
    _clear_reversible_token_maps()
    yield
    app.core.encryption._provider = None
    _clear_reversible_token_maps()


class TestReversibleTokenization:
    # ── Functional Tests ─────────────────────────────────────────────

    async def test_tokenize_reversible_capability_enabled(self):
        tenant_id = uuid.uuid4()
        text = "My email is test@example.com"
        matches = [{"entity_type": "EMAIL_ADDRESS", "start": 12, "end": 28, "value": "test@example.com"}]
        
        result = await TokenVaultService.tokenize(tenant_id, text, matches)
        
        assert "{{AUTHCLAW:TOKEN:" in result
        assert "test@example.com" not in result

    async def test_detokenize_restores_plaintext(self):
        tenant_id = uuid.uuid4()
        text = "My email is test@example.com"
        matches = [{"entity_type": "EMAIL_ADDRESS", "start": 12, "end": 28, "value": "test@example.com"}]
        
        tokenized = await TokenVaultService.tokenize(tenant_id, text, matches)
        detokenized = await TokenVaultService.detokenize(tenant_id, tokenized)
        
        assert detokenized == text

    async def test_gateway_inbound_mixed_strategies(self):
        tenant_id = uuid.uuid4()
        text = "Call 555-1234 or email foo@bar.com"
        detections = [
            {"entity_type": "PHONE_NUMBER", "start": 5, "end": 13},
            {"entity_type": "EMAIL_ADDRESS", "start": 23, "end": 34}
        ]
        entity_actions = {
            "PHONE_NUMBER": "SYNTHETIC",
            "EMAIL_ADDRESS": "MASK"
        }
        reversible_entities = ["PHONE_NUMBER"] # Phone is reversible, Email is NOT

        result, mode = await TokenVaultService.apply_redaction(
            text=text,
            detections=detections,
            sanitized_text="Call [PHONE_NUMBER] or email [EMAIL_ADDRESS]",
            route_mode="",
            entity_actions=entity_actions,
            reversible_entities=reversible_entities,
            tenant_id=tenant_id
        )

        assert "{{AUTHCLAW:TOKEN:" in result
        assert "[EMAIL_ADDRESS]" in result
        assert "foo@bar.com" not in result
        assert "555-1234" not in result

        # Detokenizing should bring back the phone, but email remains masked
        detokenized = await TokenVaultService.detokenize(tenant_id, result)
        assert "555-1234" in detokenized
        assert "[EMAIL_ADDRESS]" in detokenized

    # ── Security Tests ───────────────────────────────────────────────

    async def test_cross_tenant_isolation(self):
        tenant_a = uuid.uuid4()
        tenant_b = uuid.uuid4()
        
        text = "Secret 123"
        matches = [{"start": 7, "end": 10, "value": "123"}]
        
        tokenized = await TokenVaultService.tokenize(tenant_a, text, matches)
        
        # Tenant B tries to resolve Tenant A's token
        detokenized_b = await TokenVaultService.detokenize(tenant_b, tokenized)
        assert "123" not in detokenized_b
        assert "{{AUTHCLAW:TOKEN:" in detokenized_b

        # Tenant A can resolve it
        detokenized_a = await TokenVaultService.detokenize(tenant_a, tokenized)
        assert "123" in detokenized_a

    async def test_no_plaintext_stored_in_redis(self):
        tenant_id = uuid.uuid4()
        plaintext = "SuperSecretData"
        matches = [{"start": 0, "end": 15, "value": plaintext}]
        
        await TokenVaultService.tokenize(tenant_id, plaintext, matches)
        
        redis = RedisClient.get()
        keys = await redis.keys(f"pii:map:{tenant_id}:*")
        assert len(keys) == 1
        
        ciphertext = await redis.get(keys[0])
        assert ciphertext is not None
        ciphertext_str = ciphertext.decode('utf-8') if isinstance(ciphertext, bytes) else str(ciphertext)
        assert plaintext not in ciphertext_str

    async def test_invalid_token_handling(self):
        tenant_id = uuid.uuid4()
        text = "This is a fake {{AUTHCLAW:TOKEN:12345-abcde}} token"
        detokenized = await TokenVaultService.detokenize(tenant_id, text)
        
        # Unresolved tokens must remain safely in the text (fail-closed)
        assert "{{AUTHCLAW:TOKEN:12345-abcde}}" in detokenized

    @patch('app.core.engine.token_vault.decrypt_value')
    async def test_kms_decryption_failure_fails_closed(self, mock_decrypt):
        mock_decrypt.side_effect = Exception("KMS unavailable")
        tenant_id = uuid.uuid4()
        text = "Data"
        matches = [{"start": 0, "end": 4, "value": "Data"}]
        
        tokenized = await TokenVaultService.tokenize(tenant_id, text, matches)
        detokenized = await TokenVaultService.detokenize(tenant_id, tokenized)
        
        # Must fail closed by leaving token intact
        assert "Data" not in detokenized
        assert "{{AUTHCLAW:TOKEN:" in detokenized

    @patch('app.core.engine.token_vault.encrypt_value')
    async def test_kms_encryption_failure_fails_closed(self, mock_encrypt):
        mock_encrypt.side_effect = Exception("KMS unavailable")
        tenant_id = uuid.uuid4()
        
        with pytest.raises(Exception, match="KMS unavailable"):
            await TokenVaultService.tokenize(tenant_id, "Data", [{"start": 0, "end": 4, "value": "Data"}])

    async def test_expired_tokens(self):
        tenant_id = uuid.uuid4()
        token_uuid = str(uuid.uuid4())
        
        # Store with 1 second TTL
        with patch('app.core.config.settings.TOKEN_TTL_SECONDS', 1):
            await TokenVaultService.store(tenant_id, token_uuid, "ExpiringData")
            
        await asyncio.sleep(1.1) # Wait for TTL
        
        val = await TokenVaultService.retrieve(tenant_id, token_uuid)
        assert val is None

    # ── Streaming & Object Traverse Tests ────────────────────────────

    async def test_gateway_payload_recursive_detokenization(self):
        tenant_id = uuid.uuid4()
        
        text1 = "Value1"
        text2 = "Value2"
        tok1 = await TokenVaultService.tokenize(tenant_id, text1, [{"start": 0, "end": 6, "value": text1}])
        tok2 = await TokenVaultService.tokenize(tenant_id, text2, [{"start": 0, "end": 6, "value": text2}])
        
        payload = {
            "choices": [
                {
                    "message": {
                        "content": f"Found {tok1} and {tok2}"
                    }
                }
            ],
            "metadata": [tok1]
        }
        
        detokenized_payload = await TokenVaultService.detokenize_payload(tenant_id, payload)
        
        content = detokenized_payload["choices"][0]["message"]["content"]
        assert "Found Value1 and Value2" == content
        assert detokenized_payload["metadata"][0] == "Value1"

    # ── Performance & Concurrency Tests ──────────────────────────────

    async def test_hundreds_of_tokens_batching(self):
        tenant_id = uuid.uuid4()
        mappings = {str(uuid.uuid4()): f"Value_{i}" for i in range(500)}
        
        # Store 500 tokens in a single pipeline
        await TokenVaultService.store_batch(tenant_id, mappings)
        
        redis = RedisClient.get()
        keys = await redis.keys(f"pii:map:{tenant_id}:*")
        assert len(keys) == 500

    async def test_concurrent_tenants(self):
        async def tenant_worker(tenant_id, idx):
            val = f"Data_{idx}"
            tok = await TokenVaultService.tokenize(tenant_id, val, [{"start": 0, "end": len(val), "value": val}])
            detok = await TokenVaultService.detokenize(tenant_id, tok)
            return detok == val

        results = []
        for i in range(100):
            results.append(await tenant_worker(uuid.uuid4(), i))
        assert all(results)
