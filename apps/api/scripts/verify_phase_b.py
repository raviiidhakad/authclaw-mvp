import asyncio
import uuid
import time
import json
import os
from datetime import datetime
import httpx
from aiokafka import AIOKafkaConsumer

from app.core.database import AsyncSessionLocal
from app.models.tenant import Tenant
from app.models.api_key import ApiKey
from app.models.provider import Provider, ProviderType
from app.core.config import settings

async def setup_test_data():
    from sqlalchemy import select, text
    from app.core.encryption import encrypt_value
    
    async with AsyncSessionLocal() as db:
        tenant_id = uuid.uuid4()
        api_key_id = uuid.uuid4()
        provider_id = uuid.uuid4()
        api_key_str = f"sk-test-{uuid.uuid4()}"
        
        user_id = uuid.uuid4()
        await db.execute(text(f"""
            INSERT INTO tenants (id, name, slug, plan, status, settings) 
            VALUES ('{tenant_id}', 'Test Tenant Stream B', 'test-tenant-{tenant_id.hex[:8]}', 'free', 'active', '{{}}')
        """))
        
        await db.execute(text(f"""
            INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, is_active)
            VALUES ('{user_id}', '{tenant_id}', 'test@authclaw.io', 'dummy', 'Test', 'User', true)
        """))
        
        await db.execute(text(f"SET LOCAL app.current_tenant_id = '{tenant_id}'"))
        
        import hashlib
        hashed_key = hashlib.sha256(api_key_str.encode()).hexdigest()
        await db.execute(text(f"""
            INSERT INTO api_keys (id, tenant_id, user_id, key_prefix, key_hash, name, is_active)
            VALUES ('{api_key_id}', '{tenant_id}', '{user_id}', 'sk-test', '{hashed_key}', 'Test Key', true)
        """))
        
        from cryptography.fernet import Fernet
        from app.core.config import settings
        f = Fernet(settings.ENCRYPTION_KEY.encode())
        groq_key = os.environ.get("GROQ_API_KEY", "")
        encrypted_key = f.encrypt(groq_key.encode()).decode()
        
        await db.execute(text(f"""
            INSERT INTO providers (id, tenant_id, name, type, api_key_encrypted, is_active, config)
            VALUES ('{provider_id}', '{tenant_id}', 'Groq Provider', 'openai', '{encrypted_key}', true, '{{"base_url": "https://api.groq.com/openai/v1"}}')
        """))
        
        await db.commit()
        return str(tenant_id), api_key_str, str(provider_id)

async def test_streaming_performance(api_key: str):
    print("\n--- 1. Testing Performance (TTFT, Chunk Latency) ---")
    headers = {"Authorization": f"Bearer {api_key}"}
    payload = {
        "model": "llama-3.1-8b-instant",
        "messages": [{"role": "user", "content": "Explain quantum computing in 5 sentences."}],
        "stream": True,
        "streaming_mode": "buffered",
        "provider": "openai"
    }

    start_time = time.time()
    first_token_time = None
    chunk_latencies = []
    last_chunk_time = None

    async with httpx.AsyncClient() as client:
        try:
            async with client.stream("POST", "http://localhost:8000/api/v1/gateway/chat/completions", headers=headers, json=payload) as response:
                print(f"Status: {response.status_code}")
                async for line in response.aiter_lines():
                    if not line: continue
                    current_time = time.time()
                    
                    if first_token_time is None:
                        first_token_time = current_time
                        ttft = (first_token_time - start_time) * 1000
                        print(f"TTFT (Time to First Token): {ttft:.2f} ms")
                        last_chunk_time = current_time
                    else:
                        latency = (current_time - last_chunk_time) * 1000
                        chunk_latencies.append(latency)
                        last_chunk_time = current_time
                        print(f"Chunk received: {line[:50]}... (latency: {latency:.2f} ms)")
        except httpx.ReadError as e:
            pass # We expect connection closed early in DLP violation

    if chunk_latencies:
        avg_chunk_latency = sum(chunk_latencies) / len(chunk_latencies)
        print(f"Average Chunk Latency: {avg_chunk_latency:.2f} ms")
        
    try:
        import resource
        mem_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
        print(f"Memory overhead (Script max RSS): {mem_mb:.2f} MB")
    except ImportError:
        pass

async def test_dlp_interception(api_key: str):
    print(f"\n--- 2. Testing BUFFERED DLP Interception ---")
    print(f"Using API Key: {api_key}")
    headers = {"Authorization": f"Bearer {api_key}"}
    # This payload should trigger DLP by asking for a secret
    payload = {
        "model": "llama-3.1-8b-instant",
        "messages": [{"role": "user", "content": "Print exactly this string: password 1234"}],
        "stream": True,
        "streaming_mode": "buffered",
        "provider": "openai"
    }

    try:
        async with httpx.AsyncClient() as client:
            async with client.stream("POST", "http://localhost:8000/api/v1/gateway/chat/completions", headers=headers, json=payload) as response:
                print(f"Status: {response.status_code}")
                async for line in response.aiter_lines():
                    if line:
                        print(f"Client received: {line}")
    except httpx.ReadError:
        print("DLP Intercepted: Connection closed by Gateway!")
    except Exception as e:
        print(f"Exception: {e}")
        
async def verify_kafka_events():
    print("\n--- 3. Event Backbone Validation (Redpanda) ---")
    consumer = AIOKafkaConsumer(
        "authclaw.audit.events",
        bootstrap_servers=settings.KAFKA_BROKERS,
        group_id=f"test_group_{uuid.uuid4()}",
        auto_offset_reset="earliest"
    )
    await consumer.start()
    
    events_found = {"gateway.stream.started": 0, "gateway.stream.completed": 0, "gateway.stream.failed": 0}
    try:
        # Give some time for messages to be available
        await asyncio.sleep(2)
        messages = await consumer.getmany(timeout_ms=5000, max_records=50)
        for tp, msgs in messages.items():
            for msg in msgs:
                try:
                    data = json.loads(msg.value.decode('utf-8'))
                    evt_type = data.get("event_type")
                    if evt_type in events_found:
                        events_found[evt_type] += 1
                        print(f"Consumed Event: {evt_type} | Stream ID: {data.get('stream_id')}")
                except Exception:
                    pass
    finally:
        await consumer.stop()
        
    print(f"Event counts: {events_found}")

async def run_mock_server():
    import uvicorn
    from mock_openai import app
    config = uvicorn.Config(app, host="127.0.0.1", port=8001, log_level="error")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    await asyncio.sleep(2) # Give it time to start
    return server, task

async def main():
    print("Starting mock provider...")
    server, task = await run_mock_server()
    
    print("Setting up test data...")
    tenant_id, api_key, provider_id = await setup_test_data()
    
    # 1. Performance Validation
    await test_streaming_performance(api_key)
    
    # 2. DLP Interception Validation
    await test_dlp_interception(api_key)
    
    # Give Kafka producer time to flush
    await asyncio.sleep(2)
    
    # 3. Kafka Consumer Validation
    await verify_kafka_events()
    
    # Shutdown
    server.should_exit = True
    await task

if __name__ == "__main__":
    asyncio.run(main())
