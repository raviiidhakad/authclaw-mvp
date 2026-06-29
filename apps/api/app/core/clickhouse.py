import aiohttp
from aiochclient import ChClient
import logging
from typing import Optional

from app.core.config import settings

logger = logging.getLogger(__name__)

class ClickHouseManager:
    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None
        self.client: Optional[ChClient] = None

    async def connect(self):
        # We assume settings have CLICKHOUSE_URL, CLICKHOUSE_USER, CLICKHOUSE_PASSWORD
        # Fallbacks for local testing if not present
        url = getattr(settings, "CLICKHOUSE_URL", "http://localhost:8123")
        user = getattr(settings, "CLICKHOUSE_USER", "authclaw")
        password = getattr(settings, "CLICKHOUSE_PASSWORD", "authclaw_clickhouse_local_password")
        db = getattr(settings, "CLICKHOUSE_DB", "authclaw")

        # TCPConnector for connection pooling
        connector = aiohttp.TCPConnector(limit=100, keepalive_timeout=60)
        self.session = aiohttp.ClientSession(connector=connector)
        
        self.client = ChClient(
            self.session,
            url=url,
            user=user,
            password=password,
            database=db
        )
        logger.info("ClickHouse connection pool initialized.")

    async def disconnect(self):
        if self.client:
            try:
                await self.client.close()
            except Exception as exc:
                logger.warning("ClickHouse client close failed: %s", exc)
            finally:
                self.client = None
        if self.session:
            try:
                await self.session.close()
            except Exception as exc:
                logger.warning("ClickHouse session close failed: %s", exc)
            finally:
                self.session = None
        logger.info("ClickHouse connection pool closed.")

    async def get_client(self) -> ChClient:
        if not self.client or not self.session or self.session.closed:
            await self.connect()
        return self.client

clickhouse_manager = ClickHouseManager()

async def get_clickhouse_client() -> ChClient:
    """FastAPI dependency to get the ClickHouse client."""
    return await clickhouse_manager.get_client()
