"""
AuthClaw — Azure Connector Tests
----------------------------------
All tests use httpx mock transport (unittest.mock) — no live Azure calls.
"""
from __future__ import annotations

import uuid
from typing import List
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.models.finding import FindingSeverity
from app.models.integration import CloudIntegration, CloudProvider, IntegrationStatus
from app.services.connectors.azure import AzureConnector, _AZURE_SEVERITY_MAP
from app.services.connectors.registry import ConnectorRegistry

SUB_ID        = "00000000-0000-0000-0000-000000000001"
CLIENT_ID     = "00000000-0000-0000-0000-000000000003"
CLIENT_SECRET = "test-secret-value"
TENANT_ID     = "00000000-0000-0000-0000-000000000002"
FAKE_TOKEN    = "eyJ.fake.token"

def _mock_response(status_code: int = 200, json_body: object = None) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_body or {}
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            f"HTTP {status_code}", request=MagicMock(), response=resp
        )
    return resp

@pytest.fixture(autouse=True)
def reset_registry():
    ConnectorRegistry._reset_for_testing()
    import importlib
    import app.services.connectors.azure
    importlib.reload(app.services.connectors.azure)
    yield
    ConnectorRegistry._reset_for_testing()

@pytest.fixture
def connector():
    intg = MagicMock(spec=CloudIntegration)
    intg.id, intg.tenant_id = uuid.uuid4(), uuid.uuid4()
    intg.target_identifier = SUB_ID
    intg.provider_type = CloudProvider.azure
    intg.status = IntegrationStatus.active
    return AzureConnector(
        integration=intg,
        credentials={"azure_client_id": CLIENT_ID, "azure_client_secret": CLIENT_SECRET, "azure_tenant_id": TENANT_ID},
    )

@pytest.fixture
def mock_client():
    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    with patch("app.services.connectors.azure.httpx.AsyncClient", return_value=client):
        yield client

@pytest.fixture
def mock_token(connector):
    with patch.object(connector, "_get_arm_token", return_value=FAKE_TOKEN):
        yield

class TestAzureConnectorRegistration:
    def test_provider_is_azure(self, connector):
        assert connector.PROVIDER == CloudProvider.azure
    def test_registered_in_registry(self):
        assert "azure" in ConnectorRegistry.registered_providers()

class TestAzureSeverityMap:
    @pytest.mark.parametrize("raw,expected", [
        ("High", FindingSeverity.high), ("Medium", FindingSeverity.medium),
        ("Low", FindingSeverity.low), ("Informational", FindingSeverity.low),
        ("high", FindingSeverity.high), ("medium", FindingSeverity.medium),
        ("low", FindingSeverity.low), ("informational", FindingSeverity.low),
    ])
    def test_known_values(self, raw, expected):
        assert _AZURE_SEVERITY_MAP[raw] == expected

class TestAzureValidateCredentials:
    @pytest.mark.asyncio
    async def test_success(self, connector, mock_token, mock_client):
        mock_client.get.return_value = _mock_response(200, {"id": f"/subscriptions/{SUB_ID}", "state": "Enabled"})
        await connector.validate_credentials()

    @pytest.mark.parametrize("missing_key", ["azure_client_id", "azure_client_secret", "azure_tenant_id"])
    @pytest.mark.asyncio
    async def test_missing_credentials_raises(self, missing_key):
        creds = {"azure_client_id": CLIENT_ID, "azure_client_secret": CLIENT_SECRET, "azure_tenant_id": TENANT_ID}
        del creds[missing_key]
        conn = AzureConnector(integration=MagicMock(target_identifier=SUB_ID), credentials=creds)
        with pytest.raises(ValueError, match="missing required key"):
            await conn.validate_credentials()

    @pytest.mark.asyncio
    async def test_empty_subscription_raises(self):
        intg = MagicMock(target_identifier="")
        conn = AzureConnector(integration=intg, credentials={"azure_client_id": CLIENT_ID, "azure_client_secret": CLIENT_SECRET, "azure_tenant_id": TENANT_ID})
        with pytest.raises(ValueError, match="target_identifier must be the subscription ID"):
            await conn.validate_credentials()

    @pytest.mark.asyncio
    async def test_token_auth_401_raises(self, connector, mock_client):
        mock_client.post.return_value = _mock_response(401)
        with pytest.raises(ValueError, match="HTTP 401"):
            await connector.validate_credentials()

    @pytest.mark.asyncio
    async def test_subscription_403_raises(self, connector, mock_token, mock_client):
        mock_client.get.return_value = _mock_response(403)
        with pytest.raises(ValueError, match="lacks access"):
            await connector.validate_credentials()

    @pytest.mark.asyncio
    async def test_subscription_404_raises(self, connector, mock_token, mock_client):
        mock_client.get.return_value = _mock_response(404)
        with pytest.raises(ValueError, match="not found"):
            await connector.validate_credentials()

    @pytest.mark.asyncio
    async def test_disabled_subscription_state_raises(self, connector, mock_token, mock_client):
        mock_client.get.return_value = _mock_response(200, {"state": "Deleted"})
        with pytest.raises(ValueError, match="not in an accessible state"):
            await connector.validate_credentials()

def _make_assessment(name: str, severity: str = "High", code: str = "Unhealthy") -> dict:
    return {
        "id": f"/assessments/{name}", "name": name,
        "properties": {"status": {"code": code}, "metadata": {"severity": severity}},
    }

def _make_alert(name: str, severity: str = "High") -> dict:
    return {
        "id": f"/alerts/{name}", "name": name,
        "properties": {"alertDisplayName": f"Alert {name}", "severity": severity},
    }

class TestAzureFetchAssessments:
    @pytest.mark.asyncio
    async def test_fetches_unhealthy_assessments_only(self, connector, mock_token, mock_client):
        mock_client.get.return_value = _mock_response(200, {"value": [
            _make_assessment("a1", "High", "Unhealthy"),
            _make_assessment("a2", "Medium", "Healthy"),
            _make_assessment("a3", "Low", "Unhealthy"),
        ]})
        findings = await connector.fetch_findings()
        assert len(findings) == 2
        assert "a2" not in [f.external_id for f in findings]

    @pytest.mark.parametrize("sev,expected", [("High", FindingSeverity.high), ("Medium", FindingSeverity.medium)])
    @pytest.mark.asyncio
    async def test_severity_mapping(self, connector, mock_token, mock_client, sev, expected):
        mock_client.get.return_value = _mock_response(200, {"value": [_make_assessment("a1", sev, "Unhealthy")]})
        findings = await connector.fetch_findings()
        assert findings[0].severity == expected

    @pytest.mark.asyncio
    async def test_empty_assessments_returns_empty_list(self, connector, mock_token, mock_client):
        mock_client.get.return_value = _mock_response(200, {"value": []})
        assert await connector.fetch_findings() == []

    @pytest.mark.asyncio
    async def test_finding_external_id_matches_assessment_name(self, connector, mock_token, mock_client):
        mock_client.get.return_value = _mock_response(200, {"value": [_make_assessment("unique-abc")]})
        assert (await connector.fetch_findings())[0].external_id == "unique-abc"

    @pytest.mark.asyncio
    async def test_dedup_hash_length_and_format(self, connector, mock_token, mock_client):
        mock_client.get.return_value = _mock_response(200, {"value": [_make_assessment("a1")]})
        f = (await connector.fetch_findings())[0]
        h = connector.make_dedup_hash(f.external_id, f.resource_id)
        assert len(h) == 64 and all(c in "0123456789abcdef" for c in h)

    @pytest.mark.asyncio
    async def test_limit_respected(self, connector, mock_token, mock_client):
        mock_client.get.return_value = _mock_response(200, {"value": [_make_assessment(f"a{i}") for i in range(10)]})
        with patch("app.services.connectors.azure.settings") as mock_settings:
            mock_settings.MAX_FINDINGS_PER_SYNC = 3
            assert len(await connector.fetch_findings()) <= 3

class TestAzureFetchAlertsFallback:
    @pytest.mark.asyncio
    async def test_fallback_on_403_and_404(self, connector, mock_token, mock_client):
        for code in [403, 404]:
            mock_client.get.side_effect = [_mock_response(code), _mock_response(200, {"value": [_make_alert("a1")]})]
            findings = await connector.fetch_findings()
            assert len(findings) == 1 and "Alert" in findings[0].title

    @pytest.mark.asyncio
    async def test_non_fallback_error_propagates(self, connector, mock_token, mock_client):
        mock_client.get.return_value = _mock_response(500)
        with pytest.raises(httpx.HTTPStatusError):
            await connector.fetch_findings()
