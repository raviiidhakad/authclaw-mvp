from __future__ import annotations

import time
import uuid
from typing import List
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.models.finding import FindingSeverity
from app.models.integration import CloudIntegration, CloudProvider, IntegrationStatus
from app.services.connectors.base import RawFindingData
from app.services.connectors.gcp import GCPConnector, _GCP_SEVERITY_MAP
from app.services.connectors.registry import ConnectorRegistry


GCP_PROJECT = "my-gcp-project-123"


def _make_sa_creds(project_id: str = GCP_PROJECT) -> dict:
    return {
        "type":            "service_account",
        "project_id":      project_id,
        "private_key_id":  "key-001",
        "private_key":     "-----BEGIN RSA PRIVATE KEY-----\nFAKE\n-----END RSA PRIVATE KEY-----",
        "client_email":    f"scanner@{project_id}.iam.gserviceaccount.com",
        "client_id":       "123456789",
        "token_uri":       "https://oauth2.googleapis.com/token",
    }


def _make_integration(project_id: str = GCP_PROJECT) -> CloudIntegration:
    intg = MagicMock(spec=CloudIntegration)
    intg.id                = uuid.uuid4()
    intg.tenant_id         = uuid.uuid4()
    intg.target_identifier = project_id
    intg.provider_type     = CloudProvider.gcp
    intg.status            = IntegrationStatus.active
    return intg


def _make_connector(project_id: str = GCP_PROJECT) -> GCPConnector:
    return GCPConnector(
        integration=_make_integration(project_id),
        credentials=_make_sa_creds(project_id),
    )


def _http_error(status_code: int) -> httpx.HTTPStatusError:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = f"HTTP {status_code} error"
    return httpx.HTTPStatusError(
        f"HTTP {status_code}", request=MagicMock(), response=resp
    )


@pytest.fixture(autouse=True)
def reset_registry():
    ConnectorRegistry._reset_for_testing()
    import importlib
    import app.services.connectors.gcp
    importlib.reload(app.services.connectors.gcp)
    yield
    ConnectorRegistry._reset_for_testing()


@pytest.fixture
def connector():
    return _make_connector()


def _inject_valid_token(connector: GCPConnector) -> None:
    connector._access_token = "ya29.fake_token"
    connector._token_expiry = time.monotonic() + 3600


class TestGCPValidateCredentials:

    @pytest.mark.asyncio
    async def test_success(self, connector):
        _inject_valid_token(connector)
        with patch.object(connector, "_get_access_token", new_callable=AsyncMock):
            with patch.object(connector, "_get", new_callable=AsyncMock,
                               return_value={"projectId": GCP_PROJECT}):
                with patch("app.services.connectors.gcp.httpx.AsyncClient") as mock_cls:
                    mock_cls.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
                    mock_cls.return_value.__aexit__  = AsyncMock(return_value=False)
                    await connector.validate_credentials()  # must not raise

    @pytest.mark.asyncio
    async def test_missing_sa_key_field_raises(self):
        bad_creds = _make_sa_creds()
        del bad_creds["private_key"]
        conn = GCPConnector(integration=_make_integration(), credentials=bad_creds)
        with pytest.raises(ValueError, match="missing required fields"):
            await conn.validate_credentials()

    @pytest.mark.asyncio
    async def test_wrong_type_raises(self):
        bad_creds = _make_sa_creds()
        bad_creds["type"] = "authorized_user"
        conn = GCPConnector(integration=_make_integration(), credentials=bad_creds)
        with pytest.raises(ValueError, match="service_account"):
            await conn.validate_credentials()

    @pytest.mark.asyncio
    async def test_project_id_mismatch_raises(self):
        conn = GCPConnector(
            integration=_make_integration("project-A"),
            credentials=_make_sa_creds("project-B"),  # mismatch
        )
        with pytest.raises(ValueError, match="does not match integration target"):
            await conn.validate_credentials()

    @pytest.mark.asyncio
    async def test_token_exchange_failure_raises(self, connector):
        with patch.object(connector, "_get_access_token",
                           new_callable=AsyncMock,
                           side_effect=ValueError("JWT signing failed")):
            with patch("app.services.connectors.gcp.httpx.AsyncClient") as mock_cls:
                mock_cls.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
                mock_cls.return_value.__aexit__  = AsyncMock(return_value=False)
                with pytest.raises(ValueError, match="JWT signing failed"):
                    await connector.validate_credentials()

    @pytest.mark.asyncio
    async def test_project_access_403_raises(self, connector):
        with patch.object(connector, "_get_access_token", new_callable=AsyncMock):
            with patch.object(connector, "_get",
                               new_callable=AsyncMock,
                               side_effect=_http_error(403)):
                with patch("app.services.connectors.gcp.httpx.AsyncClient") as mock_cls:
                    mock_cls.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
                    mock_cls.return_value.__aexit__  = AsyncMock(return_value=False)
                    with pytest.raises(ValueError, match="project access check failed"):
                        await connector.validate_credentials()


class TestGCPFetchFindingsSCC:

    def _make_scc_result(self, name: str = "finding-001", severity: str = "HIGH") -> dict:
        return {
            "finding": {
                "name": f"projects/{GCP_PROJECT}/sources/1/findings/{name}",
                "category": "PUBLIC_IP_ADDRESS",
                "severity": severity,
                "resourceName": f"//compute.googleapis.com/projects/{GCP_PROJECT}/zones/us-central1-a/instances/vm-1",
                "state": "ACTIVE",
                "description": "VM has a public IP.",
            }
        }

    @pytest.mark.asyncio
    async def test_scc_returns_findings(self, connector):
        _inject_valid_token(connector)
        scc_result = self._make_scc_result("finding-001", "HIGH")

        with patch.object(connector, "_get_access_token", new_callable=AsyncMock):
            with patch.object(connector, "_paginate_get",
                               new_callable=AsyncMock,
                               return_value=[scc_result]):
                with patch("app.services.connectors.gcp.httpx.AsyncClient") as mock_cls:
                    mock_cls.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
                    mock_cls.return_value.__aexit__  = AsyncMock(return_value=False)
                    findings = await connector.fetch_findings()

        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.high
        assert "PUBLIC_IP_ADDRESS" in findings[0].title

    @pytest.mark.asyncio
    async def test_fallback_triggered_on_403(self, connector):
        with patch.object(connector, "_get_access_token", new_callable=AsyncMock):
            with patch.object(connector, "_fetch_from_scc",
                               new_callable=AsyncMock,
                               side_effect=_http_error(403)):
                with patch.object(connector, "_run_fallback_scanners",
                                   new_callable=AsyncMock,
                                   return_value=[]) as mock_fb:
                    with patch("app.services.connectors.gcp.httpx.AsyncClient") as mock_cls:
                        mock_cls.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
                        mock_cls.return_value.__aexit__  = AsyncMock(return_value=False)
                        await connector.fetch_findings()
                        mock_fb.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_fallback_triggered_on_404(self, connector):
        with patch.object(connector, "_get_access_token", new_callable=AsyncMock):
            with patch.object(connector, "_fetch_from_scc",
                               new_callable=AsyncMock,
                               side_effect=_http_error(404)):
                with patch.object(connector, "_run_fallback_scanners",
                                   new_callable=AsyncMock,
                                   return_value=[]) as mock_fb:
                    with patch("app.services.connectors.gcp.httpx.AsyncClient") as mock_cls:
                        mock_cls.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
                        mock_cls.return_value.__aexit__  = AsyncMock(return_value=False)
                        await connector.fetch_findings()
                        mock_fb.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_non_access_error_propagates(self, connector):
        with patch.object(connector, "_get_access_token", new_callable=AsyncMock):
            with patch.object(connector, "_fetch_from_scc",
                               new_callable=AsyncMock,
                               side_effect=_http_error(500)):
                with patch("app.services.connectors.gcp.httpx.AsyncClient") as mock_cls:
                    mock_cls.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
                    mock_cls.return_value.__aexit__  = AsyncMock(return_value=False)
                    with pytest.raises(httpx.HTTPStatusError):
                        await connector.fetch_findings()


class TestGCPSCCSeverityMapping:

    @pytest.mark.parametrize("gcp_sev,expected", [
        ("CRITICAL",           FindingSeverity.critical),
        ("HIGH",               FindingSeverity.high),
        ("MEDIUM",             FindingSeverity.medium),
        ("LOW",                FindingSeverity.low),
        ("SEVERITY_UNSPECIFIED", FindingSeverity.critical),  # fail-safe
        ("UNKNOWN_VALUE",      FindingSeverity.critical),    # fail-safe
    ])
    def test_severity_map(self, connector, gcp_sev, expected):
        raw = {
            "finding": {
                "name":         f"projects/{GCP_PROJECT}/sources/1/findings/f1",
                "category":     "TEST_CATEGORY",
                "severity":     gcp_sev,
                "resourceName": "//compute.googleapis.com/projects/p/instances/i",
            }
        }
        finding = connector._map_scc_finding(raw)
        assert finding.severity == expected

    def test_title_contains_category(self, connector):
        raw = {
            "finding": {
                "category": "OPEN_FIREWALL",
                "severity":  "HIGH",
                "resourceName": "//resource",
            }
        }
        finding = connector._map_scc_finding(raw)
        assert "OPEN_FIREWALL" in finding.title


class TestGCPFallbackScanners:

    @pytest.mark.asyncio
    async def test_iam_allUsers_binding_is_critical(self, connector):
        policy = {
            "bindings": [
                {"role": "roles/storage.objectViewer", "members": ["allUsers"]}
            ]
        }
        mock_client = AsyncMock()
        with patch.object(connector, "_post", new_callable=AsyncMock, return_value=policy):
            findings = await connector._scan_iam_bindings(mock_client)
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.critical
        assert "allUsers" in findings[0].title

    @pytest.mark.asyncio
    async def test_iam_owner_to_user_is_high(self, connector):
        policy = {
            "bindings": [
                {"role": "roles/owner", "members": ["user:admin@example.com"]}
            ]
        }
        with patch.object(connector, "_post", new_callable=AsyncMock, return_value=policy):
            findings = await connector._scan_iam_bindings(AsyncMock())
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.high
        assert "roles/owner" in findings[0].title

    @pytest.mark.asyncio
    async def test_iam_owner_to_service_account_no_finding(self, connector):
        policy = {
            "bindings": [
                {
                    "role":    "roles/owner",
                    "members": ["serviceAccount:app@project.iam.gserviceaccount.com"],
                }
            ]
        }
        with patch.object(connector, "_post", new_callable=AsyncMock, return_value=policy):
            findings = await connector._scan_iam_bindings(AsyncMock())
        assert findings == []

    @pytest.mark.asyncio
    async def test_iam_http_error_returns_empty(self, connector):
        with patch.object(connector, "_post",
                           new_callable=AsyncMock,
                           side_effect=_http_error(403)):
            findings = await connector._scan_iam_bindings(AsyncMock())
        assert findings == []

    @pytest.mark.asyncio
    async def test_gcs_public_bucket_is_critical(self, connector):
        buckets_resp = {"items": [{"name": "public-bucket"}]}
        iam_resp     = {
            "bindings": [
                {"role": "roles/storage.objectViewer", "members": ["allUsers"]}
            ]
        }
        with patch.object(connector, "_get",
                           new_callable=AsyncMock,
                           side_effect=[buckets_resp, iam_resp]):
            findings = await connector._scan_gcs_public_access(AsyncMock())
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.critical
        assert "public-bucket" in findings[0].title

    @pytest.mark.asyncio
    async def test_gcs_private_bucket_no_finding(self, connector):
        buckets_resp = {"items": [{"name": "private-bucket"}]}
        iam_resp     = {"bindings": [{"role": "roles/storage.objectViewer",
                                      "members": ["user:alice@example.com"]}]}
        with patch.object(connector, "_get",
                           new_callable=AsyncMock,
                           side_effect=[buckets_resp, iam_resp]):
            findings = await connector._scan_gcs_public_access(AsyncMock())
        assert findings == []

    @pytest.mark.asyncio
    async def test_gcs_http_error_returns_empty(self, connector):
        with patch.object(connector, "_get",
                           new_callable=AsyncMock,
                           side_effect=_http_error(403)):
            findings = await connector._scan_gcs_public_access(AsyncMock())
        assert findings == []

    @pytest.mark.asyncio
    async def test_kms_key_without_rotation_is_medium(self, connector):
        locations_resp = {"locations": [{"locationId": "us-central1"}]}
        keyrings_resp  = {"keyRings": [{"name": f"projects/{GCP_PROJECT}/locations/us-central1/keyRings/ring1"}]}
        keys_resp      = {
            "cryptoKeys": [
                {
                    "name":    f"projects/{GCP_PROJECT}/locations/us-central1/keyRings/ring1/cryptoKeys/key1",
                    "purpose": "ENCRYPT_DECRYPT",
                }
            ]
        }
        with patch.object(connector, "_get",
                           new_callable=AsyncMock,
                           side_effect=[locations_resp, keyrings_resp, keys_resp]):
            findings = await connector._scan_kms_rotation(AsyncMock())
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.medium

    @pytest.mark.asyncio
    async def test_kms_key_with_rotation_no_finding(self, connector):
        locations_resp = {"locations": [{"locationId": "us-central1"}]}
        keyrings_resp  = {"keyRings": [{"name": f"projects/{GCP_PROJECT}/locations/us-central1/keyRings/r"}]}
        keys_resp      = {
            "cryptoKeys": [
                {
                    "name":           f"projects/{GCP_PROJECT}/locations/us-central1/keyRings/r/cryptoKeys/k",
                    "purpose":        "ENCRYPT_DECRYPT",
                    "rotationPeriod": "7776000s",  # 90 days
                }
            ]
        }
        with patch.object(connector, "_get",
                           new_callable=AsyncMock,
                           side_effect=[locations_resp, keyrings_resp, keys_resp]):
            findings = await connector._scan_kms_rotation(AsyncMock())
        assert findings == []

    @pytest.mark.asyncio
    async def test_audit_logs_not_configured_is_high(self, connector):
        project_data = {"projectId": GCP_PROJECT}  # no auditConfigs key
        with patch.object(connector, "_get",
                           new_callable=AsyncMock,
                           return_value=project_data):
            findings = await connector._scan_audit_logs(AsyncMock())
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.high
        assert "Audit Logs" in findings[0].title

    @pytest.mark.asyncio
    async def test_audit_logs_configured_no_finding(self, connector):
        project_data = {
            "projectId":    GCP_PROJECT,
            "auditConfigs": [
                {"service": "allServices", "auditLogConfigs": [{"logType": "DATA_READ"}]}
            ],
        }
        with patch.object(connector, "_get",
                           new_callable=AsyncMock,
                           return_value=project_data):
            findings = await connector._scan_audit_logs(AsyncMock())
        assert findings == []


class TestGCPFallbackOrchestration:

    @pytest.mark.asyncio
    async def test_failed_scanner_does_not_abort_others(self, connector):
        mock_client = AsyncMock()

        async def failing_scanner(_client):
            raise RuntimeError("API down")

        async def successful_scanner(_client):
            return [RawFindingData(
                external_id="test-001",
                resource_id="//resource",
                title="Test Finding",
                severity=FindingSeverity.low,
            )]

        with patch.object(connector, "_scan_iam_bindings",    failing_scanner):
            with patch.object(connector, "_scan_gcs_public_access", successful_scanner):
                with patch.object(connector, "_scan_kms_rotation",   failing_scanner):
                    with patch.object(connector, "_scan_audit_logs",  successful_scanner):
                        results = await connector._run_fallback_scanners(mock_client)

        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_results_capped_at_max_findings(self, connector):
        mock_client = AsyncMock()

        async def big_scanner(_client):
            return [
                RawFindingData(
                    external_id=f"f-{i}",
                    resource_id="r",
                    title=f"F{i}",
                    severity=FindingSeverity.low,
                )
                for i in range(20)
            ]

        with patch.object(connector, "_scan_iam_bindings",     big_scanner):
            with patch.object(connector, "_scan_gcs_public_access", big_scanner):
                with patch.object(connector, "_scan_kms_rotation",   big_scanner):
                    with patch.object(connector, "_scan_audit_logs",  big_scanner):
                        with patch("app.services.connectors.gcp.settings") as mock_s:
                            mock_s.MAX_FINDINGS_PER_SYNC = 5
                            results = await connector._run_fallback_scanners(mock_client)

        assert len(results) <= 5


class TestGCPDedupHash:

    def test_hash_format_and_length(self, connector):
        h = connector.make_dedup_hash("iam-public-roles/owner-allUsers", "//cloudresourcemanager.googleapis.com/projects/p")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_hash_is_deterministic(self, connector):
        h1 = connector.make_dedup_hash("gcs-public-my-bucket-roles/viewer", "//storage.googleapis.com/my-bucket")
        h2 = connector.make_dedup_hash("gcs-public-my-bucket-roles/viewer", "//storage.googleapis.com/my-bucket")
        assert h1 == h2
