from __future__ import annotations

import uuid
from typing import List
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import pytest_asyncio

from app.models.finding import FindingSeverity
from app.models.integration import CloudIntegration, CloudProvider, IntegrationStatus
from app.services.connectors.github import GitHubConnector, _REQUIRED_SCOPES
from app.services.connectors.base import RawFindingData
from app.services.connectors.registry import ConnectorRegistry


GITHUB_ORG   = "acme-corp"
GITHUB_TOKEN = "ghp_test_token_1234567890abcdef"


def _make_integration(org: str = GITHUB_ORG) -> CloudIntegration:
    intg = MagicMock(spec=CloudIntegration)
    intg.id                = uuid.uuid4()
    intg.tenant_id         = uuid.uuid4()
    intg.target_identifier = org
    intg.provider_type     = CloudProvider.github
    intg.status            = IntegrationStatus.active
    return intg


def _make_credentials(org: str = GITHUB_ORG) -> dict:
    return {
        "github_token":        GITHUB_TOKEN,
        "github_org":          org,
        "github_api_base_url": "https://api.github.com",
    }


def _make_connector(org: str = GITHUB_ORG) -> GitHubConnector:
    return GitHubConnector(
        integration=_make_integration(org),
        credentials=_make_credentials(org),
    )


def _mock_response(
    status_code: int = 200,
    json_body: object = None,
    headers: dict = None,
) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_body or {}
    resp.headers = headers or {}
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            f"HTTP {status_code}",
            request=MagicMock(),
            response=resp,
        )
    return resp


@pytest.fixture(autouse=True)
def reset_registry():
    ConnectorRegistry._reset_for_testing()
    import importlib
    import app.services.connectors.github
    importlib.reload(app.services.connectors.github)
    yield
    ConnectorRegistry._reset_for_testing()


@pytest.fixture
def connector():
    return _make_connector()


class TestGitHubValidateCredentials:

    @pytest.mark.asyncio
    async def test_success_all_scopes_present(self, connector):
        all_scopes = ", ".join(_REQUIRED_SCOPES)
        user_resp = _mock_response(
            200,
            {"login": "bot"},
            {"X-OAuth-Scopes": all_scopes},
        )
        org_resp = _mock_response(200, {"login": GITHUB_ORG})

        mock_client = AsyncMock()
        mock_client.get.side_effect = [user_resp, org_resp]
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__  = AsyncMock(return_value=False)

        with patch.object(connector, "_make_client", return_value=mock_client):
            await connector.validate_credentials()  # must not raise

    @pytest.mark.asyncio
    async def test_missing_token_raises(self):
        conn = GitHubConnector(
            integration=_make_integration(),
            credentials={"github_org": GITHUB_ORG},
        )
        with pytest.raises(ValueError, match="missing required key: 'github_token'"):
            await conn.validate_credentials()

    @pytest.mark.asyncio
    async def test_missing_org_raises(self):
        conn = GitHubConnector(
            integration=_make_integration(),
            credentials={"github_token": GITHUB_TOKEN},
        )
        with pytest.raises(ValueError, match="missing required key: 'github_org'"):
            await conn.validate_credentials()

    @pytest.mark.asyncio
    async def test_org_mismatch_raises(self):
        conn = GitHubConnector(
            integration=_make_integration("org-A"),
            credentials=_make_credentials("org-B"),  # mismatch
        )
        with pytest.raises(ValueError, match="does not match integration target"):
            await conn.validate_credentials()

    @pytest.mark.asyncio
    async def test_http_401_raises(self, connector):
        resp_401 = _mock_response(401)
        mock_client = AsyncMock()
        mock_client.get.return_value = resp_401
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__  = AsyncMock(return_value=False)

        with patch.object(connector, "_make_client", return_value=mock_client):
            with pytest.raises(ValueError, match="invalid or expired"):
                await connector.validate_credentials()

    @pytest.mark.asyncio
    async def test_org_not_found_raises(self, connector):
        user_resp = _mock_response(
            200,
            {"login": "bot"},
            {"X-OAuth-Scopes": ", ".join(_REQUIRED_SCOPES)},
        )
        org_resp = _mock_response(404)
        mock_client = AsyncMock()
        mock_client.get.side_effect = [user_resp, org_resp]
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__  = AsyncMock(return_value=False)

        with patch.object(connector, "_make_client", return_value=mock_client):
            with pytest.raises(ValueError, match="not found"):
                await connector.validate_credentials()

    @pytest.mark.asyncio
    async def test_missing_scopes_raises(self, connector):
        user_resp = _mock_response(
            200,
            {"login": "bot"},
            {"X-OAuth-Scopes": "repo"},  # missing read:org, security_events, read:audit_log
        )
        org_resp = _mock_response(200, {"login": GITHUB_ORG})
        mock_client = AsyncMock()
        mock_client.get.side_effect = [user_resp, org_resp]
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__  = AsyncMock(return_value=False)

        with patch.object(connector, "_make_client", return_value=mock_client):
            with pytest.raises(ValueError, match="missing required OAuth scopes"):
                await connector.validate_credentials()


class TestGitHubFetchFindingsGHAS:

    def _make_code_alert(self, number: int = 1, severity: str = "high") -> dict:
        return {
            "number": number,
            "rule": {
                "id": f"rule-{number}",
                "description": f"Code issue {number}",
                "severity": severity,
                "help": "Fix it",
            },
            "repository": {"full_name": f"{GITHUB_ORG}/repo-a"},
            "most_recent_instance": {
                "message": {"text": f"Detail for {number}"}
            },
        }

    def _make_secret_alert(self, number: int = 1) -> dict:
        return {
            "number": number,
            "secret_type": "github_personal_access_token",
            "secret_type_display_name": "GitHub Personal Access Token",
            "repository": {"full_name": f"{GITHUB_ORG}/repo-b"},
        }

    @pytest.mark.asyncio
    async def test_returns_code_and_secret_findings(self, connector):
        code_alert   = self._make_code_alert(1, "high")
        secret_alert = self._make_secret_alert(1)

        with patch.object(connector, "_paginate", new_callable=AsyncMock) as mock_pag:
            mock_pag.side_effect = [[code_alert], [secret_alert]]
            with patch.object(connector, "_make_client") as mock_mk:
                mock_mk.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
                mock_mk.return_value.__aexit__  = AsyncMock(return_value=False)
                findings = await connector.fetch_findings()

        assert len(findings) == 2
        code_f   = next(f for f in findings if "Code issue" in f.title)
        secret_f = next(f for f in findings if "Exposed secret" in f.title)
        assert code_f.severity   == FindingSeverity.high
        assert secret_f.severity == FindingSeverity.critical

    @pytest.mark.asyncio
    async def test_fallback_triggered_on_403(self, connector):
        with patch.object(connector, "_make_client") as mock_mk:
            mock_client = MagicMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__  = AsyncMock(return_value=False)
            mock_mk.return_value = mock_client
            with patch.object(connector, "_fetch_from_ghas",
                               new_callable=AsyncMock) as mock_ghas:
                err_resp = MagicMock()
                err_resp.status_code = 403
                mock_ghas.side_effect = httpx.HTTPStatusError(
                    "403", request=MagicMock(), response=err_resp
                )
                with patch.object(connector, "_run_fallback_scanners",
                                   new_callable=AsyncMock,
                                   return_value=[]) as mock_fb:
                    await connector.fetch_findings()
                    mock_fb.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_fallback_triggered_on_422(self, connector):
        with patch.object(connector, "_make_client") as mock_mk:
            mock_client = MagicMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__  = AsyncMock(return_value=False)
            mock_mk.return_value = mock_client
            with patch.object(connector, "_fetch_from_ghas",
                               new_callable=AsyncMock) as mock_ghas:
                err_resp = MagicMock()
                err_resp.status_code = 422
                mock_ghas.side_effect = httpx.HTTPStatusError(
                    "422", request=MagicMock(), response=err_resp
                )
                with patch.object(connector, "_run_fallback_scanners",
                                   new_callable=AsyncMock,
                                   return_value=[]) as mock_fb:
                    await connector.fetch_findings()
                    mock_fb.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_non_access_error_propagates(self, connector):
        with patch.object(connector, "_make_client") as mock_mk:
            mock_client = MagicMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__  = AsyncMock(return_value=False)
            mock_mk.return_value = mock_client
            with patch.object(connector, "_fetch_from_ghas",
                               new_callable=AsyncMock) as mock_ghas:
                err_resp = MagicMock()
                err_resp.status_code = 500
                mock_ghas.side_effect = httpx.HTTPStatusError(
                    "500", request=MagicMock(), response=err_resp
                )
                with pytest.raises(httpx.HTTPStatusError):
                    await connector.fetch_findings()


class TestGitHubAlertMapping:

    @pytest.mark.parametrize("gh_severity,expected", [
        ("critical", FindingSeverity.critical),
        ("high",     FindingSeverity.high),
        ("medium",   FindingSeverity.medium),
        ("warning",  FindingSeverity.medium),
        ("low",      FindingSeverity.low),
        ("note",     FindingSeverity.low),
        ("error",    FindingSeverity.high),
        ("UNKNOWN",  FindingSeverity.critical),  # fail-safe
    ])
    def test_code_scanning_severity_mapping(self, connector, gh_severity, expected):
        raw = {
            "number": 1,
            "rule": {"description": "T", "severity": gh_severity},
            "repository": {"full_name": f"{GITHUB_ORG}/r"},
            "most_recent_instance": {},
        }
        finding = connector._map_code_scanning_alert(raw)
        assert finding.severity == expected

    def test_code_scanning_external_id_format(self, connector):
        raw = {
            "number": 42,
            "rule": {"description": "T", "severity": "high"},
            "repository": {"full_name": f"{GITHUB_ORG}/myrepo"},
            "most_recent_instance": {},
        }
        finding = connector._map_code_scanning_alert(raw)
        assert "42" in finding.external_id
        assert "myrepo" in finding.external_id

    def test_secret_scanning_always_critical(self, connector):
        raw = {
            "number": 7,
            "secret_type": "aws_access_key",
            "secret_type_display_name": "AWS Access Key",
            "repository": {"full_name": f"{GITHUB_ORG}/secrets-repo"},
        }
        finding = connector._map_secret_scanning_alert(raw)
        assert finding.severity == FindingSeverity.critical
        assert "AWS Access Key" in finding.title

    def test_secret_scanning_title_contains_type(self, connector):
        raw = {
            "number": 3,
            "secret_type_display_name": "GitHub PAT",
            "repository": {"full_name": f"{GITHUB_ORG}/r"},
        }
        finding = connector._map_secret_scanning_alert(raw)
        assert "GitHub PAT" in finding.title


class TestGitHubFallbackScanners:

    def _make_repos(self, *names: str, public: bool = False) -> list[dict]:
        return [
            {
                "full_name":      f"{GITHUB_ORG}/{n}",
                "name":           n,
                "private":        not public,
                "visibility":     "public" if public else "private",
                "default_branch": "main",
            }
            for n in names
        ]

    @pytest.mark.asyncio
    async def test_branch_protection_no_rule_gives_high_finding(self, connector):
        repos = self._make_repos("unprotected-repo")
        mock_client = AsyncMock()
        not_found = _mock_response(404)
        mock_client.get.return_value = not_found
        findings = await connector._scan_branch_protection(mock_client, repos)
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.high
        assert "unprotected-repo" in findings[0].title

    @pytest.mark.asyncio
    async def test_branch_protection_existing_rule_no_finding(self, connector):
        repos = self._make_repos("protected-repo")
        mock_client = AsyncMock()
        ok_resp = _mock_response(200, {"required_pull_request_reviews": {}})
        mock_client.get.return_value = ok_resp
        findings = await connector._scan_branch_protection(mock_client, repos)
        assert findings == []

    @pytest.mark.asyncio
    async def test_visibility_public_repo_gives_medium_finding(self, connector):
        repos = self._make_repos("public-repo", public=True)
        findings = await connector._scan_repo_visibility(AsyncMock(), repos)
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.medium
        assert "public-repo" in findings[0].title

    @pytest.mark.asyncio
    async def test_visibility_private_repo_no_finding(self, connector):
        repos = self._make_repos("private-repo", public=False)
        findings = await connector._scan_repo_visibility(AsyncMock(), repos)
        assert findings == []

    @pytest.mark.asyncio
    async def test_actions_write_perms_gives_medium_finding(self, connector):
        repos = self._make_repos("risky-repo")
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(
            200, {"default_workflow_permissions": "write"}
        )
        findings = await connector._scan_actions_security(mock_client, repos)
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.medium

    @pytest.mark.asyncio
    async def test_actions_read_perms_no_finding(self, connector):
        repos = self._make_repos("safe-repo")
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(
            200, {"default_workflow_permissions": "read"}
        )
        findings = await connector._scan_actions_security(mock_client, repos)
        assert findings == []

    @pytest.mark.asyncio
    async def test_outside_collab_admin_gives_high_finding(self, connector):
        repos = self._make_repos("repo-x")
        mock_client = AsyncMock()
        mock_client.get.side_effect = [
            _mock_response(200, [{"login": "evil-outsider"}], {"Link": ""}),
            _mock_response(200, {"permission": "admin"}),
        ]
        findings = await connector._scan_outside_collaborators(mock_client, repos)
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.high
        assert "evil-outsider" in findings[0].title

    @pytest.mark.asyncio
    async def test_outside_collab_write_no_finding(self, connector):
        repos = self._make_repos("repo-y")
        mock_client = AsyncMock()
        mock_client.get.side_effect = [
            _mock_response(200, [{"login": "safe-outsider"}], {"Link": ""}),
            _mock_response(200, {"permission": "write"}),
        ]
        findings = await connector._scan_outside_collaborators(mock_client, repos)
        assert findings == []

    @pytest.mark.asyncio
    async def test_outside_collab_403_returns_empty(self, connector):
        repos = self._make_repos("repo-z")
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(403)
        findings = await connector._scan_outside_collaborators(mock_client, repos)
        assert findings == []


class TestGitHubUtilities:

    def test_extract_next_link_with_next(self, connector):
        header = (
            '<https://api.github.com/orgs/acme/repos?page=2>; rel="next", '
            '<https://api.github.com/orgs/acme/repos?page=5>; rel="last"'
        )
        result = connector._extract_next_link(header)
        assert result == "https://api.github.com/orgs/acme/repos?page=2"

    def test_extract_next_link_no_next_returns_none(self, connector):
        header = '<https://api.github.com/orgs/acme/repos?page=5>; rel="last"'
        assert connector._extract_next_link(header) is None

    def test_extract_next_link_empty_header(self, connector):
        assert connector._extract_next_link("") is None

    def test_dedup_hash_consistent(self, connector):
        h1 = connector.make_dedup_hash("code-acme-1", "acme-corp/repo")
        h2 = connector.make_dedup_hash("code-acme-1", "acme-corp/repo")
        assert h1 == h2 and len(h1) == 64
