from __future__ import annotations

import inspect
import uuid
from types import SimpleNamespace
from typing import List

import pytest

import app.core.engine.agent as agent_module


class FakeContextBuilder:
    def __init__(self, findings):
        self.findings = findings
        self.calls = []

    async def build_for_tenant(self, tenant_id, limit=None):
        self.calls.append(("tenant", tenant_id, limit))
        return self.findings

    async def build_for_provider(self, tenant_id, provider_type, limit=None):
        self.calls.append(("provider", tenant_id, provider_type, limit))
        return self.findings

    async def build_for_integration(self, tenant_id, integration_id, limit=None):
        self.calls.append(("integration", tenant_id, integration_id, limit))
        return self.findings


@pytest.mark.asyncio
async def test_agent_uses_real_persisted_findings_instead_of_mock_strings(monkeypatch):
    tenant_id = uuid.uuid4()
    builder = FakeContextBuilder(
        [
            (
                "[CRITICAL] | provider=aws | service=s3 | "
                "resource_id=arn:aws:s3:::real-bucket | title=Real persisted finding"
            )
        ]
    )
    captured = {}

    async def fake_ainvoke(initial_state):
        captured["state"] = initial_state
        return {
            "approval_id": "approval-1",
            "analysis_result": "Real finding analyzed.",
        }

    monkeypatch.setattr(agent_module, "FindingsContextBuilder", lambda session: builder)
    monkeypatch.setattr(agent_module, "agent_executor", SimpleNamespace(ainvoke=fake_ainvoke))

    result = await agent_module.run_security_scan_agent(
        str(tenant_id),
        "aws",
        session=object(),
        actor_id=str(uuid.uuid4()),
    )

    assert result["approval_id"] == "approval-1"
    assert result["finding_count"] == 1
    assert builder.calls[0][0] == "provider"
    assert builder.calls[0][2] == "aws"
    assert captured["state"]["findings"] == builder.findings
    assert "company-data" not in str(captured["state"]["findings"])
    assert "IAM user 'dev-1'" not in str(captured["state"]["findings"])


@pytest.mark.asyncio
async def test_agent_returns_safe_empty_state_without_running_graph(monkeypatch):
    tenant_id = uuid.uuid4()
    builder = FakeContextBuilder([])

    async def fail_if_called(_initial_state):
        raise AssertionError("Agent graph should not run without active findings")

    monkeypatch.setattr(agent_module, "FindingsContextBuilder", lambda session: builder)
    monkeypatch.setattr(agent_module, "agent_executor", SimpleNamespace(ainvoke=fail_if_called))

    result = await agent_module.run_security_scan_agent(
        str(tenant_id),
        "aws",
        session=object(),
    )

    assert result["approval_id"] is None
    assert result["finding_count"] == 0
    assert "No active persisted security findings" in result["analysis"]


@pytest.mark.asyncio
async def test_agent_can_target_specific_integration(monkeypatch):
    tenant_id = uuid.uuid4()
    integration_id = uuid.uuid4()
    builder = FakeContextBuilder(["[HIGH] provider=github title=Branch protection missing"])

    async def fake_ainvoke(initial_state):
        return {"approval_id": "approval-2", "analysis_result": "ok"}

    monkeypatch.setattr(agent_module, "FindingsContextBuilder", lambda session: builder)
    monkeypatch.setattr(agent_module, "agent_executor", SimpleNamespace(ainvoke=fake_ainvoke))

    await agent_module.run_security_scan_agent(
        str(tenant_id),
        str(integration_id),
        session=object(),
    )

    assert builder.calls[0][0] == "integration"
    assert builder.calls[0][2] == integration_id


def test_agent_state_contract_preserves_findings_as_list_of_strings():
    assert agent_module.AgentState.__annotations__["findings"] == List[str]


def test_agent_module_does_not_import_cloud_sdks():
    source = inspect.getsource(agent_module)

    assert "boto3" not in source
    assert "botocore" not in source
    assert "google.cloud" not in source
    assert "github.Github" not in source
    assert "app.services.connectors.aws" not in source
    assert "app.services.connectors.github" not in source
    assert "app.services.connectors.gcp" not in source
