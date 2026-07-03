from __future__ import annotations

import asyncio
import uuid
from typing import List
from unittest.mock import MagicMock, patch, call

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from app.models.finding import FindingSeverity
from app.models.integration import CloudIntegration, CloudProvider, IntegrationStatus
from app.services.connectors.aws import AWSConnector
from app.services.connectors.base import RawFindingData
from app.services.connectors.registry import ConnectorRegistry


AWS_ACCOUNT_ID = "123456789012"
AWS_REGION     = "us-east-1"


def _make_integration(account_id: str = AWS_ACCOUNT_ID) -> CloudIntegration:
    intg = MagicMock(spec=CloudIntegration)
    intg.id              = uuid.uuid4()
    intg.tenant_id       = uuid.uuid4()
    intg.target_identifier = account_id
    intg.provider_type   = CloudProvider.aws
    intg.status          = IntegrationStatus.active
    return intg


def _make_credentials(account_id: str = AWS_ACCOUNT_ID) -> dict:
    return {
        "aws_access_key_id":     "AKIAIOSFODNN7EXAMPLE",
        "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "aws_region":            AWS_REGION,
    }


def _client_error(code: str, message: str = "") -> ClientError:
    return ClientError(
        {"Error": {"Code": code, "Message": message}},
        "operation",
    )


@pytest.fixture(autouse=True)
def clear_registry():
    ConnectorRegistry._reset_for_testing()
    import importlib
    import app.services.connectors.aws
    importlib.reload(app.services.connectors.aws)
    yield
    ConnectorRegistry._reset_for_testing()


@pytest.fixture
def integration():
    return _make_integration()


@pytest.fixture
def credentials():
    return _make_credentials()


@pytest.fixture
def connector(integration, credentials):
    return AWSConnector(integration=integration, credentials=credentials)


class TestAWSConnectorMock:
    def _make_mock_clients(self, connector: AWSConnector, service_map: dict):
        def side_effect(service):
            return service_map[service]
        return patch.object(connector, "_get_client", side_effect=side_effect)

    @pytest.mark.asyncio
    async def test_validate_credentials_success(self, connector):
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {
            "Arn": f"arn:aws:iam::{AWS_ACCOUNT_ID}:user/scanner",
            "Account": AWS_ACCOUNT_ID,
        }
        mock_iam = MagicMock()
        mock_iam.simulate_principal_policy.return_value = {
            "EvaluationResults": [
                {"EvalActionName": p, "EvalDecision": "allowed"}
                for p in AWSConnector._REQUIRED_PERMISSIONS
            ]
        }
        with self._make_mock_clients(connector, {"sts": mock_sts, "iam": mock_iam}):
            await connector.validate_credentials()

    @pytest.mark.asyncio
    async def test_validate_credentials_missing_keys_raises(self, integration):
        bad_creds = {"aws_region": "us-east-1"}
        conn = AWSConnector(integration, bad_creds)
        with pytest.raises(ValueError, match="missing required keys"):
            await conn.validate_credentials()

    @pytest.mark.asyncio
    async def test_validate_credentials_wrong_account_raises(self, connector):
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {
            "Arn": "arn:aws:iam::999999999999:user/scanner",
            "Account": "999999999999",  # Different from integration.target_identifier
        }
        mock_iam = MagicMock()
        with self._make_mock_clients(connector, {"sts": mock_sts, "iam": mock_iam}):
            with pytest.raises(ValueError, match="registered for account"):
                await connector.validate_credentials()

    @pytest.mark.asyncio
    async def test_validate_credentials_sts_failure_raises(self, connector):
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.side_effect = _client_error("InvalidClientTokenId")
        mock_iam = MagicMock()
        with self._make_mock_clients(connector, {"sts": mock_sts, "iam": mock_iam}):
            with pytest.raises(ValueError, match="STS"):
                await connector.validate_credentials()

    @pytest.mark.asyncio
    async def test_validate_credentials_denied_permissions_raises(self, connector):
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {
            "Arn": f"arn:aws:iam::{AWS_ACCOUNT_ID}:user/scanner",
            "Account": AWS_ACCOUNT_ID,
        }
        mock_iam = MagicMock()
        mock_iam.simulate_principal_policy.return_value = {
            "EvaluationResults": [
                {"EvalActionName": "securityhub:GetFindings", "EvalDecision": "implicitDeny"},
                {"EvalActionName": "kms:ListKeys",           "EvalDecision": "allowed"},
            ]
        }
        with self._make_mock_clients(connector, {"sts": mock_sts, "iam": mock_iam}):
            with pytest.raises(ValueError, match="lacks required permissions"):
                await connector.validate_credentials()

    @pytest.mark.asyncio
    async def test_validate_credentials_simulate_access_denied_is_warning(self, connector):
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {
            "Arn": f"arn:aws:iam::{AWS_ACCOUNT_ID}:user/scanner",
            "Account": AWS_ACCOUNT_ID,
        }
        mock_iam = MagicMock()
        mock_iam.simulate_principal_policy.side_effect = _client_error("AccessDenied")
        with self._make_mock_clients(connector, {"sts": mock_sts, "iam": mock_iam}):
            await connector.validate_credentials()

    @pytest.mark.asyncio
    async def test_fetch_findings_returns_security_hub_results(self, connector):
        raw_finding = {
            "Id": "arn:aws:securityhub:us-east-1::finding/001",
            "Title": "Public S3 Bucket",
            "Description": "Bucket is public",
            "Severity": {"Label": "HIGH"},
            "Resources": [{"Id": "arn:aws:s3:::my-bucket"}],
            "RecordState": "ACTIVE",
            "WorkflowStatus": "NEW",
            "Remediation": {"Recommendation": {"Text": "Block public access"}},
        }
        mock_hub = MagicMock()
        mock_hub.get_paginator.return_value.paginate.return_value = [
            {"Findings": [raw_finding]}
        ]
        with patch.object(connector, "_get_client", return_value=mock_hub):
            findings = await connector.fetch_findings()

        assert len(findings) == 1
        assert findings[0].title == "Public S3 Bucket"
        assert findings[0].severity == FindingSeverity.high
        assert findings[0].resource_id == "arn:aws:s3:::my-bucket"
        assert findings[0].remediation_instructions == "Block public access"

    @pytest.mark.asyncio
    async def test_fetch_findings_triggers_fallback_on_access_denied(self, connector):
        mock_hub = MagicMock()
        mock_hub.get_paginator.side_effect = _client_error("AccessDeniedException")

        with patch.object(connector, "_get_client", return_value=mock_hub):
            with patch.object(connector, "_run_fallback_scanners", return_value=[]) as mock_fallback:
                findings = await connector.fetch_findings()
                mock_fallback.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_fetch_findings_triggers_fallback_on_invalid_access(self, connector):
        mock_hub = MagicMock()
        mock_hub.get_paginator.side_effect = _client_error("InvalidAccessException")

        with patch.object(connector, "_get_client", return_value=mock_hub):
            with patch.object(connector, "_run_fallback_scanners", return_value=[]) as mock_fallback:
                await connector.fetch_findings()
                mock_fallback.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_fetch_findings_non_access_error_propagates(self, connector):
        mock_hub = MagicMock()
        mock_hub.get_paginator.side_effect = _client_error("InternalFailure")

        with patch.object(connector, "_get_client", return_value=mock_hub):
            with pytest.raises(ClientError):
                await connector.fetch_findings()

    @pytest.mark.asyncio
    async def test_fetch_findings_respects_max_findings_limit(self, connector):
        findings_pool = [
            {
                "Id": f"arn:aws:securityhub:::finding/{i:04d}",
                "Title": f"Finding {i}",
                "Severity": {"Label": "MEDIUM"},
                "Resources": [{"Id": f"arn:aws:s3:::bucket-{i}"}],
            }
            for i in range(20)
        ]
        mock_hub = MagicMock()
        mock_hub.get_paginator.return_value.paginate.return_value = [
            {"Findings": findings_pool}
        ]
        with patch.object(connector, "_get_client", return_value=mock_hub):
            with patch("app.services.connectors.aws.settings") as mock_settings:
                mock_settings.MAX_FINDINGS_PER_SYNC = 5
                findings = await connector.fetch_findings()

        assert len(findings) <= 5

    @pytest.mark.parametrize("label,expected", [
        ("CRITICAL",     FindingSeverity.critical),
        ("HIGH",         FindingSeverity.high),
        ("MEDIUM",       FindingSeverity.medium),
        ("LOW",          FindingSeverity.low),
        ("INFORMATIONAL",FindingSeverity.low),
        ("BANANA",       FindingSeverity.critical),   # unknown → critical (fail-safe)
    ])
    def test_map_security_hub_severity(self, connector, label, expected):
        raw = {
            "Id": "arn:test",
            "Title": "T",
            "Severity": {"Label": label},
            "Resources": [{"Id": "r"}],
        }
        finding = connector._map_security_hub_finding(raw)
        assert finding.severity == expected

    def test_map_security_hub_no_resources(self, connector):
        raw = {
            "Id": "arn:aws:securityhub:::finding/x",
            "Title": "T",
            "Severity": {"Label": "LOW"},
            "Resources": [],
        }
        finding = connector._map_security_hub_finding(raw)
        assert finding.resource_id == "arn:aws:securityhub:::finding/x"

    def test_dedup_hash_consistent_for_same_finding(self, connector):
        h1 = connector.make_dedup_hash("finding-001", "arn:aws:s3:::bucket")
        h2 = connector.make_dedup_hash("finding-001", "arn:aws:s3:::bucket")
        assert h1 == h2
        assert len(h1) == 64

    @pytest.mark.asyncio
    async def test_scan_s3_detects_no_public_block_config(self, connector):
        mock_s3 = MagicMock()
        mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "exposed-bucket"}]}
        mock_s3.get_bucket_public_access_block.side_effect = _client_error(
            "NoSuchPublicAccessBlockConfiguration"
        )
        with patch.object(connector, "_get_client", return_value=mock_s3):
            findings = await connector._scan_s3()
        assert len(findings) == 1
        assert "exposed-bucket" in findings[0].title
        assert findings[0].severity == FindingSeverity.critical

    @pytest.mark.asyncio
    async def test_scan_s3_no_findings_when_fully_blocked(self, connector):
        mock_s3 = MagicMock()
        mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "safe-bucket"}]}
        mock_s3.get_bucket_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
            }
        }
        with patch.object(connector, "_get_client", return_value=mock_s3):
            findings = await connector._scan_s3()
        assert findings == []

    @pytest.mark.asyncio
    async def test_scan_s3_detects_partial_block(self, connector):
        mock_s3 = MagicMock()
        mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "partial-bucket"}]}
        mock_s3.get_bucket_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True, "IgnorePublicAcls": False,
                "BlockPublicPolicy": False, "RestrictPublicBuckets": False,
            }
        }
        with patch.object(connector, "_get_client", return_value=mock_s3):
            findings = await connector._scan_s3()
        assert any("partial-bucket" in f.title for f in findings)
        assert all(f.severity == FindingSeverity.high for f in findings)


class TestAWSConnectorMoto:
    def _make_connector(self) -> AWSConnector:
        intg = _make_integration()
        creds = _make_credentials()
        conn = AWSConnector(integration=intg, credentials=creds)
        def real_get_client(service: str):
            return boto3.client(
                service,
                region_name=AWS_REGION,
                aws_access_key_id="testing",
                aws_secret_access_key="testing",
            )
        conn._get_client = real_get_client
        return conn

    @mock_aws
    def test_scan_iam_detects_user_without_mfa(self):
        iam = boto3.client("iam", region_name=AWS_REGION,
                           aws_access_key_id="testing",
                           aws_secret_access_key="testing")
        iam.create_user(UserName="alice")
        conn = self._make_connector()
        findings = asyncio.run(conn._scan_iam())
        titles = [f.title for f in findings]
        assert any("alice" in t and "no MFA" in t for t in titles)
        assert all(f.severity == FindingSeverity.high for f in findings)

    @mock_aws
    def test_scan_iam_no_users_no_findings(self):
        conn = self._make_connector()
        findings = asyncio.run(conn._scan_iam())
        assert findings == []

    @mock_aws
    def test_scan_iam_dedup_hash_format(self):
        iam = boto3.client("iam", region_name=AWS_REGION,
                           aws_access_key_id="testing",
                           aws_secret_access_key="testing")
        iam.create_user(UserName="bob")
        conn = self._make_connector()
        findings = asyncio.run(conn._scan_iam())
        for f in findings:
            hash_val = conn.make_dedup_hash(f.external_id, f.resource_id)
            assert len(hash_val) == 64

    @mock_aws
    def test_scan_kms_detects_rotation_disabled(self):
        kms = boto3.client("kms", region_name=AWS_REGION,
                           aws_access_key_id="testing",
                           aws_secret_access_key="testing")
        key = kms.create_key(Description="no-rotation")["KeyMetadata"]
        conn = self._make_connector()
        findings = asyncio.run(conn._scan_kms())
        key_ids = [f.external_id for f in findings]
        assert any(key["KeyId"] in k for k in key_ids)
        assert all(f.severity == FindingSeverity.medium for f in findings)

    @mock_aws
    def test_scan_kms_no_findings_when_rotation_enabled(self):
        kms = boto3.client("kms", region_name=AWS_REGION,
                           aws_access_key_id="testing",
                           aws_secret_access_key="testing")
        key = kms.create_key(Description="with-rotation")["KeyMetadata"]
        kms.enable_key_rotation(KeyId=key["KeyId"])
        conn = self._make_connector()
        findings = asyncio.run(conn._scan_kms())
        assert findings == []

    @mock_aws
    def test_scan_cloudtrail_critical_when_no_trails(self):
        conn = self._make_connector()
        findings = asyncio.run(conn._scan_cloudtrail())
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.critical
        assert "No CloudTrail" in findings[0].title

    @mock_aws
    def test_scan_cloudtrail_detects_single_region_trail(self):
        s3 = boto3.client("s3", region_name=AWS_REGION,
                          aws_access_key_id="testing",
                          aws_secret_access_key="testing")
        ct = boto3.client("cloudtrail", region_name=AWS_REGION,
                          aws_access_key_id="testing",
                          aws_secret_access_key="testing")
        s3.create_bucket(Bucket="trail-log-bucket")
        ct.create_trail(
            Name="single-trail",
            S3BucketName="trail-log-bucket",
            IsMultiRegionTrail=False,
        )
        conn = self._make_connector()
        findings = asyncio.run(conn._scan_cloudtrail())
        assert any("single-region" in f.title or "single-trail" in f.title for f in findings)
        assert all(f.severity == FindingSeverity.medium for f in findings)

    @mock_aws
    def test_scan_cloudtrail_no_findings_for_multi_region_trail(self):
        s3 = boto3.client("s3", region_name=AWS_REGION,
                          aws_access_key_id="testing",
                          aws_secret_access_key="testing")
        ct = boto3.client("cloudtrail", region_name=AWS_REGION,
                          aws_access_key_id="testing",
                          aws_secret_access_key="testing")
        s3.create_bucket(Bucket="ok-trail-bucket")
        ct.create_trail(
            Name="multi-trail",
            S3BucketName="ok-trail-bucket",
            IsMultiRegionTrail=True,
        )
        conn = self._make_connector()
        findings = asyncio.run(conn._scan_cloudtrail())
        assert findings == []

    @mock_aws
    def test_run_fallback_scanners_collects_all_results(self):
        iam = boto3.client("iam", region_name=AWS_REGION,
                           aws_access_key_id="testing",
                           aws_secret_access_key="testing")
        iam.create_user(UserName="frank")
        conn = self._make_connector()
        results = asyncio.run(conn._run_fallback_scanners())
        assert len(results) >= 1
        assert all(isinstance(f, RawFindingData) for f in results)

    @mock_aws
    def test_run_fallback_scanners_respects_limit(self):
        iam = boto3.client("iam", region_name=AWS_REGION,
                           aws_access_key_id="testing",
                           aws_secret_access_key="testing")
        for i in range(10):
            iam.create_user(UserName=f"user-{i:02d}")
        conn = self._make_connector()
        with patch("app.services.connectors.aws.settings") as mock_settings:
            mock_settings.MAX_FINDINGS_PER_SYNC = 3
            results = asyncio.run(conn._run_fallback_scanners())
        assert len(results) <= 3
