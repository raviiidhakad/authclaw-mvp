"""
AuthClaw Sprint 2 — AWS Security Connector
-------------------------------------------
Fetches active security findings from AWS via:

  Primary:  AWS Security Hub  (aggregates GuardDuty, Config, IAM Access Analyzer)
  Fallback: Native AWS APIs   (IAM / S3 / KMS / CloudTrail) when Security Hub
            is not enabled or the credential lacks securityhub:GetFindings.

Credential dict structure (stored in Vault):
  {
    "aws_access_key_id":      str,   # Required
    "aws_secret_access_key":  str,   # Required
    "aws_region":             str,   # Optional — default "us-east-1"
    "aws_session_token":      str,   # Optional — for STS-assumed role sessions
  }

Tenant isolation:
  - All API calls use credentials retrieved from Vault for this specific
    CloudIntegration (scoped to integration.tenant_id).
  - The STS identity check verifies the credential's Account matches
    integration.target_identifier (the registered AWS Account ID).
  - No cross-account calls are made without an explicit role ARN.

Resiliency:
  - boto3 ThrottlingException / RequestLimitExceeded → RateLimitError
    → caught by async_retry in _fetch_from_security_hub.
  - Circuit breaker wraps fetch_findings() at the ConnectorWorker level.
  - Fallback scanners run independently — one failing does NOT stop others.
"""
from __future__ import annotations

import asyncio
import logging
from typing import List

import boto3
from botocore.exceptions import ClientError

from app.core.config import settings
from app.models.finding import FindingSeverity
from app.models.integration import CloudIntegration, CloudProvider
from app.services.connectors.base import BaseConnector, RawFindingData
from app.services.connectors.registry import ConnectorRegistry
from app.services.connectors.resiliency import (
    RateLimitError,
    RetryConfig,
    async_retry,
)

logger = logging.getLogger(__name__)


@ConnectorRegistry.register
class AWSConnector(BaseConnector):
    """
    AWS security connector.

    Validates:
      1. STS  — credential authenticates and belongs to the registered account.
      2. IAM  — SimulatePrincipalPolicy confirms required action permissions.

    Primary scan:  Security Hub paginator (ACTIVE + NEW/NOTIFIED filters).
    Fallback scan: IAM, S3, KMS, CloudTrail native API checks.
    """

    PROVIDER = CloudProvider.aws

    # Required credential keys in the Vault-stored dict
    _REQUIRED_CRED_KEYS: tuple[str, ...] = (
        "aws_access_key_id",
        "aws_secret_access_key",
    )

    # Actions the credential must be able to perform.
    # SimulatePrincipalPolicy validates these during validate_credentials().
    _REQUIRED_PERMISSIONS: list[str] = [
        "securityhub:GetFindings",
        "s3:GetBucketPublicAccessBlock",
        "kms:ListKeys",
        "cloudtrail:DescribeTrails",
    ]

    # boto3 error codes that map to RateLimitError
    _THROTTLING_CODES: frozenset[str] = frozenset({
        "ThrottlingException",
        "RequestLimitExceeded",
        "Throttling",
        "RequestThrottled",
    })

    # boto3 error codes that indicate Security Hub is unavailable (trigger fallback)
    _SECURITY_HUB_UNAVAILABLE_CODES: frozenset[str] = frozenset({
        "AccessDeniedException",
        "InvalidAccessException",
    })

    # ── Client factory ─────────────────────────────────────────────────────────

    def _get_client(self, service: str):
        """
        Create a boto3 client scoped to this integration's Vault credentials.
        Called inside asyncio.to_thread — never on the event loop directly.
        """
        kwargs: dict = {
            "aws_access_key_id":     self._creds["aws_access_key_id"],
            "aws_secret_access_key": self._creds["aws_secret_access_key"],
            "region_name":           self._creds.get("aws_region", "us-east-1"),
        }
        session_token = self._creds.get("aws_session_token")
        if session_token:
            kwargs["aws_session_token"] = session_token
        return boto3.client(service, **kwargs)

    # ── Error classification ───────────────────────────────────────────────────

    def _is_throttling(self, exc: ClientError) -> bool:
        return exc.response["Error"]["Code"] in self._THROTTLING_CODES

    def _is_security_hub_unavailable(self, exc: ClientError) -> bool:
        return exc.response["Error"]["Code"] in self._SECURITY_HUB_UNAVAILABLE_CODES

    def _raise_rate_limit_if_throttled(self, exc: ClientError) -> None:
        """Re-raise as RateLimitError when boto3 returns a throttling code."""
        if self._is_throttling(exc):
            retry_after = int(exc.response.get("RetryAfterSeconds", 60))
            raise RateLimitError(
                f"AWS throttling: {exc.response['Error']['Code']}",
                retry_after=retry_after,
            ) from exc

    # ── validate_credentials ───────────────────────────────────────────────────

    async def validate_credentials(self) -> None:
        """
        Two-step credential validation:
          1. STS GetCallerIdentity — verifies the credential authenticates and
             that the resulting Account ID matches integration.target_identifier.
          2. IAM SimulatePrincipalPolicy — verifies the required permissions.
             If SimulatePrincipalPolicy itself is denied, we log a warning and
             proceed (some environments lock down IAM simulation).

        Raises:
            ValueError: Human-readable message on any validation failure.
        """
        # ── Pre-flight: key presence ──────────────────────────────────────────
        missing = [k for k in self._REQUIRED_CRED_KEYS if not self._creds.get(k)]
        if missing:
            raise ValueError(
                f"AWS credentials are missing required keys: {missing}."
            )

        # ── Step 1: STS identity ──────────────────────────────────────────────
        sts = self._get_client("sts")
        try:
            identity = await asyncio.to_thread(sts.get_caller_identity)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            raise ValueError(
                f"AWS credential validation failed (STS): [{code}] {exc}"
            ) from exc

        caller_arn     = identity.get("Arn", "")
        caller_account = identity.get("Account", "")

        # Account ID must match the registered target
        if caller_account != self.target:
            raise ValueError(
                f"Credential belongs to AWS account '{caller_account}', "
                f"but integration is registered for account '{self.target}'. "
                "Use credentials that belong to the configured account."
            )

        logger.info(
            "AWSConnector: STS identity confirmed for integration %s — ARN: %s",
            self.integration_id, caller_arn,
        )

        # ── Step 2: Permission simulation ─────────────────────────────────────
        iam = self._get_client("iam")

        def _simulate() -> dict:
            return iam.simulate_principal_policy(
                PolicySourceArn=caller_arn,
                ActionNames=self._REQUIRED_PERMISSIONS,
                ResourceArns=["*"],
            )

        try:
            result = await asyncio.to_thread(_simulate)
            denied = [
                r["EvalActionName"]
                for r in result.get("EvaluationResults", [])
                if r.get("EvalDecision") != "allowed"
            ]
            if denied:
                raise ValueError(
                    f"AWS credential lacks required permissions: {denied}. "
                    "Grant these IAM actions before saving the integration."
                )
            logger.info(
                "AWSConnector: all required permissions confirmed for integration %s.",
                self.integration_id,
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "AccessDenied":
                # SimulatePrincipalPolicy is itself restricted in some orgs.
                # Log a warning and allow validation to pass — the real
                # permission failure will surface on the first sync.
                logger.warning(
                    "AWSConnector: iam:SimulatePrincipalPolicy is denied for "
                    "integration %s. Skipping permission pre-check.",
                    self.integration_id,
                )
            else:
                raise ValueError(
                    f"AWS permission simulation failed: [{code}] {exc}"
                ) from exc

    # ── fetch_findings ─────────────────────────────────────────────────────────

    async def fetch_findings(self) -> List[RawFindingData]:
        """
        Primary path: Security Hub.
        Fallback: IAM / S3 / KMS / CloudTrail on AccessDeniedException.
        """
        try:
            findings = await self._fetch_from_security_hub()
            logger.info(
                "AWSConnector: Security Hub returned %d findings for integration %s.",
                len(findings), self.integration_id,
            )
            return findings

        except ClientError as exc:
            if self._is_security_hub_unavailable(exc):
                logger.warning(
                    "AWSConnector: Security Hub unavailable (%s) for integration %s. "
                    "Activating fallback scanners.",
                    exc.response["Error"]["Code"], self.integration_id,
                )
                return await self._run_fallback_scanners()
            # Any other ClientError propagates — circuit breaker records it
            raise

    # ── Primary: Security Hub ──────────────────────────────────────────────────

    async def _fetch_from_security_hub(self) -> List[RawFindingData]:
        """
        Paginate Security Hub findings filtered to ACTIVE + NEW/NOTIFIED.
        Respects MAX_FINDINGS_PER_SYNC — truncates at limit to protect memory.
        """
        hub = self._get_client("securityhub")
        limit = settings.MAX_FINDINGS_PER_SYNC

        filters = {
            "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
            "WorkflowStatus": [
                {"Value": "NEW",      "Comparison": "EQUALS"},
                {"Value": "NOTIFIED", "Comparison": "EQUALS"},
            ],
        }

        def _paginate() -> list[dict]:
            paginator = hub.get_paginator("get_findings")
            collected: list[dict] = []
            for page in paginator.paginate(
                Filters=filters,
                PaginationConfig={"MaxItems": limit, "PageSize": 100},
            ):
                for finding in page.get("Findings", []):
                    collected.append(finding)
                    if len(collected) >= limit:
                        return collected
            return collected

        # async_retry handles ThrottlingException via RateLimitError
        try:
            raw_list = await async_retry(
                asyncio.to_thread,
                _paginate,
                config=RetryConfig(max_retries=3, base_delay=1.0),
                reraise_types=(ValueError, PermissionError),
            )
        except ClientError as exc:
            self._raise_rate_limit_if_throttled(exc)
            raise

        return [self._map_security_hub_finding(raw) for raw in raw_list]

    def _map_security_hub_finding(self, raw: dict) -> RawFindingData:
        """Map a raw Security Hub finding dict → RawFindingData DTO."""
        severity_label = raw.get("Severity", {}).get("Label", "INFORMATIONAL")
        resources      = raw.get("Resources", [])
        resource_id    = (
            resources[0].get("Id", raw.get("Id", "unknown"))
            if resources else raw.get("Id", "unknown")
        )
        remediation_text = (
            raw.get("Remediation", {})
               .get("Recommendation", {})
               .get("Text")
        )
        return RawFindingData(
            external_id=raw.get("Id", ""),
            resource_id=resource_id,
            title=raw.get("Title", "Untitled Security Hub Finding"),
            severity=self._normalize_severity(severity_label),
            description=raw.get("Description"),
            remediation_instructions=remediation_text,
            raw_payload=raw,
        )

    # ── Fallback orchestrator ──────────────────────────────────────────────────

    async def _run_fallback_scanners(self) -> List[RawFindingData]:
        """
        Run all four fallback scanners sequentially.
        A single scanner failure does NOT abort remaining scanners — the error
        is logged and that scanner's results are omitted.
        Stops collecting once MAX_FINDINGS_PER_SYNC is reached.
        """
        limit = settings.MAX_FINDINGS_PER_SYNC
        results: List[RawFindingData] = []

        scanners = (
            self._scan_iam,
            self._scan_s3,
            self._scan_kms,
            self._scan_cloudtrail,
        )
        for scanner in scanners:
            if len(results) >= limit:
                break
            try:
                findings = await scanner()
                results.extend(findings)
            except Exception as exc:
                logger.warning(
                    "AWSConnector: fallback scanner '%s' failed for integration %s: %s",
                    scanner.__name__, self.integration_id, exc,
                )

        return results[:limit]

    # ── Fallback: IAM ──────────────────────────────────────────────────────────

    async def _scan_iam(self) -> List[RawFindingData]:
        """
        Check every IAM user for a missing MFA device.
        Finding: users without any MFA device configured.
        """
        iam = self._get_client("iam")
        findings: List[RawFindingData] = []

        def _list_users() -> list[dict]:
            paginator = iam.get_paginator("list_users")
            users: list[dict] = []
            for page in paginator.paginate():
                users.extend(page.get("Users", []))
            return users

        users = await asyncio.to_thread(_list_users)

        for user in users:
            username = user["UserName"]
            user_arn = user.get("Arn", username)

            def _list_mfa(name=username) -> list[dict]:
                return iam.list_mfa_devices(UserName=name).get("MFADevices", [])

            try:
                mfa_devices = await asyncio.to_thread(_list_mfa)
            except ClientError:
                continue  # Permission denied for this user — skip

            if not mfa_devices:
                findings.append(RawFindingData(
                    external_id=f"iam-no-mfa-{username}",
                    resource_id=user_arn,
                    title=f"IAM user '{username}' has no MFA device",
                    severity=FindingSeverity.high,
                    description=(
                        f"IAM user '{username}' does not have an MFA device configured. "
                        "MFA provides a second layer of protection beyond passwords."
                    ),
                    remediation_instructions=(
                        f"Enable MFA for '{username}' via the IAM console or CLI: "
                        f"aws iam enable-mfa-device --user-name {username} ..."
                    ),
                    raw_payload={"User": user, "MFADevices": []},
                ))

        return findings

    # ── Fallback: S3 ───────────────────────────────────────────────────────────

    async def _scan_s3(self) -> List[RawFindingData]:
        """
        Check every S3 bucket for incomplete public access block configuration.
        Finding: any of the four block settings is False or absent.
        """
        s3 = self._get_client("s3")
        findings: List[RawFindingData] = []

        buckets_resp = await asyncio.to_thread(s3.list_buckets)
        buckets = buckets_resp.get("Buckets", [])

        for bucket in buckets:
            name = bucket["Name"]
            resource_id = f"arn:aws:s3:::{name}"

            def _get_block(n=name) -> dict:
                return s3.get_bucket_public_access_block(Bucket=n)

            try:
                block = await asyncio.to_thread(_get_block)
                cfg = block.get("PublicAccessBlockConfiguration", {})
                all_blocked = all([
                    cfg.get("BlockPublicAcls",      False),
                    cfg.get("IgnorePublicAcls",     False),
                    cfg.get("BlockPublicPolicy",    False),
                    cfg.get("RestrictPublicBuckets", False),
                ])
                if not all_blocked:
                    findings.append(RawFindingData(
                        external_id=f"s3-incomplete-block-{name}",
                        resource_id=resource_id,
                        title=f"S3 bucket '{name}' has incomplete public access block",
                        severity=FindingSeverity.high,
                        description=(
                            f"One or more public access block settings are disabled for '{name}'. "
                            "This may allow unintended public access to bucket content."
                        ),
                        remediation_instructions=(
                            f"Run: aws s3api put-public-access-block --bucket {name} "
                            "--public-access-block-configuration "
                            "BlockPublicAcls=true,IgnorePublicAcls=true,"
                            "BlockPublicPolicy=true,RestrictPublicBuckets=true"
                        ),
                        raw_payload={"Bucket": name, "PublicAccessBlockConfiguration": cfg},
                    ))
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "NoSuchPublicAccessBlockConfiguration":
                    # No block config = maximum exposure
                    findings.append(RawFindingData(
                        external_id=f"s3-no-public-block-{name}",
                        resource_id=resource_id,
                        title=f"S3 bucket '{name}' has no public access block configuration",
                        severity=FindingSeverity.critical,
                        description=(
                            f"Bucket '{name}' has no public access block configuration set. "
                            "Without it, bucket-level ACL grants and policies may expose data publicly."
                        ),
                        remediation_instructions=(
                            f"Enable public access block for '{name}'."
                        ),
                        raw_payload={"Bucket": name, "error": code},
                    ))

        return findings

    # ── Fallback: KMS ──────────────────────────────────────────────────────────

    async def _scan_kms(self) -> List[RawFindingData]:
        """
        Check every customer-managed KMS key for automatic rotation disabled.
        AWS-managed keys are skipped (rotation is handled automatically by AWS).
        """
        kms = self._get_client("kms")
        region = self._creds.get("aws_region", "us-east-1")
        findings: List[RawFindingData] = []

        def _list_keys() -> list[dict]:
            paginator = kms.get_paginator("list_keys")
            keys: list[dict] = []
            for page in paginator.paginate():
                keys.extend(page.get("Keys", []))
            return keys

        keys = await asyncio.to_thread(_list_keys)

        for key in keys:
            key_id = key["KeyId"]

            def _check_rotation(kid=key_id) -> dict:
                return kms.get_key_rotation_status(KeyId=kid)

            try:
                rotation = await asyncio.to_thread(_check_rotation)
                if not rotation.get("KeyRotationEnabled", True):
                    findings.append(RawFindingData(
                        external_id=f"kms-rotation-disabled-{key_id}",
                        resource_id=f"arn:aws:kms:{region}::key/{key_id}",
                        title=f"KMS key '{key_id}' has automatic rotation disabled",
                        severity=FindingSeverity.medium,
                        description=(
                            f"KMS key '{key_id}' does not have automatic annual key rotation enabled. "
                            "Rotating keys limits the blast radius of a compromised key."
                        ),
                        remediation_instructions=(
                            f"Enable rotation: aws kms enable-key-rotation --key-id {key_id}"
                        ),
                        raw_payload=rotation,
                    ))
            except ClientError:
                continue  # Skip keys where permission is denied (e.g. AWS-managed)

        return findings

    # ── Fallback: CloudTrail ───────────────────────────────────────────────────

    async def _scan_cloudtrail(self) -> List[RawFindingData]:
        """
        Check CloudTrail configuration for:
          - No trails configured at all.
          - Trails that are not multi-region.
        """
        ct = self._get_client("cloudtrail")
        findings: List[RawFindingData] = []
        region = self._creds.get("aws_region", "us-east-1")
        no_trail_resource = f"arn:aws:cloudtrail:{region}::trail/none"

        def _describe() -> dict:
            return ct.describe_trails(includeShadowTrails=False)

        trails_resp = await asyncio.to_thread(_describe)
        trails = trails_resp.get("trailList", [])

        if not trails:
            findings.append(RawFindingData(
                external_id="cloudtrail-no-trails",
                resource_id=no_trail_resource,
                title="No CloudTrail trails are configured in this account/region",
                severity=FindingSeverity.critical,
                description=(
                    "No CloudTrail trails exist. Without CloudTrail, AWS API activity "
                    "is not logged, making it impossible to investigate security incidents."
                ),
                remediation_instructions=(
                    "Create a CloudTrail trail with multi-region logging and "
                    "log file validation enabled."
                ),
                raw_payload={"trailList": []},
            ))
            return findings

        for trail in trails:
            trail_name = trail.get("Name", "unknown")
            trail_arn  = trail.get("TrailARN", trail_name)

            if not trail.get("IsMultiRegionTrail", False):
                findings.append(RawFindingData(
                    external_id=f"cloudtrail-single-region-{trail_name}",
                    resource_id=trail_arn,
                    title=f"CloudTrail '{trail_name}' is single-region only",
                    severity=FindingSeverity.medium,
                    description=(
                        f"Trail '{trail_name}' only captures events in one region. "
                        "Multi-region trails provide complete visibility across all regions."
                    ),
                    remediation_instructions=(
                        f"Update trail '{trail_name}' to enable multi-region logging."
                    ),
                    raw_payload=trail,
                ))

        return findings
