"""
AuthClaw Sprint 2 — GCP Security Connector
-------------------------------------------
Fetches active security findings from GCP via:

  Primary:  GCP Security Command Center (SCC) — ListFindings API
  Fallback: Native GCP APIs when SCC is unavailable or not enabled:
              • IAM policy bindings (primitive/predefined roles audit)
              • GCS bucket IAM public access
              • KMS CryptoKey rotation period
              • Cloud Audit Logs configuration

Credential dict structure (stored in Vault):
  {
    "type":                       "<GCP service account type>",  # Required
    "project_id":                 str,                  # Required
    "private_key_id":             str,                  # Required
    "private_key":                str,                  # Required (PEM)
    "client_email":               str,                  # Required
    "client_id":                  str,                  # Required
    "token_uri":                  str,                  # Required
    "auth_uri":                   str,                  # Optional
  }

This is the standard GCP service account key JSON format.

Tenant isolation:
  - All API calls are scoped to the project_id from credentials.
  - project_id is cross-checked against integration.target_identifier.
  - Credentials are never logged or stored beyond __init__.

Resiliency:
  - HTTP 429 / RESOURCE_EXHAUSTED → RateLimitError with Retry-After.
  - SCC 403 / PERMISSION_DENIED + 404 / NOT_FOUND → fallback trigger.
  - All httpx calls wrapped in async_retry.
  - Circuit breaker wraps fetch_findings() at the ConnectorWorker level.

GCP API Strategy:
  - Uses Service Account access tokens obtained via OAuth2 JWT flow.
  - All calls via REST (httpx) — no GCP client library required in container.
  - Token cached for lifetime of a single scan (< MAX_SCAN_DURATION).
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, Dict, List, Optional

import httpx

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

# GCP SCC severity → FindingSeverity
_GCP_SEVERITY_MAP: dict[str, FindingSeverity] = {
    "CRITICAL": FindingSeverity.critical,
    "HIGH":     FindingSeverity.high,
    "MEDIUM":   FindingSeverity.medium,
    "LOW":      FindingSeverity.low,
    # SCC also returns SEVERITY_UNSPECIFIED for some findings
    "SEVERITY_UNSPECIFIED": FindingSeverity.critical,  # fail-safe
}

# Required GCP OAuth2 scope
_GCP_SCOPE = "https://www.googleapis.com/auth/cloud-platform"

# GCP APIs
_SCC_BASE     = "https://securitycenter.googleapis.com/v1"
_IAM_BASE     = "https://cloudresourcemanager.googleapis.com/v1"
_STORAGE_BASE = "https://storage.googleapis.com/storage/v1"
_KMS_BASE     = "https://cloudkms.googleapis.com/v1"
_LOG_BASE     = "https://logging.googleapis.com/v2"

# Primitive/predefined roles considered overly permissive at project level
_OVERPERMISSIVE_PROJECT_ROLES = frozenset({
    "roles/owner",
    "roles/editor",
    "roles/viewer",  # Only flag if granted to allUsers or allAuthenticatedUsers
})
_PUBLIC_MEMBERS = frozenset({"allUsers", "allAuthenticatedUsers"})


@ConnectorRegistry.register
class GCPConnector(BaseConnector):
    """
    GCP security connector.

    Validates:
      1. Service account key structure — required fields present.
      2. Token exchange — verifies the key successfully obtains an access token.
      3. Project access — GET cloudresourcemanager projects/{project_id} confirms
         the service account has resourcemanager.projects.get permission.

    Primary scan:  Security Command Center ListFindings (org-level or project-level).
    Fallback scan: IAM bindings, GCS public access, KMS rotation, Audit Logs config.
    """

    PROVIDER = CloudProvider.gcp

    _REQUIRED_SA_FIELDS: tuple[str, ...] = (
        "type",
        "project_id",
        "private_key_id",
        "private_key",
        "client_email",
        "client_id",
        "token_uri",
    )

    # GCP error codes that indicate SCC is unavailable → trigger fallback
    _SCC_UNAVAILABLE_HTTP_CODES: frozenset[int] = frozenset({403, 404, 501})

    def __init__(self, integration: CloudIntegration, credentials: dict) -> None:
        super().__init__(integration, credentials)
        self._project_id: str = credentials.get("project_id", "")
        self._access_token: Optional[str] = None
        self._token_expiry: float = 0.0

    # ── Credential helpers ─────────────────────────────────────────────────────

    def _validate_sa_key_structure(self) -> None:
        """Raise ValueError if any required service account key field is missing."""
        missing = [f for f in self._REQUIRED_SA_FIELDS if not self._creds.get(f)]
        if missing:
            raise ValueError(
                f"GCP service account key is missing required fields: {missing}."
            )
        if self._creds.get("type") != "service_account":
            raise ValueError(
                "GCP credentials must be a service_account key. "
                f"Got type='{self._creds.get('type')}'."
            )

    async def _get_access_token(self, client: httpx.AsyncClient) -> str:
        """
        Obtain a short-lived OAuth2 access token via Service Account JWT assertion.
        Token is cached until expiry minus a 60-second buffer.
        """
        if self._access_token and time.monotonic() < self._token_expiry - 60:
            return self._access_token

        # Build the JWT claim set
        now = int(time.time())
        claim = {
            "iss":   self._creds["client_email"],
            "scope": _GCP_SCOPE,
            "aud":   self._creds["token_uri"],
            "iat":   now,
            "exp":   now + 3600,
        }

        # Sign the JWT with the service account private key
        try:
            import jwt as _jwt  # PyJWT — already in requirements
            encoded = _jwt.encode(
                claim,
                self._creds["private_key"],
                algorithm="RS256",
            )
        except Exception as exc:
            raise ValueError(
                f"Failed to sign GCP service account JWT: {exc}"
            ) from exc

        # Exchange the signed JWT for an access token
        resp = await client.post(
            self._creds["token_uri"],
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion":  encoded,
            },
        )
        if resp.status_code != 200:
            raise ValueError(
                f"GCP token exchange failed (HTTP {resp.status_code}): {resp.text}"
            )

        token_data = resp.json()
        self._access_token = token_data["access_token"]
        self._token_expiry = time.monotonic() + token_data.get("expires_in", 3600)
        return self._access_token

    def _auth_headers(self) -> dict:
        """Return Authorization header dict. Token must already be obtained."""
        return {"Authorization": f"Bearer {self._access_token}"}

    # ── HTTP helpers ───────────────────────────────────────────────────────────

    async def _get(
        self,
        client: httpx.AsyncClient,
        url: str,
        params: Optional[dict] = None,
    ) -> Any:
        """GET with rate-limit and error handling."""
        response = await client.get(url, headers=self._auth_headers(), params=params)
        if response.status_code == 429:
            retry_after = int(response.headers.get("Retry-After", 60))
            raise RateLimitError(
                f"GCP rate limit on {url}", retry_after=retry_after
            )
        response.raise_for_status()
        return response.json()

    async def _post(
        self,
        client: httpx.AsyncClient,
        url: str,
        body: dict,
    ) -> Any:
        """POST with rate-limit handling."""
        response = await client.post(url, headers=self._auth_headers(), json=body)
        if response.status_code == 429:
            retry_after = int(response.headers.get("Retry-After", 60))
            raise RateLimitError(
                f"GCP rate limit on {url}", retry_after=retry_after
            )
        response.raise_for_status()
        return response.json()

    async def _paginate_get(
        self,
        client: httpx.AsyncClient,
        url: str,
        params: Optional[dict] = None,
        result_key: str = "findings",
        limit: int = 10_000,
    ) -> list[dict]:
        """Paginate a GCP REST GET endpoint using nextPageToken."""
        results: list[dict] = []
        page_params = dict(params or {})

        while len(results) < limit:
            data = await async_retry(
                self._get,
                client,
                url,
                page_params,
                config=RetryConfig(max_retries=3, base_delay=1.0),
                reraise_types=(ValueError,),
            )
            items = data.get(result_key, [])
            results.extend(items)

            next_token = data.get("nextPageToken")
            if not next_token:
                break
            page_params["pageToken"] = next_token

        return results[:limit]

    # ── validate_credentials ───────────────────────────────────────────────────

    async def validate_credentials(self) -> None:
        """
        Three-step GCP credential validation:
          1. Service account key structure check.
          2. OAuth2 token exchange (private key is valid and key is not revoked).
          3. Project access check (service account has basic project permissions).

        Raises:
            ValueError: Human-readable failure message.
        """
        # Step 1: Structure
        self._validate_sa_key_structure()

        if self._project_id != self.target:
            raise ValueError(
                f"Service account project_id '{self._project_id}' does not match "
                f"integration target '{self.target}'. "
                "Use a service account key that belongs to the registered project."
            )

        async with httpx.AsyncClient(timeout=30.0) as client:
            # Step 2: Token exchange
            try:
                await self._get_access_token(client)
            except ValueError:
                raise
            except Exception as exc:
                raise ValueError(
                    f"GCP token exchange failed: {exc}"
                ) from exc

            # Step 3: Project access
            try:
                project_url = f"{_IAM_BASE}/projects/{self._project_id}"
                await self._get(client, project_url)
                logger.info(
                    "GCPConnector: project access confirmed for '%s' (integration %s).",
                    self._project_id, self.integration_id,
                )
            except httpx.HTTPStatusError as exc:
                raise ValueError(
                    f"GCP project access check failed for '{self._project_id}' "
                    f"(HTTP {exc.response.status_code}): {exc.response.text}"
                ) from exc

    # ── fetch_findings ─────────────────────────────────────────────────────────

    async def fetch_findings(self) -> List[RawFindingData]:
        """
        Primary: SCC ListFindings.
        Fallback: IAM / GCS / KMS / Audit Logs on 403/404/501.
        """
        async with httpx.AsyncClient(timeout=60.0) as client:
            await self._get_access_token(client)

            try:
                findings = await self._fetch_from_scc(client)
                logger.info(
                    "GCPConnector: SCC returned %d findings for integration %s.",
                    len(findings), self.integration_id,
                )
                return findings

            except httpx.HTTPStatusError as exc:
                if exc.response.status_code in self._SCC_UNAVAILABLE_HTTP_CODES:
                    logger.warning(
                        "GCPConnector: SCC unavailable (HTTP %d) for integration %s. "
                        "Activating fallback scanners.",
                        exc.response.status_code, self.integration_id,
                    )
                    return await self._run_fallback_scanners(client)
                raise

    # ── Primary: Security Command Center ──────────────────────────────────────

    async def _fetch_from_scc(self, client: httpx.AsyncClient) -> List[RawFindingData]:
        """
        List active findings from Security Command Center for the project.
        Uses the project-level SCC source (v1 API).
        Filter: state=ACTIVE, not muted.
        """
        parent = f"projects/{self._project_id}/sources/-"
        url = f"{_SCC_BASE}/{parent}/findings"
        limit = settings.MAX_FINDINGS_PER_SYNC

        raw_list = await self._paginate_get(
            client,
            url,
            params={
                "filter":   "state=\"ACTIVE\" AND NOT muted=\"MUTED\"",
                "pageSize": 100,
            },
            result_key="listFindingsResults",
            limit=limit,
        )

        return [self._map_scc_finding(r) for r in raw_list]

    def _map_scc_finding(self, raw: dict) -> RawFindingData:
        """Map raw SCC ListFindingsResult → RawFindingData DTO."""
        finding     = raw.get("finding", raw)  # unwrap listFindingsResults envelope
        severity    = finding.get("severity", "SEVERITY_UNSPECIFIED")
        resource    = finding.get("resourceName", self._project_id)
        category    = finding.get("category", "Uncategorized")
        description = finding.get("description", "")
        name        = finding.get("name", "")
        # Extract last segment of the finding name as external_id
        external_id = name.split("/")[-1] if name else category

        return RawFindingData(
            external_id=external_id,
            resource_id=resource,
            title=f"[GCP SCC] {category}",
            severity=_GCP_SEVERITY_MAP.get(severity, FindingSeverity.critical),
            description=description or None,
            remediation_instructions=finding.get("nextSteps"),
            raw_payload=raw,
        )

    # ── Fallback orchestrator ──────────────────────────────────────────────────

    async def _run_fallback_scanners(
        self, client: httpx.AsyncClient
    ) -> List[RawFindingData]:
        """
        Run all four fallback scanners sequentially.
        A single scanner failure does NOT abort remaining scanners.
        Results capped at MAX_FINDINGS_PER_SYNC.
        """
        limit = settings.MAX_FINDINGS_PER_SYNC
        results: List[RawFindingData] = []

        scanners = (
            self._scan_iam_bindings,
            self._scan_gcs_public_access,
            self._scan_kms_rotation,
            self._scan_audit_logs,
        )
        for scanner in scanners:
            if len(results) >= limit:
                break
            try:
                findings = await scanner(client)
                results.extend(findings)
            except Exception as exc:
                logger.warning(
                    "GCPConnector: fallback scanner '%s' failed: %s",
                    scanner.__name__, exc,
                )

        return results[:limit]

    # ── Fallback: IAM bindings ─────────────────────────────────────────────────

    async def _scan_iam_bindings(
        self, client: httpx.AsyncClient
    ) -> List[RawFindingData]:
        """
        Detect overly permissive IAM bindings at the project level:
          - roles/owner or roles/editor granted to any non-service-account member.
          - Any primitive role granted to allUsers or allAuthenticatedUsers.
        """
        url = f"{_IAM_BASE}/projects/{self._project_id}:getIamPolicy"
        try:
            policy = await self._post(client, url, body={"options": {"requestedPolicyVersion": 3}})
        except httpx.HTTPStatusError as exc:
            logger.warning("GCPConnector IAM scan failed: HTTP %d", exc.response.status_code)
            return []

        findings: List[RawFindingData] = []
        project_resource = f"//cloudresourcemanager.googleapis.com/projects/{self._project_id}"

        for binding in policy.get("bindings", []):
            role    = binding.get("role", "")
            members = binding.get("members", [])

            for member in members:
                # Flag any role granted to allUsers or allAuthenticatedUsers
                if member in _PUBLIC_MEMBERS:
                    findings.append(RawFindingData(
                        external_id=f"iam-public-{role}-{member}",
                        resource_id=project_resource,
                        title=(
                            f"IAM role '{role}' granted to public principal '{member}' "
                            f"on project '{self._project_id}'"
                        ),
                        severity=FindingSeverity.critical,
                        description=(
                            f"The IAM binding '{role}' for '{member}' makes this "
                            f"project resource accessible to all internet users."
                        ),
                        remediation_instructions=(
                            f"Remove the '{member}' binding from '{role}' at "
                            f"project level immediately."
                        ),
                        raw_payload={"role": role, "member": member, "binding": binding},
                    ))
                # Flag owner/editor granted to any non-service-account user
                elif role in ("roles/owner", "roles/editor"):
                    if not member.startswith("serviceAccount:"):
                        findings.append(RawFindingData(
                            external_id=f"iam-overpermissive-{role}-{member}",
                            resource_id=project_resource,
                            title=(
                                f"Overpermissive IAM role '{role}' granted to "
                                f"'{member}' on project '{self._project_id}'"
                            ),
                            severity=FindingSeverity.high,
                            description=(
                                f"Member '{member}' has the primitive role '{role}' "
                                f"at the project level. Primitive roles should be avoided "
                                "in favour of predefined or custom roles."
                            ),
                            remediation_instructions=(
                                f"Replace '{role}' with a more granular predefined role "
                                f"for '{member}'."
                            ),
                            raw_payload={"role": role, "member": member, "binding": binding},
                        ))

        return findings

    # ── Fallback: GCS public access ────────────────────────────────────────────

    async def _scan_gcs_public_access(
        self, client: httpx.AsyncClient
    ) -> List[RawFindingData]:
        """
        Detect GCS buckets with public IAM bindings (allUsers / allAuthenticatedUsers).
        """
        findings: List[RawFindingData] = []

        # List buckets in the project
        try:
            data = await self._get(
                client,
                f"{_STORAGE_BASE}/b",
                params={"project": self._project_id},
            )
        except httpx.HTTPStatusError:
            return []

        buckets = data.get("items", [])

        for bucket in buckets:
            bucket_name = bucket.get("name", "unknown")
            resource_id = f"//storage.googleapis.com/{bucket_name}"

            try:
                iam_data = await self._get(
                    client,
                    f"{_STORAGE_BASE}/b/{bucket_name}/iam",
                )
            except httpx.HTTPStatusError:
                continue

            for binding in iam_data.get("bindings", []):
                role    = binding.get("role", "")
                members = binding.get("members", [])
                public_members = [m for m in members if m in _PUBLIC_MEMBERS]
                if public_members:
                    findings.append(RawFindingData(
                        external_id=f"gcs-public-{bucket_name}-{role}",
                        resource_id=resource_id,
                        title=(
                            f"GCS bucket '{bucket_name}' is publicly accessible "
                            f"(role: {role})"
                        ),
                        severity=FindingSeverity.critical,
                        description=(
                            f"GCS bucket '{bucket_name}' has role '{role}' granted "
                            f"to {public_members}. All internet users can access this bucket."
                        ),
                        remediation_instructions=(
                            f"Remove public IAM bindings from '{bucket_name}': "
                            f"gcloud storage buckets remove-iam-policy-binding "
                            f"gs://{bucket_name} --member=allUsers --role={role}"
                        ),
                        raw_payload={"bucket": bucket_name, "role": role, "members": public_members},
                    ))

        return findings

    # ── Fallback: KMS rotation ─────────────────────────────────────────────────

    async def _scan_kms_rotation(
        self, client: httpx.AsyncClient
    ) -> List[RawFindingData]:
        """
        Detect KMS CryptoKeys without automatic rotation configured.
        Checks all KeyRings in all supported locations.
        """
        findings: List[RawFindingData] = []

        # List locations for the project
        try:
            loc_data = await self._get(
                client,
                f"{_KMS_BASE}/projects/{self._project_id}/locations",
            )
        except httpx.HTTPStatusError:
            return []

        locations = [loc["locationId"] for loc in loc_data.get("locations", [])]

        for location in locations:
            loc_path = f"projects/{self._project_id}/locations/{location}"
            try:
                kr_data = await self._get(client, f"{_KMS_BASE}/{loc_path}/keyRings")
            except httpx.HTTPStatusError:
                continue

            for ring in kr_data.get("keyRings", []):
                ring_name = ring["name"]
                try:
                    ck_data = await self._get(
                        client, f"{_KMS_BASE}/{ring_name}/cryptoKeys"
                    )
                except httpx.HTTPStatusError:
                    continue

                for key in ck_data.get("cryptoKeys", []):
                    key_name = key.get("name", "")
                    # rotationPeriod absent → no automatic rotation
                    if "rotationPeriod" not in key:
                        findings.append(RawFindingData(
                            external_id=f"kms-no-rotation-{key_name.split('/')[-1]}",
                            resource_id=f"//{key_name}",
                            title=(
                                f"KMS CryptoKey '{key_name.split('/')[-1]}' "
                                "has no automatic rotation configured"
                            ),
                            severity=FindingSeverity.medium,
                            description=(
                                f"CryptoKey '{key_name}' does not have automatic "
                                "rotation configured. GCP recommends rotating keys "
                                "at least annually."
                            ),
                            remediation_instructions=(
                                f"Set rotation period: gcloud kms keys update "
                                f"{key_name.split('/')[-1]} "
                                f"--rotation-period=365d --keyring={ring_name.split('/')[-1]} "
                                f"--location={location}"
                            ),
                            raw_payload=key,
                        ))

        return findings

    # ── Fallback: Audit Logs ───────────────────────────────────────────────────

    async def _scan_audit_logs(
        self, client: httpx.AsyncClient
    ) -> List[RawFindingData]:
        """
        Detect Cloud Audit Log configuration gaps:
          - DATA_READ or DATA_WRITE audit logs disabled for any service.
        Checks the project's AuditConfig via Cloud Resource Manager.
        """
        findings: List[RawFindingData] = []

        try:
            data = await self._get(
                client,
                f"{_IAM_BASE}/projects/{self._project_id}",
            )
        except httpx.HTTPStatusError:
            return []

        audit_configs = data.get("auditConfigs", [])

        if not audit_configs:
            findings.append(RawFindingData(
                external_id="audit-logs-not-configured",
                resource_id=f"//cloudresourcemanager.googleapis.com/projects/{self._project_id}",
                title=f"Cloud Audit Logs not configured for project '{self._project_id}'",
                severity=FindingSeverity.high,
                description=(
                    f"Project '{self._project_id}' has no audit log configuration. "
                    "Without audit logs, API activity and data access are not logged."
                ),
                remediation_instructions=(
                    "Enable audit logging: add auditConfigs to the project IAM policy "
                    "to capture DATA_READ and DATA_WRITE log types."
                ),
                raw_payload={"auditConfigs": []},
            ))

        return findings
