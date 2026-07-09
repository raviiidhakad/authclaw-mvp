"""
AuthClaw — Azure Cloud Connector
---------------------------------
Discovers security findings from Microsoft Azure via the Azure Resource Manager
(ARM) REST API.  No Azure SDK dependency — all calls use httpx (already required
by the project).

Primary path:   Microsoft Defender for Cloud security assessments
                GET /subscriptions/{sub}/providers/Microsoft.Security/assessments
                Returns unhealthy resource assessments (policy non-compliance).

Fallback path:  Microsoft Defender for Cloud security alerts
                GET /subscriptions/{sub}/providers/Microsoft.Security/alerts
                Triggered when assessments endpoint returns 403 / 404.

Authentication:
    OAuth 2.0 client credentials flow against Azure AD using scope
    https://management.azure.com/.default (ARM scope, not OpenAI scope).
    The existing azure_auth.py uses the cognitiveservices scope — this
    connector manages its own token fetch to avoid coupling.

Credential dict structure (stored in Vault):
    {
        "azure_client_id":     str,  # Service principal application (client) ID
        "azure_client_secret": str,  # Service principal secret — NEVER logged
        "azure_tenant_id":     str,  # Azure Active Directory tenant ID
    }

    integration.target_identifier = Azure subscription ID

Tenant isolation:
    All ARM calls are scoped to the subscription ID stored at integration-
    creation time in integration.target_identifier. Connector code never
    accepts the subscription ID from user input at scan time.

Required service principal permissions (minimum):
    Microsoft.Security/assessments/read
    Microsoft.Security/alerts/read
    (Reader role on the subscription satisfies both.)

Severity mapping:
    Azure Defender assessment/alert severity → FindingSeverity
        High         → high
        Medium       → medium
        Low          → low
        Informational → low

    Note: Azure assessments use High/Medium/Low; there is no Critical tier.
    Unknown values fall back to high (fail-safe).
"""
from __future__ import annotations

import logging
from typing import Any, List, Optional

import httpx

from app.core.config import settings
from app.models.finding import FindingSeverity
from app.models.integration import CloudIntegration, CloudProvider
from app.services.connectors.base import BaseConnector, RawFindingData
from app.services.connectors.registry import ConnectorRegistry

logger = logging.getLogger(__name__)

# Azure endpoints
_ARM_BASE       = "https://management.azure.com"
_TOKEN_URL_TMPL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
_ARM_SCOPE      = "https://management.azure.com/.default"

# API versions
_SUB_API_VERSION          = "2022-12-01"
_ASSESSMENTS_API_VERSION  = "2021-06-01"
_ALERTS_API_VERSION       = "2022-01-01"

# Azure severity → normalized FindingSeverity
_AZURE_SEVERITY_MAP: dict[str, FindingSeverity] = {
    "High":          FindingSeverity.high,
    "Medium":        FindingSeverity.medium,
    "Low":           FindingSeverity.low,
    "Informational": FindingSeverity.low,
    # lower-case variants (alerts API uses mixed case)
    "high":          FindingSeverity.high,
    "medium":        FindingSeverity.medium,
    "low":           FindingSeverity.low,
    "informational": FindingSeverity.low,
}


@ConnectorRegistry.register
class AzureConnector(BaseConnector):
    """
    Azure Cloud Connector.

    Validates:
      1. Required credential keys are present.
      2. Client credentials token is obtainable from Azure AD.
      3. Subscription is accessible via ARM subscriptions API.

    Primary scan:   Defender for Cloud security assessments (unhealthy only).
    Fallback scan:  Defender for Cloud security alerts (if assessments 403/404).
    """

    PROVIDER = CloudProvider.azure

    # ── Azure AD token acquisition ────────────────────────────────────────────

    async def _get_arm_token(self) -> str:
        """
        Fetch an ARM-scoped OAuth2 token via client credentials grant.

        Uses scope https://management.azure.com/.default — distinct from the
        cognitiveservices scope used by the Azure OpenAI provider adapter.

        Raises:
            ValueError: On auth failure with a sanitized (non-secret) message.
        """
        tenant_id = self._creds["azure_tenant_id"]
        token_url = _TOKEN_URL_TMPL.format(tenant_id=tenant_id)
        data = {
            "grant_type":    "client_credentials",
            "client_id":     self._creds["azure_client_id"],
            "client_secret": self._creds["azure_client_secret"],
            "scope":         _ARM_SCOPE,
        }
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(token_url, data=data)
                if resp.status_code == 401:
                    raise ValueError(
                        "Azure AD authentication failed (HTTP 401): "
                        "check client_id, client_secret, and tenant_id."
                    )
                if resp.status_code == 400:
                    # AADSTS error codes are safe to surface (no secrets)
                    body = resp.json()
                    error = body.get("error", "invalid_request")
                    raise ValueError(
                        f"Azure AD token request rejected ({error}). "
                        "Verify tenant_id, client_id, and that the service "
                        "principal has the correct permissions."
                    )
                resp.raise_for_status()
                return str(resp.json()["access_token"])
        except ValueError:
            raise
        except httpx.HTTPStatusError as exc:
            raise ValueError(
                f"Azure AD token request failed: HTTP {exc.response.status_code}"
            ) from exc
        except httpx.RequestError as exc:
            raise ValueError(
                "Azure AD token endpoint unreachable. "
                "Check network connectivity and tenant_id format."
            ) from exc

    # ── ARM HTTP helper ───────────────────────────────────────────────────────

    async def _arm_paginate(
        self,
        client: httpx.AsyncClient,
        path: str,
        params: dict,
        limit: int,
    ) -> list[dict]:
        """Auto-paginate ARM nextLink responses until exhausted or limit reached."""
        results: list[dict] = []
        next_url: Optional[str] = path

        while next_url and len(results) < limit:
            resp = await client.get(
                next_url if next_url.startswith("http") else next_url,
                params=params if not next_url.startswith("http") else None,
            )
            if resp.status_code == 401:
                raise ValueError("ARM token rejected during pagination (HTTP 401).")
            resp.raise_for_status()
            body = resp.json()
            results.extend(body.get("value", []))
            next_url = body.get("nextLink")
            params = {}  # nextLink already contains query params

        return results[:limit]

    # ── validate_credentials ──────────────────────────────────────────────────

    async def validate_credentials(self) -> None:
        """
        Three-step validation:
          1. Required credential keys are present.
          2. ARM token is obtainable from Azure AD.
          3. Subscription endpoint is reachable and accessible.

        Raises:
            ValueError: Human-readable message on failure (no secrets included).
        """
        # Step 1: Key presence
        required = ("azure_client_id", "azure_client_secret", "azure_tenant_id")
        missing = [k for k in required if not self._creds.get(k)]
        if missing:
            raise ValueError(
                f"Azure credentials missing required key(s): {missing}. "
                "Provide azure_client_id, azure_client_secret, and azure_tenant_id."
            )

        sub_id = self.target
        if not sub_id:
            raise ValueError(
                "Azure integration target_identifier must be the subscription ID. "
                "Set target_identifier to the Azure subscription UUID."
            )

        # Step 2: Token acquisition
        token = await self._get_arm_token()

        # Step 3: Subscription access
        path = f"/subscriptions/{sub_id}"
        try:
            async with httpx.AsyncClient(
                base_url=_ARM_BASE,
                headers={"Authorization": f"Bearer {token}"},
                timeout=20.0,
            ) as client:
                resp = await client.get(path, params={"api-version": _SUB_API_VERSION})
                if resp.status_code == 401:
                    raise ValueError("ARM token rejected (HTTP 401). Token may have expired.")
                resp.raise_for_status()
                body = resp.json()
            state = body.get("state", "unknown")
            if state not in ("Enabled", "Warned", "PastDue"):
                raise ValueError(
                    f"Azure subscription '{sub_id}' is not in an accessible state: "
                    f"'{state}'. Enabled subscriptions return state=Enabled."
                )
        except ValueError:
            raise
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            if status == 403:
                raise ValueError(
                    f"Service principal lacks access to subscription '{sub_id}' (HTTP 403). "
                    "Assign the Reader role at the subscription level."
                ) from exc
            if status == 404:
                raise ValueError(
                    f"Subscription '{sub_id}' not found (HTTP 404). "
                    "Verify the subscription ID."
                ) from exc
            raise ValueError(
                f"Azure subscription check failed: HTTP {status}"
            ) from exc

        logger.info(
            "AzureConnector: validation passed for subscription '%s' (integration %s).",
            sub_id,
            self.integration_id,
        )

    # ── fetch_findings ─────────────────────────────────────────────────────────

    async def fetch_findings(self) -> List[RawFindingData]:
        """
        Primary:  Defender for Cloud security assessments (unhealthy only).
        Fallback: Defender for Cloud security alerts.

        Returns findings truncated to settings.MAX_FINDINGS_PER_SYNC.
        """
        token  = await self._get_arm_token()
        sub_id = self.target
        limit  = settings.MAX_FINDINGS_PER_SYNC

        async with httpx.AsyncClient(
            base_url=_ARM_BASE,
            headers={"Authorization": f"Bearer {token}"},
            timeout=30.0,
        ) as client:
            try:
                return await self._fetch_assessments(client, sub_id, limit)
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code in (403, 404):
                    logger.info(
                        "AzureConnector: assessments endpoint returned %d for "
                        "subscription '%s'; falling back to alerts.",
                        exc.response.status_code,
                        sub_id,
                    )
                    return await self._fetch_alerts(client, sub_id, limit)
                raise

    async def _fetch_assessments(
        self,
        client: httpx.AsyncClient,
        sub_id: str,
        limit: int,
    ) -> List[RawFindingData]:
        """
        Fetch Defender for Cloud security assessments.
        Only unhealthy assessments (properties.status.code = 'Unhealthy') are
        returned as findings — healthy assessments are not security issues.
        """
        path   = f"/subscriptions/{sub_id}/providers/Microsoft.Security/assessments"
        params = {"api-version": _ASSESSMENTS_API_VERSION}
        raw    = await self._arm_paginate(client, path, params, limit)

        findings: List[RawFindingData] = []
        for item in raw:
            props  = item.get("properties", {})
            status = props.get("status", {})
            if status.get("code") != "Unhealthy":
                continue

            meta       = props.get("metadata", {})
            name       = item.get("name", "unknown")
            resource_id = props.get("resourceDetails", {}).get("Id") or item.get("id", "")
            display    = meta.get("displayName") or name
            severity   = meta.get("severity", "Medium")

            findings.append(
                RawFindingData(
                    external_id=name,
                    resource_id=resource_id,
                    title=f"[Defender] {display}",
                    severity=_AZURE_SEVERITY_MAP.get(severity, FindingSeverity.high),
                    description=props.get("description") or meta.get("description"),
                    remediation_instructions=props.get("remediationDescription")
                    or meta.get("remediationDescription"),
                    raw_payload=item,
                )
            )
            if len(findings) >= limit:
                break

        logger.info(
            "AzureConnector: fetched %d unhealthy assessments for subscription '%s'.",
            len(findings),
            sub_id,
        )
        return findings

    async def _fetch_alerts(
        self,
        client: httpx.AsyncClient,
        sub_id: str,
        limit: int,
    ) -> List[RawFindingData]:
        """
        Fallback: fetch Defender for Cloud security alerts.
        Used when the assessments endpoint is inaccessible.
        """
        path   = f"/subscriptions/{sub_id}/providers/Microsoft.Security/alerts"
        params = {"api-version": _ALERTS_API_VERSION}
        raw    = await self._arm_paginate(client, path, params, limit)

        findings: List[RawFindingData] = []
        for item in raw:
            props    = item.get("properties", {})
            alert_id = item.get("name", "unknown")
            title    = props.get("alertDisplayName") or props.get("alertType") or alert_id
            resource = (
                props.get("compromisedEntity")
                or props.get("resourceIdentifiers", [{}])[0].get("azureResourceId", "")
                or item.get("id", "")
            )
            severity = props.get("severity", "Medium")

            findings.append(
                RawFindingData(
                    external_id=alert_id,
                    resource_id=resource,
                    title=f"[Defender Alert] {title}",
                    severity=_AZURE_SEVERITY_MAP.get(severity, FindingSeverity.high),
                    description=props.get("description"),
                    remediation_instructions=props.get("remediationSteps", [None])[0]
                    if props.get("remediationSteps")
                    else None,
                    raw_payload=item,
                )
            )
            if len(findings) >= limit:
                break

        logger.info(
            "AzureConnector: fetched %d alerts for subscription '%s'.",
            len(findings),
            sub_id,
        )
        return findings
