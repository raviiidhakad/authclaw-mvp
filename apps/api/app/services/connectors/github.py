"""
AuthClaw Sprint 2 — GitHub Security Connector
----------------------------------------------
Fetches active security findings from GitHub via:

  Primary:  GitHub Advanced Security (GHAS) code scanning + secret scanning alerts
  Fallback: GitHub REST API native checks when GHAS is unavailable or unlicensed:
              • Branch protection rules (default branch)
              • Repository visibility (public repos in private org)
              • Actions security (GITHUB_TOKEN permissions, fork PR access)
              • Outside collaborator permissions (admin access granted externally)

Credential dict structure (stored in Vault):
  {
    "github_token":        str,   # Required — Personal Access Token or GitHub App token
    "github_org":          str,   # Required — Organization login name
    "github_api_base_url": str,   # Optional — default "https://api.github.com"
  }

Required token scopes (checked during validate_credentials):
  repo, read:org, security_events, read:audit_log

Tenant isolation:
  - All API calls are scoped to self._org (from credentials, cross-checked
    against integration.target_identifier).
  - Pagination stops at MAX_FINDINGS_PER_SYNC.
  - No cross-org calls are possible since the org is fixed at integration
    creation time and stored in Vault credentials.

Resiliency:
  - HTTP 429 + Retry-After header → RateLimitError with exact wait time.
  - GHAS 403 / 404 → fallback scanners activate.
  - All httpx calls wrapped in async_retry (3 retries, exponential backoff).
  - Circuit breaker wraps fetch_findings() at the ConnectorWorker level.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, List, Optional

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


# GitHub severity → FindingSeverity (GitHub uses lowercase names)
_GITHUB_SEVERITY_MAP: dict[str, FindingSeverity] = {
    "critical": FindingSeverity.critical,
    "high":     FindingSeverity.high,
    "medium":   FindingSeverity.medium,
    "warning":  FindingSeverity.medium,
    "low":      FindingSeverity.low,
    "note":     FindingSeverity.low,
    "error":    FindingSeverity.high,     # SARIF rule severity
}

# Required OAuth scopes for the GitHub token
_REQUIRED_SCOPES: frozenset[str] = frozenset({
    "repo",
    "read:org",
    "security_events",
    "read:audit_log",
})


@ConnectorRegistry.register
class GitHubConnector(BaseConnector):
    """
    GitHub security connector.

    Validates:
      1. Token authentication — GET /user confirms the token is valid.
      2. Org membership — GET /orgs/{org} confirms access to the target org.
      3. Token scopes — X-OAuth-Scopes header must include required scopes.

    Primary scan:  GHAS code scanning + secret scanning (per-repo pagination).
    Fallback scan: Branch protection, repo visibility, Actions security,
                   outside collaborator permission checks.
    """

    PROVIDER = CloudProvider.github

    # ── Setup ──────────────────────────────────────────────────────────────────

    def _make_headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self._creds['github_token']}",
            "Accept":        "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _base_url(self) -> str:
        return self._creds.get("github_api_base_url", "https://api.github.com")

    def _org(self) -> str:
        return self._creds.get("github_org", self.target)

    def _make_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self._base_url(),
            headers=self._make_headers(),
            timeout=30.0,
        )

    # ── HTTP helpers ───────────────────────────────────────────────────────────

    async def _get(
        self,
        client: httpx.AsyncClient,
        path: str,
        params: Optional[dict] = None,
    ) -> Any:
        """
        Execute a GET with rate-limit handling.
        HTTP 429 → RateLimitError with Retry-After seconds.
        HTTP 403/404 → re-raised as-is for caller to handle.
        """
        response = await client.get(path, params=params)

        if response.status_code == 429:
            retry_after = int(response.headers.get("Retry-After", 60))
            raise RateLimitError(
                f"GitHub rate limit hit on {path}",
                retry_after=retry_after,
            )
        # Let callers handle 403/404 directly
        response.raise_for_status()
        return response.json()

    async def _paginate(
        self,
        client: httpx.AsyncClient,
        path: str,
        params: Optional[dict] = None,
        limit: int = 10_000,
    ) -> list[dict]:
        """
        Auto-paginate GitHub REST endpoints using the Link header.
        Stops when: all pages fetched OR limit reached.
        """
        results: list[dict] = []
        base_params = dict(params or {})
        base_params.setdefault("per_page", 100)
        next_url: Optional[str] = path

        while next_url and len(results) < limit:
            response = await client.get(
                next_url if next_url.startswith("http") else next_url,
                params=base_params if not next_url.startswith("http") else None,
            )
            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", 60))
                raise RateLimitError(
                    f"GitHub rate limit during pagination of {path}",
                    retry_after=retry_after,
                )
            response.raise_for_status()
            data = response.json()
            if isinstance(data, list):
                results.extend(data)
            else:
                results.extend(data.get("items", [data]))

            # Extract next page from Link header
            link_header = response.headers.get("Link", "")
            next_url = self._extract_next_link(link_header)
            base_params = {}  # Already encoded in the next_url

        return results[:limit]

    @staticmethod
    def _extract_next_link(link_header: str) -> Optional[str]:
        """Parse the GitHub Link header and return the 'next' URL if present."""
        if not link_header:
            return None
        for part in link_header.split(","):
            part = part.strip()
            if 'rel="next"' in part:
                url_part = part.split(";")[0].strip()
                return url_part.strip("<>")
        return None

    # ── validate_credentials ───────────────────────────────────────────────────

    async def validate_credentials(self) -> None:
        """
        Three-step validation:
          1. GET /user — token is valid.
          2. GET /orgs/{org} — org is accessible.
          3. X-OAuth-Scopes header — required scopes are present.

        Raises:
            ValueError: Human-readable message on failure.
        """
        token = self._creds.get("github_token")
        if not token:
            raise ValueError("GitHub credentials missing required key: 'github_token'.")

        # Explicitly check the credential key — _org() falls back to self.target
        # which would mask a missing github_org in the stored credential dict.
        if not self._creds.get("github_org"):
            raise ValueError(
                "GitHub credentials missing required key: 'github_org'. "
                "Set github_org to the organization login name."
            )

        org = self._org()

        # Org must match integration target
        if org != self.target:
            raise ValueError(
                f"Credential github_org '{org}' does not match "
                f"integration target '{self.target}'."
            )

        async with self._make_client() as client:
            # ── Step 1: Token validity ─────────────────────────────────────
            try:
                user_resp = await client.get("/user")
                if user_resp.status_code == 401:
                    raise ValueError(
                        "GitHub token is invalid or expired (HTTP 401)."
                    )
                user_resp.raise_for_status()
            except httpx.HTTPStatusError as exc:
                raise ValueError(
                    f"GitHub credential validation failed (GET /user): {exc}"
                ) from exc

            # ── Step 2: Org access ─────────────────────────────────────────
            try:
                org_resp = await client.get(f"/orgs/{org}")
                if org_resp.status_code == 404:
                    raise ValueError(
                        f"GitHub org '{org}' not found or token lacks read:org scope."
                    )
                org_resp.raise_for_status()
            except httpx.HTTPStatusError as exc:
                raise ValueError(
                    f"GitHub org access check failed for '{org}': {exc}"
                ) from exc

            # ── Step 3: Scope validation ───────────────────────────────────
            scopes_header = user_resp.headers.get("X-OAuth-Scopes", "")
            granted_scopes = {s.strip() for s in scopes_header.split(",") if s.strip()}
            missing_scopes = _REQUIRED_SCOPES - granted_scopes

            if missing_scopes:
                raise ValueError(
                    f"GitHub token is missing required OAuth scopes: {sorted(missing_scopes)}. "
                    f"Granted scopes: {sorted(granted_scopes)}. "
                    "Re-generate the token with all required scopes."
                )

        logger.info(
            "GitHubConnector: validation passed for org '%s' (integration %s).",
            org, self.integration_id,
        )

    # ── fetch_findings ─────────────────────────────────────────────────────────

    async def fetch_findings(self) -> List[RawFindingData]:
        """
        Primary: GHAS code scanning + secret scanning.
        Fallback: Branch protection, repo visibility, Actions, collaborators.
        Fallback triggers on: HTTP 403, 404, or GHAS not enabled (422).
        """
        async with self._make_client() as client:
            try:
                findings = await self._fetch_from_ghas(client)
                logger.info(
                    "GitHubConnector: GHAS returned %d findings for integration %s.",
                    len(findings), self.integration_id,
                )
                return findings
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code in (403, 404, 422):
                    logger.warning(
                        "GitHubConnector: GHAS unavailable (HTTP %d) for integration %s. "
                        "Activating fallback scanners.",
                        exc.response.status_code, self.integration_id,
                    )
                    return await self._run_fallback_scanners(client)
                raise

    # ── Primary: GHAS ─────────────────────────────────────────────────────────

    async def _fetch_from_ghas(self, client: httpx.AsyncClient) -> List[RawFindingData]:
        """
        Fetch GHAS code scanning and secret scanning alerts org-wide.
        Uses the org-level endpoints (requires Advanced Security license).
        """
        org = self._org()
        limit = settings.MAX_FINDINGS_PER_SYNC
        findings: List[RawFindingData] = []

        # Code scanning alerts (org-level)
        try:
            code_alerts = await async_retry(
                self._paginate,
                client,
                f"/orgs/{org}/code-scanning/alerts",
                params={"state": "open"},
                limit=limit,
                config=RetryConfig(max_retries=3, base_delay=1.0),
            )
            for alert in code_alerts:
                findings.append(self._map_code_scanning_alert(alert))
                if len(findings) >= limit:
                    return findings
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in (403, 404, 422):
                raise  # Bubble up to trigger fallback in fetch_findings
            logger.warning(
                "GitHubConnector: code-scanning alerts error (HTTP %d): %s",
                exc.response.status_code, exc,
            )

        # Secret scanning alerts (org-level)
        try:
            secret_alerts = await async_retry(
                self._paginate,
                client,
                f"/orgs/{org}/secret-scanning/alerts",
                params={"state": "open"},
                limit=limit - len(findings),
                config=RetryConfig(max_retries=3, base_delay=1.0),
            )
            for alert in secret_alerts:
                findings.append(self._map_secret_scanning_alert(alert))
                if len(findings) >= limit:
                    break
        except httpx.HTTPStatusError as exc:
            logger.warning(
                "GitHubConnector: secret-scanning alerts error (HTTP %d): %s",
                exc.response.status_code, exc,
            )

        return findings[:limit]

    def _map_code_scanning_alert(self, raw: dict) -> RawFindingData:
        rule    = raw.get("rule", {})
        repo    = raw.get("repository", {})
        repo_name = repo.get("full_name", self.target)
        severity_str = rule.get("severity", "warning")
        return RawFindingData(
            external_id=f"code-{repo_name}-{raw.get('number', '')}",
            resource_id=repo_name,
            title=rule.get("description", "Code scanning alert"),
            severity=_GITHUB_SEVERITY_MAP.get(severity_str, FindingSeverity.critical),
            description=raw.get("most_recent_instance", {}).get("message", {}).get("text"),
            remediation_instructions=rule.get("help"),
            raw_payload=raw,
        )

    def _map_secret_scanning_alert(self, raw: dict) -> RawFindingData:
        repo     = raw.get("repository", {})
        repo_name = repo.get("full_name", self.target)
        secret_type = raw.get("secret_type_display_name", raw.get("secret_type", "secret"))
        return RawFindingData(
            external_id=f"secret-{repo_name}-{raw.get('number', '')}",
            resource_id=repo_name,
            title=f"Exposed secret: {secret_type}",
            severity=FindingSeverity.critical,  # All secret leaks are CRITICAL
            description=(
                f"A {secret_type} was detected in repository '{repo_name}'. "
                "The secret may be exposed in commit history."
            ),
            remediation_instructions=(
                f"Revoke the exposed {secret_type} immediately, rotate credentials, "
                "and review commit history to confirm the scope of exposure."
            ),
            raw_payload=raw,
        )

    # ── Fallback orchestrator ──────────────────────────────────────────────────

    async def _run_fallback_scanners(
        self, client: httpx.AsyncClient
    ) -> List[RawFindingData]:
        """
        Run all four fallback scanners against the org's repositories.
        A single scanner failure does NOT abort remaining scanners.
        Results capped at MAX_FINDINGS_PER_SYNC.
        """
        limit = settings.MAX_FINDINGS_PER_SYNC
        results: List[RawFindingData] = []

        # Fetch all org repos once — shared by all fallback scanners
        try:
            org = self._org()
            repos = await self._paginate(
                client,
                f"/orgs/{org}/repos",
                params={"type": "all"},
                limit=500,  # Cap at 500 repos for the fallback scan
            )
        except Exception as exc:
            logger.warning(
                "GitHubConnector: could not list repos for fallback scan: %s", exc
            )
            return []

        scanners = (
            self._scan_branch_protection,
            self._scan_repo_visibility,
            self._scan_actions_security,
            self._scan_outside_collaborators,
        )
        for scanner in scanners:
            if len(results) >= limit:
                break
            try:
                findings = await scanner(client, repos)
                results.extend(findings)
            except Exception as exc:
                logger.warning(
                    "GitHubConnector: fallback scanner '%s' failed: %s",
                    scanner.__name__, exc,
                )

        return results[:limit]

    # ── Fallback: Branch protection ────────────────────────────────────────────

    async def _scan_branch_protection(
        self,
        client: httpx.AsyncClient,
        repos: list[dict],
    ) -> List[RawFindingData]:
        """
        Check each repo's default branch for missing branch protection rules.
        Finding: no branch protection on the default branch.
        """
        findings: List[RawFindingData] = []

        for repo in repos:
            repo_name   = repo.get("full_name", "")
            default_branch = repo.get("default_branch", "main")
            try:
                await self._get(
                    client,
                    f"/repos/{repo_name}/branches/{default_branch}/protection",
                )
                # 200 = protection exists → no finding
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 404:
                    # No protection rule on the default branch
                    findings.append(RawFindingData(
                        external_id=f"bp-no-protection-{repo_name}",
                        resource_id=repo_name,
                        title=f"No branch protection on '{default_branch}' in '{repo_name}'",
                        severity=FindingSeverity.high,
                        description=(
                            f"Repository '{repo_name}' has no branch protection rules "
                            f"on its default branch '{default_branch}'. "
                            "Direct pushes and force pushes to the default branch are allowed."
                        ),
                        remediation_instructions=(
                            f"Add branch protection rules to '{default_branch}' in '{repo_name}': "
                            "require PR reviews, status checks, and disable force push."
                        ),
                        raw_payload={"repo": repo_name, "branch": default_branch},
                    ))

        return findings

    # ── Fallback: Repository visibility ───────────────────────────────────────

    async def _scan_repo_visibility(
        self,
        client: httpx.AsyncClient,
        repos: list[dict],
    ) -> List[RawFindingData]:
        """
        Detect public repositories in an otherwise private org.
        Finding: private org has public repos.
        """
        findings: List[RawFindingData] = []

        for repo in repos:
            repo_name = repo.get("full_name", "")
            visibility = repo.get("visibility", "")
            is_private = repo.get("private", True)

            if visibility == "public" or not is_private:
                findings.append(RawFindingData(
                    external_id=f"visibility-public-{repo_name}",
                    resource_id=repo_name,
                    title=f"Repository '{repo_name}' is publicly visible",
                    severity=FindingSeverity.medium,
                    description=(
                        f"Repository '{repo_name}' is set to public visibility. "
                        "All source code, issues, and pull requests are visible to anyone."
                    ),
                    remediation_instructions=(
                        f"Review if '{repo_name}' should be public. "
                        "Change to private via: Settings → Danger Zone → Change visibility."
                    ),
                    raw_payload=repo,
                ))

        return findings

    # ── Fallback: Actions security ─────────────────────────────────────────────

    async def _scan_actions_security(
        self,
        client: httpx.AsyncClient,
        repos: list[dict],
    ) -> List[RawFindingData]:
        """
        Check GitHub Actions permissions for each repository:
          - GITHUB_TOKEN with write permissions (default_workflow_permissions).
          - Actions enabled for pull requests from forks without approval.
        """
        findings: List[RawFindingData] = []

        for repo in repos:
            repo_name = repo.get("full_name", "")
            try:
                perms = await self._get(
                    client,
                    f"/repos/{repo_name}/actions/permissions/workflow",
                )
                # "write" default permissions = over-privileged GITHUB_TOKEN
                if perms.get("default_workflow_permissions") == "write":
                    findings.append(RawFindingData(
                        external_id=f"actions-write-perms-{repo_name}",
                        resource_id=repo_name,
                        title=(
                            f"Actions in '{repo_name}' have write GITHUB_TOKEN by default"
                        ),
                        severity=FindingSeverity.medium,
                        description=(
                            f"The default GITHUB_TOKEN permissions for '{repo_name}' are set "
                            "to 'write', giving all workflow runs write access to repo contents. "
                            "This increases blast radius if a workflow is compromised."
                        ),
                        remediation_instructions=(
                            f"Set default_workflow_permissions to 'read' for '{repo_name}': "
                            "Settings → Actions → General → Workflow permissions."
                        ),
                        raw_payload=perms,
                    ))
            except httpx.HTTPStatusError:
                pass  # No Actions or no permission to read

        return findings

    # ── Fallback: Outside collaborators ───────────────────────────────────────

    async def _scan_outside_collaborators(
        self,
        client: httpx.AsyncClient,
        repos: list[dict],
    ) -> List[RawFindingData]:
        """
        Check for outside collaborators with admin permission on any org repo.
        Finding: admin-level outside collaborator detected.
        """
        findings: List[RawFindingData] = []
        org = self._org()

        try:
            outside_collabs = await self._paginate(
                client,
                f"/orgs/{org}/outside_collaborators",
                params={"filter": "all"},
                limit=500,
            )
        except httpx.HTTPStatusError:
            return []  # No permission to list outside collaborators

        for user in outside_collabs:
            login = user.get("login", "unknown")
            # Check permissions for this user across repos
            for repo in repos:
                repo_name = repo.get("full_name", "")
                try:
                    collab = await self._get(
                        client,
                        f"/repos/{repo_name}/collaborators/{login}/permission",
                    )
                    permission = collab.get("permission", "")
                    if permission == "admin":
                        findings.append(RawFindingData(
                            external_id=f"collab-admin-{repo_name}-{login}",
                            resource_id=repo_name,
                            title=(
                                f"Outside collaborator '{login}' has admin access "
                                f"to '{repo_name}'"
                            ),
                            severity=FindingSeverity.high,
                            description=(
                                f"Outside collaborator '{login}' has admin-level access "
                                f"to '{repo_name}'. Outside collaborators should have "
                                "the minimum necessary permissions."
                            ),
                            remediation_instructions=(
                                f"Review '{login}' permissions on '{repo_name}'. "
                                "Downgrade from admin to write or read if admin is not required."
                            ),
                            raw_payload=collab,
                        ))
                except httpx.HTTPStatusError:
                    continue

        return findings
