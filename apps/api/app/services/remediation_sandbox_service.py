from __future__ import annotations

import json
import re
import shutil
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.models.remediation import RemediationArtifact, RemediationArtifactType, RemediationDryRunStatus
from app.services.api_safety import sanitize_text


MAX_ARTIFACT_BYTES = 256 * 1024
DEFAULT_TIMEOUT_SECONDS = 10.0


def _finding(code: str, message: str) -> dict[str, str]:
    return {"code": sanitize_text(code), "message": sanitize_text(message)}


SHELL_OR_PROCESS_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "shell_wrapper",
        re.compile(r"(^|\n)\s*#!.*\b(?:bash|sh|pwsh|powershell)\b|\b(?:bash|sh|pwsh|powershell|cmd\.exe)\s+-c\b", re.I),
        "Artifact includes a shell wrapper or command interpreter invocation.",
    ),
    (
        "process_execution",
        re.compile(r"\b" + "sub" + r"process\b|\bos\.system\s*\(|\bexec\s*\(|\beval\s*\(", re.I),
        "Artifact includes process execution code.",
    ),
    (
        "pipe_to_shell",
        re.compile(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:bash|sh)\b", re.I),
        "Artifact pipes downloaded content to a shell.",
    ),
)


@dataclass(frozen=True)
class SandboxValidationOutcome:
    sandbox_id: str
    dry_run_type: str
    status: RemediationDryRunStatus
    output_summary: str
    warnings: list[dict[str, str]] = field(default_factory=list)
    blocking_reasons: list[dict[str, str]] = field(default_factory=list)


class RemediationSandboxService:
    """Static remediation artifact validation in an isolated temp workspace."""

    def __init__(
        self,
        *,
        root_dir: str | Path | None = None,
        keep_debug_workspace: bool = False,
        max_artifact_bytes: int = MAX_ARTIFACT_BYTES,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.root_dir = Path(root_dir or Path(tempfile.gettempdir()) / "authclaw-remediation-sandbox").resolve()
        self.keep_debug_workspace = keep_debug_workspace
        self.max_artifact_bytes = max_artifact_bytes
        self.timeout_seconds = timeout_seconds

    def validate_artifact(self, artifact: RemediationArtifact) -> SandboxValidationOutcome:
        started = time.monotonic()
        sandbox_id = f"dryrun-{uuid.uuid4().hex}"
        workspace = self.create_workspace(sandbox_id)
        warnings: list[dict[str, str]] = []
        blocking: list[dict[str, str]] = []
        dry_run_type = self._artifact_type_value(artifact)

        try:
            raw_content = str(getattr(artifact, "content_redacted", "") or "")
            content = sanitize_text(raw_content)
            content_bytes = content.encode("utf-8", errors="replace")
            if len(content_bytes) > self.max_artifact_bytes:
                blocking.append(_finding("artifact_too_large", f"Artifact exceeds dry-run size limit of {self.max_artifact_bytes} bytes."))
            if "\x00" in raw_content:
                blocking.append(_finding("binary_artifact", "Binary or null-byte artifact content is not accepted for dry-run."))

            for code, pattern, message in SHELL_OR_PROCESS_PATTERNS:
                if pattern.search(content):
                    blocking.append(_finding(code, message))

            if time.monotonic() - started > self.timeout_seconds:
                blocking.append(_finding("sandbox_timeout", "Dry-run static validation exceeded the sandbox timeout."))

            if not blocking:
                artifact_path = self.workspace_file_path(sandbox_id, self._artifact_filename(dry_run_type))
                artifact_path.write_text(content, encoding="utf-8")
                type_warnings, type_blocking, summary = self._validate_by_type(dry_run_type, content)
                warnings.extend(type_warnings)
                blocking.extend(type_blocking)
            else:
                summary = "Dry-run rejected before artifact-type validation."

            status = RemediationDryRunStatus.succeeded if not blocking else RemediationDryRunStatus.rejected
            return SandboxValidationOutcome(
                sandbox_id=sandbox_id,
                dry_run_type=dry_run_type,
                status=status,
                output_summary=sanitize_text(summary),
                warnings=self._sanitize_findings(warnings),
                blocking_reasons=self._sanitize_findings(blocking),
            )
        finally:
            if not self.keep_debug_workspace:
                self.cleanup_workspace(workspace)

    def create_workspace(self, sandbox_id: str) -> Path:
        safe_id = self._safe_component(sandbox_id)
        self.root_dir.mkdir(parents=True, exist_ok=True)
        workspace = (self.root_dir / safe_id).resolve()
        self._assert_controlled_path(workspace)
        workspace.mkdir(mode=0o700, parents=False, exist_ok=False)
        return workspace

    def workspace_file_path(self, sandbox_id: str, filename: str) -> Path:
        workspace = (self.root_dir / self._safe_component(sandbox_id)).resolve()
        path = (workspace / filename).resolve()
        self._assert_controlled_path(path)
        if path.parent != workspace:
            raise ValueError("Sandbox path traversal is not allowed")
        return path

    def cleanup_workspace(self, workspace: Path) -> None:
        resolved = workspace.resolve()
        self._assert_controlled_path(resolved)
        if resolved == self.root_dir:
            raise ValueError("Refusing to clean sandbox root")
        if resolved.exists():
            shutil.rmtree(resolved)

    def _validate_by_type(self, dry_run_type: str, content: str) -> tuple[list[dict[str, str]], list[dict[str, str]], str]:
        if dry_run_type == RemediationArtifactType.terraform_plan_draft.value:
            return self._validate_terraform(content)
        if dry_run_type == RemediationArtifactType.aws_cli_command_draft.value:
            return self._validate_aws_cli(content)
        if dry_run_type == RemediationArtifactType.github_pr_patch_draft.value:
            return self._validate_github_patch(content)
        if dry_run_type == RemediationArtifactType.iam_policy_diff.value:
            return self._validate_iam_policy(content)
        if dry_run_type == RemediationArtifactType.documentation_only.value:
            return [], [], "Documentation-only artifact passed static dry-run checks. No execution was attempted."
        return [], [_finding("unsupported_artifact_type", "Artifact type is not supported by dry-run sandbox.")], "Unsupported artifact type."

    def _validate_terraform(self, content: str) -> tuple[list[dict[str, str]], list[dict[str, str]], str]:
        blocking = []
        patterns = (
            ("terraform_apply", r"\bterraform\s+apply\b|\bapply\s+-auto-approve\b", "Terraform apply is forbidden in dry-run."),
            ("terraform_destroy", r"\bterraform\s+destroy\b|\bdestroy\b", "Terraform destroy is forbidden in dry-run."),
            ("terraform_local_exec", r"\blocal-exec\b", "Terraform local-exec provisioners are forbidden."),
            ("terraform_remote_exec", r"\bremote-exec\b", "Terraform remote-exec provisioners are forbidden."),
            ("terraform_provisioner", r"\bprovisioner\s+\"", "Terraform provisioners are forbidden."),
            ("terraform_external_data", r'data\s+"external"', "Terraform external data sources are forbidden in dry-run."),
        )
        for code, pattern, message in patterns:
            if re.search(pattern, content, re.I):
                blocking.append(_finding(code, message))
        warnings = []
        if shutil.which("terraform") is None:
            warnings.append(_finding("terraform_validate_unavailable", "Terraform binary is unavailable; static validation only was performed."))
        return warnings, blocking, "Terraform draft completed static dry-run validation. No provider credentials, plan, or apply were used."

    def _validate_aws_cli(self, content: str) -> tuple[list[dict[str, str]], list[dict[str, str]], str]:
        blocking = []
        warnings = []
        lower = content.lower()
        if re.search(r"\baws\s+configure\b|\bAWS_[A-Z0-9_]+\s*=", content, re.I):
            blocking.append(_finding("aws_credentials_inline", "AWS credential configuration is not accepted in dry-run artifacts."))
        mutating = (
            " create-",
            " delete-",
            " put-",
            " update-",
            " modify-",
            " attach-",
            " detach-",
            " authorize-",
            " revoke-",
            " terminate-",
            " run-instances",
            " s3 rm",
            " s3api put-",
            " s3api delete-",
            " iam add-",
            " iam create-",
            " iam delete-",
            " iam put-",
            " iam attach-",
            " iam detach-",
        )
        if any(token in f" {lower}" for token in mutating):
            blocking.append(_finding("aws_mutating_command", "AWS CLI mutating command is blocked; no CLI command was executed."))
        if not re.search(r"(^|\n)\s*aws\s+", content, re.I):
            warnings.append(_finding("aws_cli_not_detected", "No AWS CLI command shape was detected; static checks only were performed."))
        return warnings, blocking, "AWS CLI draft was statically classified. No AWS CLI command was executed."

    def _validate_github_patch(self, content: str) -> tuple[list[dict[str, str]], list[dict[str, str]], str]:
        blocking = []
        if re.search(r"\bgh\s+pr\s+create\b|\bgit\s+push\b|\bapi\.github\.com\b", content, re.I):
            blocking.append(_finding("github_mutation", "GitHub PR creation, pushes, and API calls are blocked in dry-run."))
        warnings = []
        if not re.search(r"(^diff --git|^\+\+\+ |^--- |^@@ )", content, re.M):
            warnings.append(_finding("patch_shape_uncertain", "Artifact is not a standard unified diff; static patch checks only were performed."))
        return warnings, blocking, "GitHub patch draft passed static diff validation. No GitHub API, push, or PR creation was attempted."

    def _validate_iam_policy(self, content: str) -> tuple[list[dict[str, str]], list[dict[str, str]], str]:
        warnings = []
        blocking = []
        parsed = self._extract_json(content)
        if parsed is None:
            warnings.append(_finding("iam_json_parse_failed", "IAM policy diff was not valid JSON; keyword checks were used."))
            text = content.lower()
            if "*" in text:
                blocking.append(_finding("iam_wildcard_detected", "IAM wildcard action or resource detected."))
            if any(term in text for term in ("administratoraccess", "iam:passrole", "iam:createpolicyversion", "sts:assumerole")):
                blocking.append(_finding("iam_privilege_escalation", "IAM privilege escalation pattern detected."))
            return warnings, blocking, "IAM policy draft completed static keyword validation. No policy was applied."

        statements = parsed.get("Statement", []) if isinstance(parsed, dict) else []
        if isinstance(statements, dict):
            statements = [statements]
        for statement in statements if isinstance(statements, list) else []:
            if not isinstance(statement, dict):
                continue
            actions = self._as_list(statement.get("Action"))
            resources = self._as_list(statement.get("Resource"))
            effect = str(statement.get("Effect", "")).lower()
            if "*" in actions or "*" in resources:
                blocking.append(_finding("iam_wildcard_detected", "IAM wildcard action or resource detected."))
            action_blob = " ".join(str(action).lower() for action in actions)
            if effect == "allow" and any(term in action_blob for term in ("iam:passrole", "iam:createpolicyversion", "sts:assumerole")):
                blocking.append(_finding("iam_privilege_escalation", "IAM privilege escalation action detected."))
        return warnings, blocking, "IAM policy diff parsed as JSON and completed static validation. No policy was applied."

    def _extract_json(self, content: str) -> dict[str, Any] | None:
        try:
            value = json.loads(content)
            return value if isinstance(value, dict) else None
        except json.JSONDecodeError:
            return None

    def _as_list(self, value: Any) -> list[Any]:
        if value is None:
            return []
        if isinstance(value, list):
            return value
        return [value]

    def _artifact_filename(self, dry_run_type: str) -> str:
        return {
            RemediationArtifactType.terraform_plan_draft.value: "artifact.tf",
            RemediationArtifactType.aws_cli_command_draft.value: "artifact.awscli.txt",
            RemediationArtifactType.github_pr_patch_draft.value: "artifact.patch",
            RemediationArtifactType.iam_policy_diff.value: "artifact.iam.json",
            RemediationArtifactType.documentation_only.value: "artifact.md",
        }.get(dry_run_type, "artifact.txt")

    def _artifact_type_value(self, artifact: RemediationArtifact) -> str:
        artifact_type = getattr(artifact, "artifact_type", "")
        return artifact_type.value if hasattr(artifact_type, "value") else str(artifact_type)

    def _sanitize_findings(self, findings: list[dict[str, str]]) -> list[dict[str, str]]:
        return [{"code": sanitize_text(item.get("code", "")), "message": sanitize_text(item.get("message", ""))} for item in findings]

    def _safe_component(self, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,120}", value):
            raise ValueError("Invalid sandbox path component")
        if value in {".", ".."}:
            raise ValueError("Invalid sandbox path component")
        return value

    def _assert_controlled_path(self, path: Path) -> None:
        root = self.root_dir.resolve()
        resolved = path.resolve()
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise ValueError("Sandbox path escapes controlled root") from exc
