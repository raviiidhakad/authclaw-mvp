from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.core.audit.export_contracts import VerificationResultContract


class AuditExportVerificationResponse(BaseModel):
    state: str
    export_id: uuid.UUID | None = None
    tenant_id: uuid.UUID | None = None
    schema_id: str | None = Field(None, alias="schema")
    record_count: int
    manifest_digest: str | None = None
    signature_valid: bool | None = None
    manifest_valid: bool | None = None
    files_valid: bool | None = None
    chain_valid: bool | None = None
    security_summary: dict[str, Any]
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    verified_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_contract(cls, result: VerificationResultContract) -> "AuditExportVerificationResponse":
        payload = result.model_dump(mode="json", by_alias=True)
        payload["errors"] = list(payload.get("errors") or [])
        payload["warnings"] = list(payload.get("warnings") or [])
        return cls.model_validate(payload)
