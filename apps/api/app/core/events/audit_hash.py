import hashlib
import json
from datetime import datetime

GENESIS_HASH = "0" * 64

def compute_audit_hash(
    previous_hash: str,
    id_val: str,
    tenant_id: str,
    user_id: str,
    event_type: str,
    resource: str,
    resource_id: str,
    action: str,
    metadata: dict,
    created_at: datetime
) -> str:
    canonical_metadata = json.dumps(metadata or {}, sort_keys=True, separators=(',', ':'))
    # Ensure datetime is in strict ISO format
    if created_at.tzinfo is None:
        created_at_iso = created_at.isoformat() + "+00:00"
    else:
        created_at_iso = created_at.isoformat()
        
    hash_input = f"{previous_hash}{id_val}{tenant_id}{user_id}{event_type}{resource}{resource_id}{action}{canonical_metadata}{created_at_iso}"
    return hashlib.sha256(hash_input.encode('utf-8')).hexdigest()
