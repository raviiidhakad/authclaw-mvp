CREATE TABLE IF NOT EXISTS audit_logs (
    tenant_id UUID,
    record_id UUID,
    sequence_no UInt64,
    created_at DateTime64(3, 'UTC'),
    
    actor_id Nullable(UUID),
    actor_type String,
    
    action String,
    
    frameworks_affected Array(String),
    
    resource String,
    resource_id String,
    
    execution_trace String,
    metadata String,
    
    ip_address IPv4,
    user_agent String,
    
    previous_hash String,
    integrity_hash String
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(created_at)
ORDER BY (tenant_id, created_at, record_id);
