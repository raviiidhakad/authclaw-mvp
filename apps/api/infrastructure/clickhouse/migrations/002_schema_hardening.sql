-- 002_schema_hardening.sql
-- Upgrades the ClickHouse audit_logs schema to support enterprise security standards.

-- 1. Upgrade IPv4 to IPv6 to natively support both IPv4-mapped and native IPv6 clients
ALTER TABLE audit_logs MODIFY COLUMN ip_address IPv6;

-- 2. Add Bloom Filter skipping indices on JSON metadata for rapid compliance search
ALTER TABLE audit_logs ADD INDEX idx_metadata_bloom metadata TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 1;
ALTER TABLE audit_logs ADD INDEX idx_action_bloom action TYPE set(100) GRANULARITY 1;

-- 3. Materialize indices for historical data
ALTER TABLE audit_logs MATERIALIZE INDEX idx_metadata_bloom;
ALTER TABLE audit_logs MATERIALIZE INDEX idx_action_bloom;
