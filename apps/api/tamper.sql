ALTER TABLE audit_logs DISABLE TRIGGER ALL;
UPDATE audit_logs SET metadata = '{"action": "read", "resource": "login", "ip_address": "192.168.1.99", "resource_id": "test_1"}'::jsonb WHERE resource_id = 'test_1';
ALTER TABLE audit_logs ENABLE TRIGGER ALL;
