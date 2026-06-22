output "redis_primary_endpoint" { value = aws_elasticache_replication_group.main.primary_endpoint_address }
output "redis_auth_secret_arn"  { value = aws_secretsmanager_secret.redis_auth.arn }
output "redis_security_group_id" { value = aws_security_group.redis.id }
