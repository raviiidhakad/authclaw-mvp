################################################################################
# modules/redis/main.tf
# Amazon ElastiCache for Redis 7 in private data subnets
################################################################################


resource "random_password" "redis_auth" {
  length  = 32
  special = false
}

resource "aws_secretsmanager_secret" "redis_auth" {
  name                    = "authclaw/${var.environment}/redis/auth-token"
  kms_key_id              = var.kms_key_id
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "redis_auth" {
  secret_id     = aws_secretsmanager_secret.redis_auth.id
  secret_string = random_password.redis_auth.result
}

resource "aws_security_group" "redis" {
  name        = "authclaw-${var.environment}-redis-sg"
  description = "Allow Redis traffic from ECS tasks only"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [var.allowed_security_group]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "authclaw-${var.environment}-redis-sg" }
}

resource "aws_elasticache_subnet_group" "main" {
  name       = "authclaw-${var.environment}-redis-subnet-group"
  subnet_ids = var.subnet_ids
}

resource "aws_elasticache_replication_group" "main" {
  replication_group_id       = "authclaw-${var.environment}"
  description                = "AuthClaw ${var.environment} Redis cluster"
  node_type                  = var.node_type
  num_cache_clusters         = var.num_cache_nodes
  engine_version             = "7.1"
  port                       = 6379
  subnet_group_name          = aws_elasticache_subnet_group.main.name
  security_group_ids         = [aws_security_group.redis.id]
  automatic_failover_enabled = var.automatic_failover
  multi_az_enabled           = var.automatic_failover
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                 = random_password.redis_auth.result
  kms_key_id                 = var.kms_key_id
  # Backup strategy: daily snapshots, configurable retention
  snapshot_retention_limit = var.snapshot_retention_days
  snapshot_window          = "02:00-03:00"
  maintenance_window       = "sun:03:00-sun:04:00"
  tags                     = { Name = "authclaw-${var.environment}-redis" }
}

resource "aws_service_discovery_service" "redis" {
  name         = "redis"
  namespace_id = var.cloudmap_namespace_id

  dns_config {
    namespace_id = var.cloudmap_namespace_id
    dns_records {
      ttl  = 10
      type = "CNAME"
    }
    routing_policy = "WEIGHTED"
  }
}
