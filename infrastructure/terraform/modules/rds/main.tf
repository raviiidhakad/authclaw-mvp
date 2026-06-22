################################################################################
# modules/rds/main.tf
# Amazon RDS PostgreSQL 15 in private data subnets, encrypted with KMS
################################################################################

resource "random_password" "db" {
  length  = 32
  special = false
}

resource "aws_secretsmanager_secret" "db_password" {
  name                    = "authclaw/${var.environment}/db/master-password"
  kms_key_id              = var.kms_key_id
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id     = aws_secretsmanager_secret.db_password.id
  secret_string = random_password.db.result
}

resource "aws_db_subnet_group" "main" {
  name       = "authclaw-${var.environment}-db-subnet-group"
  subnet_ids = var.subnet_ids
  tags       = { Name = "authclaw-${var.environment}-db-subnet-group" }
}

resource "aws_security_group" "rds" {
  name        = "authclaw-${var.environment}-rds-sg"
  description = "Allow PostgreSQL traffic from ECS tasks only"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [var.allowed_security_group]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "authclaw-${var.environment}-rds-sg" }
}

resource "aws_db_parameter_group" "postgres15" {
  name   = "authclaw-${var.environment}-pg15"
  family = "postgres15"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
  parameter {
    name  = "log_connections"
    value = "1"
  }
}

resource "aws_db_instance" "main" {
  identifier              = "authclaw-${var.environment}"
  engine                  = "postgres"
  engine_version          = "15"
  instance_class          = var.instance_class
  allocated_storage       = 20
  max_allocated_storage   = 100
  storage_encrypted       = true
  kms_key_id              = var.kms_key_id
  db_name                 = var.db_name
  username                = var.db_username
  password                = random_password.db.result
  db_subnet_group_name    = aws_db_subnet_group.main.name
  vpc_security_group_ids  = [aws_security_group.rds.id]
  parameter_group_name    = aws_db_parameter_group.postgres15.name
  backup_retention_period = var.backup_retention_days
  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:04:00-sun:05:00"
  multi_az                = var.multi_az
  deletion_protection     = var.multi_az # protect prod
  skip_final_snapshot     = !var.multi_az
  performance_insights_enabled = var.multi_az
  tags                    = { Name = "authclaw-${var.environment}-postgres" }
}

# Cloud Map alias record for postgres.authclaw.local
resource "aws_service_discovery_service" "postgres" {
  name         = "postgres"
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
