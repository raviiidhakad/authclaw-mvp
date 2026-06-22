################################################################################
# modules/vault/main.tf
# HashiCorp Vault on ECS Fargate with DynamoDB backend + KMS auto-unseal
################################################################################


# DynamoDB backend for Vault HA storage
resource "aws_dynamodb_table" "vault_backend" {
  name         = "authclaw-${var.environment}-vault-backend"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "Path"
  range_key    = "Key"

  attribute {
    name = "Path"
    type = "S"
  }
  attribute {
    name = "Key"
    type = "S"
  }

  point_in_time_recovery { enabled = true }
  server_side_encryption {
    enabled     = true
    kms_key_arn = var.vault_unseal_key_arn
  }

  tags = { Name = "authclaw-${var.environment}-vault-backend" }
}

resource "aws_cloudwatch_log_group" "vault" {
  name              = "/ecs/authclaw-${var.environment}/vault"
  retention_in_days = var.environment == "prod" ? 365 : (var.environment == "staging" ? 30 : 7)
}

resource "aws_security_group" "vault" {
  name        = "authclaw-${var.environment}-vault-sg"
  description = "Vault ECS service security group"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 8200
    to_port         = 8200
    protocol        = "tcp"
    security_groups = [var.alb_security_group_id]
    description     = "Vault API from internal ALB"
  }

  ingress {
    from_port = 8201
    to_port   = 8201
    protocol  = "tcp"
    self      = true
    description = "Vault cluster HA communication"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "authclaw-${var.environment}-vault-sg" }
}

resource "aws_ecs_task_definition" "vault" {
  family                   = "authclaw-${var.environment}-vault"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  task_role_arn            = var.vault_task_role_arn
  execution_role_arn       = var.execution_role_arn

  container_definitions = jsonencode([{
    name      = "vault"
    image     = "hashicorp/vault:1.17"
    essential = true
    portMappings = [
      { containerPort = 8200, protocol = "tcp" },
      { containerPort = 8201, protocol = "tcp" }
    ]
    environment = [
      { name = "VAULT_ADDR",       value = "http://0.0.0.0:8200" },
      { name = "VAULT_API_ADDR",   value = "http://0.0.0.0:8200" },
      { name = "VAULT_CLUSTER_ADDR", value = "http://0.0.0.0:8201" },
      { name = "AWS_REGION",       value = data.aws_region.current.name }
    ]
    command = [
      "server",
      "-config=/vault/config/vault.hcl"
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.vault.name
        "awslogs-region"        = data.aws_region.current.name
        "awslogs-stream-prefix" = "vault"
      }
    }
    mountPoints = [{
      sourceVolume  = "vault-config"
      containerPath = "/vault/config"
      readOnly      = true
    }]
    healthCheck = {
      command     = ["CMD-SHELL", "vault status -address=http://127.0.0.1:8200 || exit 1"]
      interval    = 30
      timeout     = 5
      retries     = 3
      startPeriod = 60
    }
  }])

  volume {
    name = "vault-config"
  }
}

data "aws_region" "current" {}

resource "aws_ecs_service" "vault" {
  name            = "authclaw-${var.environment}-vault"
  cluster         = var.ecs_cluster_id
  task_definition = aws_ecs_task_definition.vault.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    security_groups  = [aws_security_group.vault.id]
    subnets          = var.subnet_ids
    assign_public_ip = false
  }

  service_registries {
    registry_arn = aws_service_discovery_service.vault.arn
    port         = 8200
  }
}

resource "aws_service_discovery_service" "vault" {
  name         = "vault"
  namespace_id = var.cloudmap_namespace_id

  dns_config {
    namespace_id = var.cloudmap_namespace_id
    dns_records {
      ttl  = 10
      type = "A"
    }
    routing_policy = "MULTIVALUE"
  }
}
