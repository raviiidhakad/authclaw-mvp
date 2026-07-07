################################################################################
# modules/msk/main.tf
# Amazon MSK — Serverless (dev) or Provisioned (staging/prod)
# Supports both modes via var.serverless flag
################################################################################


resource "aws_security_group" "msk" {
  name        = "authclaw-${var.environment}-msk-sg"
  description = "Allow Kafka traffic from ECS tasks only"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 9098 # IAM+TLS
    to_port         = 9098
    protocol        = "tcp"
    security_groups = [var.allowed_security_group]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "authclaw-${var.environment}-msk-sg" }
}

# ─── MSK Serverless (Dev) ────────────────────────────────────────────────────
resource "aws_msk_serverless_cluster" "main" {
  count        = var.serverless ? 1 : 0
  cluster_name = "authclaw-${var.environment}"

  vpc_config {
    subnet_ids         = var.subnet_ids
    security_group_ids = [aws_security_group.msk.id]
  }

  client_authentication {
    sasl {
      iam { enabled = true }
    }
  }
}

# ─── MSK Provisioned (Staging/Prod) ──────────────────────────────────────────
resource "aws_msk_cluster" "main" {
  count                  = var.serverless ? 0 : 1
  cluster_name           = "authclaw-${var.environment}"
  kafka_version          = "3.5.1"
  number_of_broker_nodes = var.number_of_broker_nodes

  broker_node_group_info {
    instance_type   = var.broker_instance_type
    client_subnets  = var.subnet_ids
    security_groups = [aws_security_group.msk.id]

    storage_info {
      ebs_storage_info {
        volume_size = 100
        provisioned_throughput { enabled = false }
      }
    }
  }

  client_authentication {
    sasl { iam = true }
    tls {}
  }

  encryption_info {
    encryption_in_transit {
      client_broker = "TLS"
      in_cluster    = true
    }
    encryption_at_rest_kms_key_arn = var.kms_key_id
  }

  open_monitoring {
    prometheus {
      jmx_exporter { enabled_in_broker = true }
      node_exporter { enabled_in_broker = true }
    }
  }

  logging_info {
    broker_logs {
      cloudwatch_logs {
        enabled   = true
        log_group = "/aws/msk/authclaw-${var.environment}"
      }
    }
  }
}

locals {
  bootstrap_brokers = var.serverless ? (
    length(aws_msk_serverless_cluster.main) > 0
    ? aws_msk_serverless_cluster.main[0].cluster_name
    : ""
    ) : (
    length(aws_msk_cluster.main) > 0
    ? aws_msk_cluster.main[0].bootstrap_brokers_sasl_iam
    : ""
  )
}

resource "aws_service_discovery_service" "kafka" {
  name         = "kafka"
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
