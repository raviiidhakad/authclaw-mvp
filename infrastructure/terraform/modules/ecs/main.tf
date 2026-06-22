################################################################################
# modules/ecs/main.tf
# ECS Cluster, ALB, WAFv2, all Fargate services, auto-scaling
################################################################################


data "aws_region" "current" {}

# ─── ECS Cluster ─────────────────────────────────────────────────────────────
resource "aws_ecs_cluster" "main" {
  name = "authclaw-cluster-${var.environment}"
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

# ─── Security Groups ─────────────────────────────────────────────────────────
resource "aws_security_group" "alb" {
  name        = "authclaw-${var.environment}-alb-sg"
  description = "Allow HTTP/HTTPS from internet"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "authclaw-${var.environment}-alb-sg" }
}

resource "aws_security_group" "ecs_tasks" {
  name        = "authclaw-${var.environment}-ecs-tasks-sg"
  description = "Allow inbound access from the ALB only"
  vpc_id      = var.vpc_id

  ingress {
    protocol        = "tcp"
    from_port       = 8000
    to_port         = 8000
    security_groups = [aws_security_group.alb.id]
  }
  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "authclaw-${var.environment}-ecs-tasks-sg" }
}

# ─── ALB ─────────────────────────────────────────────────────────────────────
resource "aws_lb" "main" {
  name               = "authclaw-${var.environment}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.public_subnet_ids
  tags               = { Name = "authclaw-${var.environment}-alb" }
}

resource "aws_lb_target_group" "api" {
  name        = "authclaw-${var.environment}-api-tg"
  port        = 8000
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    path                = "/health"
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    matcher             = "200"
  }
}

resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# ─── WAFv2 ───────────────────────────────────────────────────────────────────
resource "aws_cloudwatch_log_group" "waf" {
  name              = "/aws/waf/authclaw-${var.environment}"
  retention_in_days = 30
}

resource "aws_wafv2_web_acl" "main" {
  name  = "authclaw-${var.environment}-waf"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "AWSCommonRuleSet"
    priority = 10
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSCommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSKnownBadInputsRuleSet"
    priority = 20
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSKnownBadInputsRuleSet"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSSQLiRuleSet"
    priority = 30
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSSQLiRuleSet"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSBotControl"
    priority = 40
    # Count only — review metrics before switching to block
    override_action {
      count {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesBotControlRuleSet"
        vendor_name = "AWS"
        managed_rule_group_configs {
          aws_managed_rules_bot_control_rule_set {
            inspection_level = "COMMON"
          }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSBotControl"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "authclaw-${var.environment}-waf"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "main" {
  resource_arn = aws_lb.main.arn
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}

resource "aws_wafv2_web_acl_logging_configuration" "main" {
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]
  resource_arn            = aws_wafv2_web_acl.main.arn
}

# ─── CloudWatch Log Groups ───────────────────────────────────────────────────
locals {
  log_retention = var.environment == "prod" ? 365 : (var.environment == "staging" ? 30 : 7)
}

resource "aws_cloudwatch_log_group" "api" {
  name              = "/ecs/authclaw-${var.environment}/api"
  retention_in_days = local.log_retention
}

resource "aws_cloudwatch_log_group" "audit_worker" {
  name              = "/ecs/authclaw-${var.environment}/audit-worker"
  retention_in_days = local.log_retention
}

resource "aws_cloudwatch_log_group" "security_worker" {
  name              = "/ecs/authclaw-${var.environment}/security-worker"
  retention_in_days = local.log_retention
}

resource "aws_cloudwatch_log_group" "reconciler_worker" {
  name              = "/ecs/authclaw-${var.environment}/reconciler-worker"
  retention_in_days = local.log_retention
}

# ─── API Task Definition ─────────────────────────────────────────────────────
resource "aws_ecs_task_definition" "api" {
  family                   = "authclaw-${var.environment}-api"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.api_task_cpu
  memory                   = var.api_task_memory
  task_role_arn            = var.task_role_arn
  execution_role_arn       = var.execution_role_arn

  container_definitions = jsonencode([
    {
      name      = "authclaw-api"
      image     = "ghcr.io/${var.environment}-placeholder/authclaw-api:latest"
      essential = true
      portMappings = [{ containerPort = 8000, protocol = "tcp" }]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.api.name
          "awslogs-region"        = data.aws_region.current.name
          "awslogs-stream-prefix" = "api"
        }
      }
    },
    {
      name      = "aws-otel-collector"
      image     = "public.ecr.aws/aws-observability/aws-otel-collector:latest"
      essential = false
      command   = ["--config=/etc/ecs/ecs-default-config.yaml"]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.api.name
          "awslogs-region"        = data.aws_region.current.name
          "awslogs-stream-prefix" = "otel"
        }
      }
    }
  ])
}

# ─── Worker Task Definition (shared template) ────────────────────────────────
resource "aws_ecs_task_definition" "audit_worker" {
  family                   = "authclaw-${var.environment}-audit-worker"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.worker_task_cpu
  memory                   = var.worker_task_memory
  task_role_arn            = var.task_role_arn
  execution_role_arn       = var.execution_role_arn

  container_definitions = jsonencode([{
    name      = "authclaw-audit-worker"
    image     = "ghcr.io/${var.environment}-placeholder/authclaw-api:latest"
    essential = true
    command   = ["python", "-m", "app.workers.audit"]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.audit_worker.name
        "awslogs-region"        = data.aws_region.current.name
        "awslogs-stream-prefix" = "audit-worker"
      }
    }
  }])
}

resource "aws_ecs_task_definition" "security_worker" {
  family                   = "authclaw-${var.environment}-security-worker"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.worker_task_cpu
  memory                   = var.worker_task_memory
  task_role_arn            = var.task_role_arn
  execution_role_arn       = var.execution_role_arn

  container_definitions = jsonencode([{
    name      = "authclaw-security-worker"
    image     = "ghcr.io/${var.environment}-placeholder/authclaw-api:latest"
    essential = true
    command   = ["python", "-m", "app.workers.security"]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.security_worker.name
        "awslogs-region"        = data.aws_region.current.name
        "awslogs-stream-prefix" = "security-worker"
      }
    }
  }])
}

resource "aws_ecs_task_definition" "reconciler_worker" {
  family                   = "authclaw-${var.environment}-reconciler-worker"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.worker_task_cpu
  memory                   = var.worker_task_memory
  task_role_arn            = var.task_role_arn
  execution_role_arn       = var.execution_role_arn

  container_definitions = jsonencode([{
    name      = "authclaw-reconciler-worker"
    image     = "ghcr.io/${var.environment}-placeholder/authclaw-api:latest"
    essential = true
    command   = ["python", "-m", "app.workers.reconciler"]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.reconciler_worker.name
        "awslogs-region"        = data.aws_region.current.name
        "awslogs-stream-prefix" = "reconciler-worker"
      }
    }
  }])
}

# ─── ECS Services ─────────────────────────────────────────────────────────────
resource "aws_ecs_service" "api" {
  name            = "authclaw-api-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.api.arn
  desired_count   = var.api_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    security_groups  = [aws_security_group.ecs_tasks.id]
    subnets          = var.subnet_ids
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.api.arn
    container_name   = "authclaw-api"
    container_port   = 8000
  }

  service_registries {
    registry_arn = aws_service_discovery_service.api.arn
    port         = 8000
  }
}

resource "aws_ecs_service" "audit_worker" {
  name            = "authclaw-audit-worker"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.audit_worker.arn
  desired_count   = 1
  launch_type     = "FARGATE"
  network_configuration {
    security_groups  = [aws_security_group.ecs_tasks.id]
    subnets          = var.subnet_ids
    assign_public_ip = false
  }
}

resource "aws_ecs_service" "security_worker" {
  name            = "authclaw-security-worker"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.security_worker.arn
  desired_count   = 1
  launch_type     = "FARGATE"
  network_configuration {
    security_groups  = [aws_security_group.ecs_tasks.id]
    subnets          = var.subnet_ids
    assign_public_ip = false
  }
}

resource "aws_ecs_service" "reconciler_worker" {
  name            = "authclaw-reconciler-worker"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.reconciler_worker.arn
  desired_count   = 1
  launch_type     = "FARGATE"
  network_configuration {
    security_groups  = [aws_security_group.ecs_tasks.id]
    subnets          = var.subnet_ids
    assign_public_ip = false
  }
}

# ─── Auto-Scaling for API ─────────────────────────────────────────────────────
resource "aws_appautoscaling_target" "api" {
  max_capacity       = var.api_max_count
  min_capacity       = var.api_min_count
  resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.api.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "api_cpu" {
  name               = "authclaw-${var.environment}-api-cpu-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.api.resource_id
  scalable_dimension = aws_appautoscaling_target.api.scalable_dimension
  service_namespace  = aws_appautoscaling_target.api.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value       = 70.0
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}

# ─── Cloud Map Service for API ─────────────────────────────────────────────────
resource "aws_service_discovery_service" "api" {
  name         = "api"
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
