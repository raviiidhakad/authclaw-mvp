################################################################################
# modules/monitoring/main.tf
# CloudWatch Dashboards, Log Groups, Alarms, and Backup Verification Lambda
################################################################################


data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

locals {
  log_retention = var.environment == "prod" ? 365 : (var.environment == "staging" ? 30 : 7)
}

# ─── SNS Topic for Alarms & Backup Reports ────────────────────────────────────
resource "aws_sns_topic" "alerts" {
  name = "authclaw-${var.environment}-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.sns_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.sns_email
}

# ─── Shared RDS Log Group ─────────────────────────────────────────────────────
resource "aws_cloudwatch_log_group" "rds" {
  name              = "/aws/rds/authclaw-${var.environment}"
  retention_in_days = local.log_retention
}

resource "aws_cloudwatch_log_group" "msk" {
  name              = "/aws/msk/authclaw-${var.environment}"
  retention_in_days = local.log_retention
}

# ─── RDS Alarms ───────────────────────────────────────────────────────────────
resource "aws_cloudwatch_metric_alarm" "rds_cpu" {
  alarm_name          = "authclaw-${var.environment}-rds-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  dimensions          = { DBInstanceIdentifier = var.db_identifier }
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "rds_storage" {
  alarm_name          = "authclaw-${var.environment}-rds-low-storage"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "FreeStorageSpace"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 5368709120 # 5 GB
  dimensions          = { DBInstanceIdentifier = var.db_identifier }
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# ─── Redis Alarms ──────────────────────────────────────────────────────────────
resource "aws_cloudwatch_metric_alarm" "redis_cpu" {
  alarm_name          = "authclaw-${var.environment}-redis-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ElastiCache"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  dimensions          = { ReplicationGroupId = var.redis_id }
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "redis_evictions" {
  alarm_name          = "authclaw-${var.environment}-redis-evictions"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Evictions"
  namespace           = "AWS/ElastiCache"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  dimensions          = { ReplicationGroupId = var.redis_id }
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# ─── ALB 5xx Alarm ────────────────────────────────────────────────────────────
resource "aws_cloudwatch_metric_alarm" "alb_5xx" {
  alarm_name          = "authclaw-${var.environment}-alb-5xx"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "HTTPCode_ELB_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Sum"
  threshold           = 10
  dimensions          = { LoadBalancer = var.alb_arn_suffix }
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}

# ─── Backup Verification Lambda ────────────────────────────────────────────────
resource "aws_iam_role" "backup_validator" {
  name = "authclaw-${var.environment}-backup-validator-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "backup_validator" {
  name = "backup-validator-policy"
  role = aws_iam_role.backup_validator.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "rds:RestoreDBInstanceToPointInTime",
          "rds:DeleteDBInstance",
          "rds:DescribeDBInstances"
        ]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["elasticache:CreateReplicationGroup", "elasticache:DeleteReplicationGroup", "elasticache:DescribeReplicationGroups"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = [aws_sns_topic.alerts.arn]
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "backup_validator" {
  name              = "/aws/lambda/authclaw-${var.environment}-backup-validator"
  retention_in_days = 30
}

resource "aws_lambda_function" "backup_validator" {
  function_name = "authclaw-${var.environment}-backup-validator"
  role          = aws_iam_role.backup_validator.arn
  runtime       = "python3.11"
  handler       = "index.handler"
  timeout       = 900 # 15 min for restore validation

  filename         = "${path.module}/backup_validator.zip"
  source_code_hash = filebase64sha256("${path.module}/backup_validator.zip")

  environment {
    variables = {
      DB_IDENTIFIER  = var.db_identifier
      REDIS_GROUP_ID = var.redis_id
      SNS_TOPIC_ARN  = aws_sns_topic.alerts.arn
      ENVIRONMENT    = var.environment
    }
  }

  depends_on = [aws_cloudwatch_log_group.backup_validator]
}

# Monthly EventBridge trigger: last Sunday at 02:00 UTC
resource "aws_cloudwatch_event_rule" "backup_validation" {
  name                = "authclaw-${var.environment}-monthly-backup-validation"
  description         = "Monthly backup restore validation"
  schedule_expression = "cron(0 2 ? * 1#5 *)"
}

resource "aws_cloudwatch_event_target" "backup_validation" {
  rule      = aws_cloudwatch_event_rule.backup_validation.name
  target_id = "BackupValidatorLambda"
  arn       = aws_lambda_function.backup_validator.arn
}

resource "aws_lambda_permission" "backup_validation" {
  statement_id  = "AllowEventBridgeInvocation"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.backup_validator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.backup_validation.arn
}

# ─── CloudWatch Dashboard ─────────────────────────────────────────────────────
resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "AuthClaw-${var.environment}"
  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric"
        properties = {
          title   = "RDS CPU Utilization"
          metrics = [["AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", var.db_identifier]]
          period  = 300
          stat    = "Average"
          region  = data.aws_region.current.name
        }
      },
      {
        type = "metric"
        properties = {
          title   = "Redis CPU Utilization"
          metrics = [["AWS/ElastiCache", "CPUUtilization", "ReplicationGroupId", var.redis_id]]
          period  = 300
          stat    = "Average"
          region  = data.aws_region.current.name
        }
      },
      {
        type = "metric"
        properties = {
          title   = "ALB 5xx Errors"
          metrics = [["AWS/ApplicationELB", "HTTPCode_ELB_5XX_Count", "LoadBalancer", var.alb_arn_suffix]]
          period  = 60
          stat    = "Sum"
          region  = data.aws_region.current.name
        }
      }
    ]
  })
}

locals {
  worker_log_group_names = {
    audit      = var.audit_worker_log_group_name
    security   = var.security_worker_log_group_name
    reconciler = var.reconciler_worker_log_group_name
  }
}

resource "aws_cloudwatch_log_metric_filter" "opa_fail_closed" {
  name           = "authclaw-${var.environment}-opa-fail-closed"
  log_group_name = var.api_log_group_name
  pattern        = "\"Gateway policy evaluation failed closed\""

  metric_transformation {
    name      = "OpaFailClosedFailureCount"
    namespace = "AuthClaw/Operational"
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "gateway_rate_limit_store_unavailable" {
  name           = "authclaw-${var.environment}-gateway-rate-limit-store-unavailable"
  log_group_name = var.api_log_group_name
  pattern        = "\"Gateway rate limit check failed closed\""

  metric_transformation {
    name      = "GatewayRateLimitStoreUnavailableCount"
    namespace = "AuthClaw/Operational"
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "audit_primary_write_failure" {
  name           = "authclaw-${var.environment}-audit-primary-write-failure"
  log_group_name = var.audit_worker_log_group_name
  pattern        = "authoritative_audit_write_failed"

  metric_transformation {
    name      = "AuditPrimaryWriteFailureCount"
    namespace = "AuthClaw/Operational"
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "audit_clickhouse_mirror_failure" {
  name           = "authclaw-${var.environment}-audit-clickhouse-mirror-failure"
  log_group_name = var.audit_worker_log_group_name
  pattern        = "clickhouse_audit_mirror_write_failed"

  metric_transformation {
    name      = "AuditClickHouseMirrorFailureCount"
    namespace = "AuthClaw/Operational"
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "worker_dlq_routed" {
  for_each       = local.worker_log_group_names
  name           = "authclaw-${var.environment}-${each.key}-dlq-routed"
  log_group_name = each.value
  pattern        = "\"Routed message to DLQ\""

  metric_transformation {
    name      = "WorkerDlqRoutedCount"
    namespace = "AuthClaw/Operational"
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "worker_dlq_publish_failure" {
  for_each       = local.worker_log_group_names
  name           = "authclaw-${var.environment}-${each.key}-dlq-publish-failure"
  log_group_name = each.value
  pattern        = "\"Failed to route message to DLQ\""

  metric_transformation {
    name      = "WorkerDlqPublishFailureCount"
    namespace = "AuthClaw/Operational"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "alb_target_5xx" {
  alarm_name          = "authclaw-${var.environment}-alb-target-5xx"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "HTTPCode_Target_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Sum"
  threshold           = 10
  dimensions          = { LoadBalancer = var.alb_arn_suffix }
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}

resource "aws_cloudwatch_metric_alarm" "alb_target_latency" {
  alarm_name          = "authclaw-${var.environment}-alb-target-latency"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "TargetResponseTime"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Average"
  threshold           = 1
  dimensions          = { TargetGroup = var.alb_target_group_arn_suffix }
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}

resource "aws_cloudwatch_metric_alarm" "opa_fail_closed" {
  alarm_name          = "authclaw-${var.environment}-opa-fail-closed"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "OpaFailClosedFailureCount"
  namespace           = "AuthClaw/Operational"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}

resource "aws_cloudwatch_metric_alarm" "gateway_rate_limit_store_unavailable" {
  alarm_name          = "authclaw-${var.environment}-gateway-rate-limit-store-unavailable"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "GatewayRateLimitStoreUnavailableCount"
  namespace           = "AuthClaw/Operational"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}

resource "aws_cloudwatch_metric_alarm" "audit_primary_write_failure" {
  alarm_name          = "authclaw-${var.environment}-audit-primary-write-failure"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "AuditPrimaryWriteFailureCount"
  namespace           = "AuthClaw/Operational"
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}

resource "aws_cloudwatch_metric_alarm" "audit_clickhouse_mirror_failure" {
  alarm_name          = "authclaw-${var.environment}-audit-clickhouse-mirror-failure"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "AuditClickHouseMirrorFailureCount"
  namespace           = "AuthClaw/Operational"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}

resource "aws_cloudwatch_metric_alarm" "worker_dlq_growth" {
  alarm_name          = "authclaw-${var.environment}-worker-dlq-growth"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "WorkerDlqRoutedCount"
  namespace           = "AuthClaw/Operational"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}

resource "aws_cloudwatch_metric_alarm" "worker_dlq_publish_failure" {
  alarm_name          = "authclaw-${var.environment}-worker-dlq-publish-failure"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "WorkerDlqPublishFailureCount"
  namespace           = "AuthClaw/Operational"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}
