################################################################################
# modules/iam/main.tf
# IAM roles and policies for ECS Task Execution and Vault
################################################################################



data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ─── ECS Task Execution Role ──────────────────────────────────────────────────
resource "aws_iam_role" "ecs_task_execution" {
  name = "authclaw-${var.environment}-ecs-execution-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_execution_managed" {
  role       = aws_iam_role.ecs_task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# ─── ECS Task Role (application-level) ───────────────────────────────────────
resource "aws_iam_role" "ecs_task" {
  name = "authclaw-${var.environment}-ecs-task-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "ecs_task_kms" {
  name = "authclaw-${var.environment}-ecs-task-kms"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "kms:Encrypt", "kms:Decrypt",
        "kms:GenerateDataKey", "kms:DescribeKey"
      ]
      Resource = [
        var.app_key_arn,
        var.db_key_arn,
        var.cache_key_arn
      ]
    }]
  })
}

resource "aws_iam_policy" "ecs_task_cloudwatch" {
  name = "authclaw-${var.environment}-ecs-task-cw"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream", "logs:PutLogEvents",
        "cloudwatch:PutMetricData"
      ]
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_task_kms" {
  role       = aws_iam_role.ecs_task.name
  policy_arn = aws_iam_policy.ecs_task_kms.arn
}

resource "aws_iam_role_policy_attachment" "ecs_task_cloudwatch" {
  role       = aws_iam_role.ecs_task.name
  policy_arn = aws_iam_policy.ecs_task_cloudwatch.arn
}

# ─── Vault Task Role ──────────────────────────────────────────────────────────
resource "aws_iam_role" "vault_task" {
  name = "authclaw-${var.environment}-vault-task-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "vault_kms_unseal" {
  name = "authclaw-${var.environment}-vault-kms-unseal"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["kms:Decrypt", "kms:DescribeKey", "kms:Encrypt"]
      Resource = [var.vault_key_arn]
    }]
  })
}

resource "aws_iam_policy" "vault_dynamodb" {
  name = "authclaw-${var.environment}-vault-dynamodb"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "dynamodb:DescribeLimits", "dynamodb:DescribeTimeToLive",
        "dynamodb:ListTagsOfResource", "dynamodb:DescribeReservedCapacityOfferings",
        "dynamodb:DescribeReservedCapacity", "dynamodb:ListTables",
        "dynamodb:BatchGetItem", "dynamodb:BatchWriteItem",
        "dynamodb:CreateTable", "dynamodb:DeleteItem",
        "dynamodb:GetItem", "dynamodb:GetRecords",
        "dynamodb:PutItem", "dynamodb:Query",
        "dynamodb:UpdateItem", "dynamodb:Scan",
        "dynamodb:DescribeTable"
      ]
      Resource = "arn:aws:dynamodb:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:table/authclaw-${var.environment}-vault-*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "vault_kms" {
  role       = aws_iam_role.vault_task.name
  policy_arn = aws_iam_policy.vault_kms_unseal.arn
}

resource "aws_iam_role_policy_attachment" "vault_dynamodb" {
  role       = aws_iam_role.vault_task.name
  policy_arn = aws_iam_policy.vault_dynamodb.arn
}
