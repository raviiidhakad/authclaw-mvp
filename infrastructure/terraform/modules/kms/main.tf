################################################################################
# modules/kms/main.tf
# Customer-managed KMS keys for all AuthClaw resources
################################################################################


resource "aws_kms_key" "app" {
  description             = "AuthClaw ${var.environment} - application envelope encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags                    = { Name = "authclaw-${var.environment}-app" }
}
resource "aws_kms_alias" "app" {
  name          = "alias/authclaw-${var.environment}-app"
  target_key_id = aws_kms_key.app.key_id
}

resource "aws_kms_key" "db" {
  description             = "AuthClaw ${var.environment} - RDS encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags                    = { Name = "authclaw-${var.environment}-db" }
}
resource "aws_kms_alias" "db" {
  name          = "alias/authclaw-${var.environment}-db"
  target_key_id = aws_kms_key.db.key_id
}

resource "aws_kms_key" "cache" {
  description             = "AuthClaw ${var.environment} - ElastiCache encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags                    = { Name = "authclaw-${var.environment}-cache" }
}
resource "aws_kms_alias" "cache" {
  name          = "alias/authclaw-${var.environment}-cache"
  target_key_id = aws_kms_key.cache.key_id
}

resource "aws_kms_key" "vault_unseal" {
  description             = "AuthClaw ${var.environment} - Vault auto-unseal"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags                    = { Name = "authclaw-${var.environment}-vault-unseal" }
}
resource "aws_kms_alias" "vault_unseal" {
  name          = "alias/authclaw-${var.environment}-vault-unseal"
  target_key_id = aws_kms_key.vault_unseal.key_id
}
