output "app_key_arn" { value = aws_kms_key.app.arn }
output "db_key_arn" { value = aws_kms_key.db.arn }
output "cache_key_arn" { value = aws_kms_key.cache.arn }
output "vault_unseal_key_arn" { value = aws_kms_key.vault_unseal.arn }
output "vault_unseal_key_id" { value = aws_kms_key.vault_unseal.key_id }
