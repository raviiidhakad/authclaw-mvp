output "vault_security_group_id"    { value = aws_security_group.vault.id }
output "vault_dynamodb_table_name"  { value = aws_dynamodb_table.vault_backend.name }
output "vault_log_group_name"       { value = aws_cloudwatch_log_group.vault.name }
