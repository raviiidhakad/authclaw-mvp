output "db_endpoint"          { value = aws_db_instance.main.endpoint }
output "db_name"              { value = aws_db_instance.main.db_name }
output "db_secret_arn"        { value = aws_secretsmanager_secret.db_password.arn }
output "rds_security_group_id" { value = aws_security_group.rds.id }
