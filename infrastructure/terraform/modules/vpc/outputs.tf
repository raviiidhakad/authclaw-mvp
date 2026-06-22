output "vpc_id"                    { value = aws_vpc.main.id }
output "public_subnets"            { value = aws_subnet.public[*].id }
output "private_app_subnets"       { value = aws_subnet.private_app[*].id }
output "private_data_subnets"      { value = aws_subnet.private_data[*].id }
output "cloudmap_namespace_id"     { value = aws_service_discovery_private_dns_namespace.main.id }
output "cloudmap_namespace_name"   { value = aws_service_discovery_private_dns_namespace.main.name }
