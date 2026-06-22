output "alb_dns_name" {
  description = "DNS name of the Application Load Balancer"
  value       = module.ecs.alb_dns_name
}

output "rds_endpoint" {
  description = "RDS PostgreSQL endpoint"
  value       = module.rds.db_endpoint
}

output "redis_endpoint" {
  description = "ElastiCache Redis primary endpoint"
  value       = module.redis.redis_primary_endpoint
}

output "msk_brokers" {
  description = "MSK bootstrap broker string"
  value       = module.msk.msk_bootstrap_brokers
}

output "vpc_id" {
  description = "VPC ID"
  value       = module.vpc.vpc_id
}

output "ecs_cluster_name" {
  description = "ECS Cluster Name"
  value       = module.ecs.ecs_cluster_name
}

output "waf_acl_arn" {
  description = "WAFv2 Web ACL ARN"
  value       = module.ecs.waf_acl_arn
}
