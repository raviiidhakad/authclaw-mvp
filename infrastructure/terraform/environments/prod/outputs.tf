output "alb_dns_name"    { value = module.ecs.alb_dns_name }
output "rds_endpoint"    { value = module.rds.db_endpoint }
output "redis_endpoint"  { value = module.redis.redis_primary_endpoint }
output "msk_brokers"     { value = module.msk.msk_bootstrap_brokers }
output "vpc_id"          { value = module.vpc.vpc_id }
output "ecs_cluster_name" { value = module.ecs.ecs_cluster_name }
output "waf_acl_arn"     { value = module.ecs.waf_acl_arn }
