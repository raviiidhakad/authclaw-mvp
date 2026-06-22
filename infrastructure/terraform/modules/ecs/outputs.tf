output "ecs_cluster_id"       { value = aws_ecs_cluster.main.id }
output "ecs_cluster_name"     { value = aws_ecs_cluster.main.name }
output "alb_dns_name"         { value = aws_lb.main.dns_name }
output "alb_arn"              { value = aws_lb.main.arn }
output "security_group_id"    { value = aws_security_group.ecs_tasks.id }
output "alb_security_group_id" { value = aws_security_group.alb.id }
output "waf_acl_arn"          { value = aws_wafv2_web_acl.main.arn }
