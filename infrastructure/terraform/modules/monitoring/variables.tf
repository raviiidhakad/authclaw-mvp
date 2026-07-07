variable "environment" { type = string }
variable "db_identifier" { type = string }
variable "redis_id" { type = string }
variable "alb_arn_suffix" { type = string }
variable "sns_email" {
  type    = string
  default = ""
}
variable "alb_target_group_arn_suffix" { type = string }
variable "api_log_group_name" { type = string }
variable "audit_worker_log_group_name" { type = string }
variable "security_worker_log_group_name" { type = string }
variable "reconciler_worker_log_group_name" { type = string }
