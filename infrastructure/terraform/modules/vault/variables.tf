variable "environment"           { type = string }
variable "vpc_id"                { type = string }
variable "subnet_ids"            { type = list(string) }
variable "vault_task_role_arn"   { type = string }
variable "execution_role_arn"    { type = string }
variable "vault_unseal_key_arn"  { type = string }
variable "vault_unseal_key_id"   { type = string }
variable "ecs_cluster_id"        { type = string }
variable "cloudmap_namespace_id" { type = string }
variable "alb_security_group_id" { type = string }
variable "task_cpu"              {
  type    = number
  default = 512
}
variable "task_memory"           {
  type    = number
  default = 1024
}
variable "desired_count"         {
  type    = number
  default = 1
}
