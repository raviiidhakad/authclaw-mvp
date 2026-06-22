variable "environment"           { type = string }
variable "vpc_id"                { type = string }
variable "subnet_ids"            { type = list(string) }
variable "public_subnet_ids"     { type = list(string) }
variable "execution_role_arn"    { type = string }
variable "task_role_arn"         { type = string }
variable "cloudmap_namespace_id" { type = string }

variable "api_task_cpu"    { type = number }
variable "api_task_memory" { type = number }
variable "api_desired_count" { type = number }
variable "api_min_count"   {
  type    = number
  default = 1
}
variable "api_max_count"   {
  type    = number
  default = 5
}
variable "worker_task_cpu"    { type = number }
variable "worker_task_memory" { type = number }
