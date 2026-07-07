variable "environment" { type = string }
variable "vpc_id" { type = string }
variable "subnet_ids" { type = list(string) }
variable "node_type" { type = string }
variable "num_cache_nodes" { type = number }
variable "kms_key_id" { type = string }
variable "allowed_security_group" { type = string }
variable "cloudmap_namespace_id" { type = string }
variable "snapshot_retention_days" {
  type    = number
  default = 7
}
variable "automatic_failover" {
  type    = bool
  default = false
}
