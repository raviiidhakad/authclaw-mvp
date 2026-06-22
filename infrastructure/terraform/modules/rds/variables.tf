variable "environment"            { type = string }
variable "vpc_id"                 { type = string }
variable "subnet_ids"             { type = list(string) }
variable "instance_class"         { type = string }
variable "multi_az"               { type = bool }
variable "kms_key_id"             { type = string }
variable "allowed_security_group" { type = string }
variable "cloudmap_namespace_id"  { type = string }
variable "backup_retention_days" {
  type    = number
  default = 7
}
variable "db_name" {
  type    = string
  default = "authclaw"
}
variable "db_username" {
  type    = string
  default = "authclaw_app"
}
