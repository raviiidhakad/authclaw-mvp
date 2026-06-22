variable "environment"              { type = string }
variable "vpc_id"                   { type = string }
variable "subnet_ids"               { type = list(string) }
variable "kms_key_id"               { type = string }
variable "allowed_security_group"   { type = string }
variable "cloudmap_namespace_id"    { type = string }
variable "serverless"               {
  type    = bool
  default = false
}
variable "broker_instance_type"     {
  type    = string
  default = "kafka.m5.large"
}
variable "number_of_broker_nodes"   {
  type    = number
  default = 3
}
