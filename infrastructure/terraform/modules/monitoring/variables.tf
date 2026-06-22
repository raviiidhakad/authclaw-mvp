variable "environment"    { type = string }
variable "db_identifier"  { type = string }
variable "redis_id"       { type = string }
variable "alb_arn_suffix" { type = string }
variable "sns_email"      {
  type    = string
  default = ""
}
