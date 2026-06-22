variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "environment" {
  type    = string
  default = "staging"
}

variable "alert_email" {
  type        = string
  description = "Email address to receive CloudWatch alarm notifications"
  default     = ""
}
