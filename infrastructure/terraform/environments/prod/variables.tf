variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "environment" {
  type    = string
  default = "prod"
}

variable "alert_email" {
  type        = string
  description = "Email address to receive CloudWatch alarm and backup validation notifications"
}
