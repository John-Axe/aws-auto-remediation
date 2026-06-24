variable "aws_region" {
  description = "AWS region to deploy the remediation stack into."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Prefix used for naming all resources created by this stack."
  type        = string
  default     = "auto-remediation"
}

variable "dry_run" {
  description = "When true, the Lambda logs and notifies what it would change without mutating any resource."
  type        = bool
  default     = true
}

variable "log_level" {
  description = "Python logging level for the Lambda function."
  type        = string
  default     = "INFO"
}

variable "log_retention_days" {
  description = "Retention, in days, for the Lambda's CloudWatch Logs log group."
  type        = number
  default     = 365
}

variable "notification_email" {
  description = "Optional email address to subscribe to the SNS notification topic. Leave empty to skip."
  type        = string
  default     = ""
}

variable "create_demo_bucket" {
  description = "If true, creates a private demo S3 bucket for use in live demonstrations of the remediation flow."
  type        = bool
  default     = false
}
