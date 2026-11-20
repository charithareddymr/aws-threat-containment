variable "aws_region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Name prefix for every resource."
  type        = string
  default     = "gd-auto-response"
}

variable "alert_email" {
  description = "Email address that receives finding notifications (you must confirm the subscription email)."
  type        = string
}

variable "severity_threshold" {
  description = "Only findings with severity >= this value trigger the response (GuardDuty: 7-8.9 = High, 9-10 = Critical)."
  type        = number
  default     = 7

  validation {
    condition     = var.severity_threshold >= 1 && var.severity_threshold <= 10
    error_message = "severity_threshold must be between 1 and 10."
  }
}

variable "dry_run" {
  description = "When true, the Lambda only reports what it would do and changes nothing."
  type        = bool
  default     = true
}

variable "snapshot_volumes" {
  description = "Take forensic EBS snapshots of an isolated instance."
  type        = bool
  default     = true
}

variable "create_guardduty_detector" {
  description = "Set to false if GuardDuty is already enabled in this region (only one detector per region is allowed)."
  type        = bool
  default     = true
}

variable "enable_test_events" {
  description = "Also accept hand-made test events from the source 'custom.gd-auto-response.test'."
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for the Lambda."
  type        = number
  default     = 365
}
