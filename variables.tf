variable "namePrefix" {
  description = ""
  type        = string
}

variable "notifications_arn" {
  description = ""
  type        = string
}

variable "backups" {
  description = ""
}

variable "kms_key_arn" { default = null }

variable "kms_multi_region" { default = false }