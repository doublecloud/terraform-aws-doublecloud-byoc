variable "ipv4_cidr" {
  type        = string
  description = "Valid IPv4 CIDR block for VPC"
  default     = "10.10.0.0/16"
}

variable "doublecloud_controlplane_account_id" {
  type        = string
  description = "leave as default"
  default     = "883433064081"
}
