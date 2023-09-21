resource "aws_vpc" "doublecloud" {
  cidr_block                       = var.ipv4_cidr
  assign_generated_ipv6_cidr_block = true
  enable_dns_hostnames             = true
  enable_dns_support               = true
}
