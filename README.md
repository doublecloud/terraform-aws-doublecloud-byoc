# DoubleCloud AWS Bring Your Own Cloud terraform module

Terraform module which creates AWS resources to bring them into DoubleCloud.

## Usage
```hcl
module "byoc" {
  source = "doublecloud/doublecloud-byoc/aws"

  ipv4_cidr = "196.168.42.0/24"
}

resource "doublecloud_network" "aws" {
  project_id = var.project_id
  name = "my-aws-network"
  region_id  = module.byoc.region_id
  cloud_type = "aws"
  aws = {
    vpc_id       = module.byoc.vpc_id
    account_id   = module.byoc.account_id
    iam_role_arn = module.byoc.iam_role_arn
  }
}
```

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.2.6 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 4.51.0 |
| <a name="requirement_time"></a> [time](#requirement\_time) | >= 0.9.1 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 4.51.0 |
| <a name="provider_time"></a> [time](#provider\_time) | >= 0.9.1 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [aws_iam_policy.doublecloud](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_role.doublecloud](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_vpc.doublecloud](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc) | resource |
| [time_sleep.sleep_to_avoid_iam_race](https://registry.terraform.io/providers/hashicorp/time/latest/docs/resources/sleep) | resource |
| [aws_caller_identity.self](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_iam_policy_document.doublecloud_permissions](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.trusted_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_doublecloud_controlplane_account_id"></a> [doublecloud\_controlplane\_account\_id](#input\_doublecloud\_controlplane\_account\_id) | leave as default | `string` | `"883433064081"` | no |
| <a name="input_ipv4_cidr"></a> [ipv4\_cidr](#input\_ipv4\_cidr) | Valid IPv4 CIDR block for VPC | `string` | `"10.10.0.0/16"` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_account_id"></a> [account\_id](#output\_account\_id) | AWS Account ID where resources will be created. |
| <a name="output_iam_role_arn"></a> [iam\_role\_arn](#output\_iam\_role\_arn) | ARN of the IAM Role that has permissions to create resources in the VPC. |
| <a name="output_region_id"></a> [region\_id](#output\_region\_id) | AWS Region where resources will be created. |
| <a name="output_vpc_id"></a> [vpc\_id](#output\_vpc\_id) | ID of the created VPC. DoubleCloud resources will be created in this VPC. |
<!-- END_TF_DOCS -->