locals {
  region     = data.aws_region.current.name
  account_id = data.aws_caller_identity.self.account_id

  policy_arns = {
    doublecloud                 = "arn:aws:iam::${local.account_id}:policy/DoubleCloud/import-${aws_vpc.doublecloud.id}"
    doublecloud_controlPlaneEKS = "arn:aws:iam::${local.account_id}:policy/DoubleCloud/import-${aws_vpc.doublecloud.id}-ControlPlaneEKS"
    permission_boundary         = "arn:aws:iam::${local.account_id}:policy/DoubleCloud/import-${aws_vpc.doublecloud.id}-permission-boundary"
  }
  role_arn = "arn:aws:iam::${local.account_id}:role/DoubleCloud/import-${aws_vpc.doublecloud.id}"
}

resource "aws_iam_role" "doublecloud" {
  name = "import-${aws_vpc.doublecloud.id}"
  path = "/DoubleCloud/"

  description = "The role that DoubleCloud will assume"

  assume_role_policy   = data.aws_iam_policy_document.trusted_policy.json
  permissions_boundary = aws_iam_policy.doublecloud_permission_boundary.arn
  managed_policy_arns = [
    aws_iam_policy.doublecloud.arn,
    aws_iam_policy.doublecloud_controlPlaneEKS.arn
  ]
}

data "aws_iam_policy_document" "trusted_policy" {
  version = "2012-10-17"
  statement {
    sid    = "DoubleCloudCanAssumeThisRole"
    effect = "Allow"
    principals {
      identifiers = [
        "arn:aws:iam::${var.doublecloud_controlplane_account_id}:role/DoubleCloud/ControlPlane"
      ]
      type = "AWS"
    }
    actions = [
      "sts:AssumeRole"
    ]
  }
}

resource "aws_iam_policy" "doublecloud_permission_boundary" {
  name = "import-${aws_vpc.doublecloud.id}-permission-boundary"
  path = "/DoubleCloud/"

  policy = data.aws_iam_policy_document.doublecloud_permission_boundary.json
}

data "aws_iam_policy_document" "doublecloud_permission_boundary" {
  version = "2012-10-17"

  statement {
    effect = "Deny"
    actions = [
      "autoscaling:*",
    ]
    resources = ["*"]
    condition {
      test     = "StringNotEquals"
      values   = ["doublecloud-platform"]
      variable = "aws:ResourceTag/eks:nodegroup-name"
    }
  }

  statement {
    effect = "Allow"
    actions = [
      "autoscaling:*",
    ]
    resources = ["*"]
  }

  statement {
    effect = "Deny"
    actions = [
      "ec2:CreateVpc",
      "ec2:DeleteVpc",
    ]
    resources = ["*"]
  }

  statement {
    effect    = "Allow"
    actions   = ["ec2:*"]
    resources = ["*"]
  }

  statement {
    effect = "Deny"
    actions = [
      "iam:PutUserPermissionsBoundary",
      "iam:PutRolePermissionsBoundary",
      "iam:CreateUser",
      "iam:CreateRole",
    ]
    resources = [
      "arn:aws:iam::${local.account_id}:user/*",
      "arn:aws:iam::${local.account_id}:role/*",
    ]
    condition {
      test     = "StringNotEquals"
      values   = [local.policy_arns[permissions_boundary]]
      variable = "iam:PermissionsBoundary"
    }
  }

  statement {
    effect = "Deny"
    actions = [
      "iam:DeletePolicy",
      "iam:DeletePolicyVersion",
      "iam:CreatePolicyVersion",
      "iam:SetDefaultPolicyVersion",
    ]
    resources = [
      local.policy_arns[doublecloud],
      local.policy_arns[doublecloud_controlPlaneEKS]
    ]
  }

  statement {
    effect = "Deny"
    actions = [
      "iam:DeleteUserPermissionsBoundary",
      "iam:DeleteRolePermissionsBoundary",
    ]
    resources = [
      "arn:aws:iam::${local.account_id}:user/*",
      "arn:aws:iam::${local.account_id}:role/*",
    ]
    condition {
      test     = "StringEquals"
      values   = [local.policy_arns[permissions_boundary]]
      variable = "iam:PermissionsBoundary"
    }
  }

  statement {
    effect    = "Allow"
    actions   = ["iam:*"]
    resources = ["*"]
  }

  statement {
    effect    = "Allow"
    actions   = ["kms:CreateAlias"]
    resources = ["*"]
  }

  statement {
    effect    = "Allow"
    actions   = ["ram:*"]
    resources = ["*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "route53:AssociateVPCWithHostedZone",
      "route53:DisassociateVPCFromHostedZone",
    ]
    resources = ["*"]
  }

  statement {
    effect    = "Allow"
    actions   = ["sts:AssumeRole"]
    resources = ["*"]
  }

  statement {
    actions   = ["*"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      values   = ["true"]
      variable = "aws:ResourceTag/AtDoubleCloud"
    }
  }
}

resource "aws_iam_policy" "doublecloud" {
  name = "import-${aws_vpc.doublecloud.id}"
  path = "/DoubleCloud/"

  policy = data.aws_iam_policy_document.doublecloud_permissions.json
}

data "aws_iam_policy_document" "doublecloud_permissions" {
  version = "2012-10-17"

  statement {
    effect = "Deny"
    actions = [
      "ec2:CreateVpc",
      "ec2:DeleteVpc",
    ]
    resources = ["*"]
  }

  statement {
    effect    = "Allow"
    actions   = ["ec2:Describe*"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      values   = [local.region]
      variable = "ec2:Region"
    }
  }

  statement {
    effect = "Allow"
    actions = [
      "ec2:CreateTransitGatewayVpcAttachment",
      "ec2:CreateSubnet",
      "ec2:CreateSecurityGroup",
      "ec2:CreateNetworkInterface",
      "ec2:CreateVolume",
      "ec2:CreateInternetGateway",
      "ec2:CreateEgressOnlyInternetGateway",
      "ec2:CreateNatGateway",
      "ec2:AllocateAddress",
      "ec2:CreateRouteTable",
    ]
    resources = [
      "arn:aws:ec2:${local.region}:${var.doublecloud_controlplane_account_id}:transit-gateway/*",
      "arn:aws:ec2:${local.region}:${local.account_id}:transit-gateway-attachment/*",
      "arn:aws:ec2:${local.region}:${local.account_id}:subnet/*",
      "arn:aws:ec2:${local.region}:${local.account_id}:security-group/*",
      "arn:aws:ec2:${local.region}:${local.account_id}:network-interface/*",
      "arn:aws:ec2:${local.region}:${local.account_id}:volume/*",
      "arn:aws:ec2:${local.region}:${local.account_id}:internet-gateway/*",
      "arn:aws:ec2:${local.region}:${local.account_id}:egress-only-internet-gateway/*",
      "arn:aws:ec2:${local.region}:${local.account_id}:natgateway/*",
      "arn:aws:ec2:${local.region}:${local.account_id}:elastic-ip/*",
      "arn:aws:ec2:${local.region}:${local.account_id}:route-table/*",
    ]
  }

  statement {
    effect    = "Allow"
    actions   = ["ec2:*"]
    resources = [aws_vpc.doublecloud.arn]
  }

  statement {
    effect    = "Allow"
    actions   = ["ec2:*"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      values   = [aws_vpc.doublecloud.arn]
      variable = "ec2:Vpc"
    }
  }

  statement {
    effect  = "Allow"
    actions = ["ec2:*"]
    resources = [
      "arn:aws:ec2:${local.region}:${local.account_id}:*/*",
      "arn:aws:ec2:${local.region}::*/*",
    ]
    condition {
      test     = "StringEquals"
      values   = ["true"]
      variable = "aws:ResourceTag/AtDoubleCloud"
    }
  }

  statement {
    effect    = "Allow"
    actions   = ["ec2:CreateTags"]
    resources = ["*"]
    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "ec2:CreateAction"
      values = [
        "RunInstances",
        "CreateVolume",
        "CreateNetworkInterface",
        "CreateVpc",
        "CreateInternetGateway",
        "CreateSubnet",
        "CreateTransitGatewayVpcAttachment",
        "CreateSecurityGroup",
        "CreateVpcPeeringConnection",
        "CreateEgressOnlyInternetGateway",
        "CreateNatGateway",
        "AllocateAddress",
        "CreateRouteTable",
      ]
    }
  }

  statement {
    effect = "Allow"
    actions = [
      "ec2:CreateVpcPeeringConnection",
      "ec2:DeleteVpcPeeringConnection",
    ]
    resources = ["arn:aws:ec2:${local.region}:${local.account_id}:vpc-peering-connection/*"]
    condition {
      test     = "StringEquals"
      values   = [aws_vpc.doublecloud.arn]
      variable = "ec2:RequesterVpc"
    }
  }

  statement {
    effect    = "Allow"
    actions   = ["iam:SimulatePrincipalPolicy"]
    resources = [local.role_arn]
  }

  statement {
    effect    = "Allow"
    actions   = ["ram:AcceptResourceShareInvitation"]
    resources = ["*"]
    condition {
      test     = "ForAnyValue:StringEquals"
      values   = [var.doublecloud_controlplane_account_id]
      variable = "ram:ShareOwnerAccountId"
    }
  }

  statement {
    effect    = "Allow"
    actions   = ["ram:GetResourceShareInvitations"]
    resources = ["*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "route53:AssociateVPCWithHostedZone",
      "route53:DisassociateVPCFromHostedZone",
    ]
    resources = ["*"]
  }

  statement {
    effect  = "Allow"
    actions = ["s3:*"]
    resources = [
      "arn:aws:s3:::double-cloud-*",
      "arn:aws:s3:::double-cloud-*/*"
    ]
  }

  statement {
    effect    = "Allow"
    actions   = ["iam:PassRole"]
    resources = ["arn:aws:iam::${local.account_id}:role/DoubleCloud/clusters/*"]
  }

  statement {
    effect    = "Allow"
    actions   = ["ec2:AssociateIamInstanceProfile"]
    resources = ["arn:aws:ec2:${local.region}:${local.account_id}:instance/*"]
    condition {
      test     = "StringLike"
      values   = ["arn:aws:iam::${local.account_id}:instance-profile/DoubleCloud/clusters/*"]
      variable = "ec2:InstanceProfile"
    }
  }

  statement {
    effect  = "Allow"
    actions = ["ec2:RunInstances"]
    resources = [
      "arn:aws:ec2:${local.region}:${local.account_id}:instance/*",
      "arn:aws:ec2:${local.region}:${local.account_id}:volume/*",
      "arn:aws:ec2:${local.region}::image/*",
    ]
  }

  statement {
    effect  = "Allow"
    actions = ["iam:*"]
    resources = [
      "arn:aws:iam::${local.account_id}:user/DoubleCloud/*",
      "arn:aws:iam::${local.account_id}:role/DoubleCloud/*",
      "arn:aws:iam::${local.account_id}:instance-profile/DoubleCloud/*",
      "arn:aws:iam::${local.account_id}:policy/DoubleCloud/*",
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "iam:*",
      "kms:*",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      values   = ["true"]
      variable = "aws:ResourceTag/AtDoubleCloud"
    }
  }

  statement {
    effect    = "Allow"
    actions   = ["kms:CreateAlias"]
    resources = ["arn:aws:kms:${local.region}:${local.account_id}:alias/*"]
  }

  statement {
    effect    = "Allow"
    actions   = ["sts:AssumeRole"]
    resources = ["*"]
  }

  statement {
    effect    = "Allow"
    actions   = ["iam:CreateServiceLinkedRole"]
    resources = ["arn:aws:iam::*:role/aws-service-role/*"]
  }

  statement {
    effect = "Deny"
    actions = [
      "iam:DeletePolicy",
      "iam:DeletePolicyVersion",
      "iam:CreatePolicyVersion",
      "iam:SetDefaultPolicyVersion",
    ]
    resources = [local.policy_arns[doublecloud]]
  }

  statement {
    effect = "Deny"
    actions = [
      "iam:DeleteUserPermissionsBoundary",
      "iam:DeleteRolePermissionsBoundary",
    ]
    resources = [
      "arn:aws:iam::${local.account_id}:user/*",
      "arn:aws:iam::${local.account_id}:role/*",
    ]
    condition {
      test     = "StringEquals"
      values   = [local.policy_arns[doublecloud_permission_boundary]]
      variable = "iam:PermissionsBoundary"
    }
  }

  statement {
    effect = "Deny"
    actions = [
      "iam:PutUserPermissionsBoundary",
      "iam:PutRolePermissionsBoundary",
      "iam:CreateUser",
      "iam:CreateRole",
    ]
    resources = [
      "arn:aws:iam::${local.account_id}:user/*",
      "arn:aws:iam::${local.account_id}:role/*",
    ]
    condition {
      test     = "StringNotEquals"
      values   = [local.policy_arns[doublecloud_permission_boundary]]
      variable = "iam:PermissionsBoundary"
    }
  }
}

resource "aws_iam_policy" "doublecloud_ControlPlaneEKS" {
  name = "import-${aws_vpc.doublecloud.id}-ControlPlaneEKS"
  path = "/DoubleCloud/"

  policy = data.aws_iam_policy_document.doublecloud_ControlPlaneEKS_permissions.json
}

data "aws_iam_policy_document" "doublecloud_ControlPlaneEKS_permissions" {
  version = "2012-10-17"

  statement {
    sid = "EKSFullAccessDoubleCloud"
    actions = [
      "eks:*",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      values   = ["true"]
      variable = "aws:ResourceTag/AtDoubleCloud"
    }
  }

  statement {
    sid = "EKSAllowPassRolesDoubleCloud"
    actions = [
      "iam:PassRole",
    ]
    effect    = "Allow"
    resources = ["arn:aws:iam::${local.account_id}:role/DoubleCloud/*"]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["eks.amazonaws.com"]
    }
  }

  statement {
    sid    = "EKSNodeGroupIAMPolicyDoubleCloud"
    effect = "Allow"
    actions = [
      "iam:GetRole",
      "iam:ListAttachedRolePolicies",
    ]
    resources = ["arn:aws:iam::${local.account_id}:role/DoubleCloud/*"]
  }

  statement {
    sid       = "EKSAllowCreateServiceLinkedRole"
    effect    = "Allow"
    resources = ["*"]
    actions = [
      "iam:CreateServiceLinkedRole"
    ]
    condition {
      test     = "StringEquals"
      variable = "iam:AWSServiceName"
      values = [
        "autoscaling.amazonaws.com",
        "ec2scheduled.amazonaws.com",
        "elasticloadbalancing.amazonaws.com",
        "eks.amazonaws.com",
        "eks-fargate-pods.amazonaws.com",
        "eks-nodegroup.amazonaws.com",
        "spot.amazonaws.com",
        "spotfleet.amazonaws.com",
        "transitgateway.amazonaws.com"
      ]
    }
  }

  statement {
    sid    = "EC2AllowAllDoubleCloudVPC"
    effect = "Allow"
    actions = [
      "ec2:*"
    ]
    resources = [aws_vpc.doublecloud.arn]
  }

  statement {
    sid    = "EC2AllowAllWithinDoubleCloudVPC"
    effect = "Allow"
    actions = [
      "ec2:*"
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      values   = [aws_vpc.doublecloud.arn]
      variable = "ec2:Vpc"
    }
  }

  statement {
    sid    = "EC2AllowAllDoubleCloud"
    effect = "Allow"
    actions = [
      "ec2:*"
    ]
    resources = [
      "arn:aws:ec2:${local.region}:${local.account_id}:*/*",
      "arn:aws:ec2:${local.region}::*/*",
    ]
    condition {
      test     = "StringEquals"
      values   = ["true"]
      variable = "aws:ResourceTag/AtDoubleCloud"
    }
  }

  statement {
    sid    = "AutoscalingAllowAllControlplaneEKS"
    effect = "Allow"
    actions = [
      "autoscaling:*",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      values   = ["doublecloud-platform"]
      variable = "aws:ResourceTag/eks:nodegroup-name"
    }
  }

  statement {
    sid    = "ElasticLoadBalancingAllowAllDoubleCloud"
    effect = "Allow"
    actions = [
      "elasticloadbalancing:*"
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      values   = ["true"]
      variable = "aws:ResourceTag/AtDoubleCloud"
    }
  }

  statement {
    sid    = "ACMAccessDoubleCloud"
    effect = "Allow"
    actions = [
      "acm:RequestCertificate",
      "acm:DescribeCertificate",
      "acm:ListCertificates",
      "acm:DeleteCertificate",
      "acm:ListTagsForCertificate",
      "acm:AddTagsToCertificate",
      "acm:RemoveTagsFromCertificate",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      values   = ["true"]
      variable = "aws:ResourceTag/AtDoubleCloud"
    }
  }

  statement {
    sid    = "RDSAccessDoubleCloud"
    effect = "Allow"
    actions = [
      "rds:AddTagsToResource",

      "rds:DescribeDBSubnetGroups",
      "rds:DescribeDBClusters",
      "rds:DescribeDBInstances",

      "rds:CreateDBInstance",
      "rds:CreateDBCluster",
      "rds:DeleteDBInstance",
      "rds:DeleteDBCluster",

      "rds:StartDBInstance",
      "rds:StartDBCluster",
      "rds:StopDBInstance",
      "rds:StopDBCluster",

      "rds:CreateDBSubnetGroup",
      "rds:DeleteDBSubnetGroup",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      values   = ["true"]
      variable = "aws:ResourceTag/AtDoubleCloud"
    }
  }
}

# AWS IAM returns AccessDenied error right after Role creation.
# We have to wait some time to make this role assumable.
# https://github.com/hashicorp/terraform-provider-aws/issues/6566
resource "time_sleep" "sleep_to_avoid_iam_race" {
  depends_on      = [aws_iam_role.doublecloud]
  create_duration = "30s"
}
