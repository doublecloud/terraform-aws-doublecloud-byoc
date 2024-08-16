locals {
  region     = data.aws_region.current.name
  account_id = data.aws_caller_identity.self.account_id

  base_policy_arn = "arn:aws:iam::${local.account_id}:policy/DoubleCloud/"
  policy_names = {
    doublecloud                           = "import-${aws_vpc.doublecloud.id}"
    doublecloud_control_plane_EKS         = "import-${aws_vpc.doublecloud.id}-ControlPlaneEKS"
    permission_boundary                   = "import-${aws_vpc.doublecloud.id}-permission-boundary"
    permission_boundary_eks_cluster       = "import-${aws_vpc.doublecloud.id}-permission-boundary-eks-cluster"
    permission_boundary_eks_node          = "import-${aws_vpc.doublecloud.id}-permission-boundary-eks-node"
    permission_boundary_eks_node_platform = "import-${aws_vpc.doublecloud.id}-permission-boundary-eks-node-platform"
  }

  role_arn = "arn:aws:iam::${local.account_id}:role/DoubleCloud/import-${aws_vpc.doublecloud.id}"
}

resource "aws_iam_role" "doublecloud" {
  name = local.policy_names.doublecloud
  path = "/DoubleCloud/"

  description = "The role that DoubleCloud will assume"

  assume_role_policy   = data.aws_iam_policy_document.trusted_policy.json
  permissions_boundary = aws_iam_policy.doublecloud_permission_boundary.arn
  managed_policy_arns = [
    "${local.base_policy_arn}${local.policy_names.doublecloud}",
    "${local.base_policy_arn}${local.policy_names.doublecloud_control_plane_EKS}",
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
  name = local.policy_names.permission_boundary
  path = "/DoubleCloud/"

  policy = data.aws_iam_policy_document.doublecloud_permission_boundary.json
}

data "aws_iam_policy_document" "doublecloud_permission_boundary" {
  version = "2012-10-17"
  statement {
    effect = "Deny"
    actions = [
      "autoscaling:Create*",
      "autoscaling:Delete*",
      "autoscaling:Update*",
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
    effect = "Allow"
    actions = [
      "eks:*",
    ]
    resources = ["arn:aws:eks:${local.region}:${local.account_id}:*/DoubleCloud-Airflow-*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "elasticloadbalancing:Describe*",
      "elasticloadbalancing:Get*",
    ]
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
      test     = "StringNotLike"
      values   = ["${local.base_policy_arn}${local.policy_names.permission_boundary}*"]
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
    resources = ["${local.base_policy_arn}${local.policy_names.doublecloud}*"]
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
      test     = "StringLike"
      values   = ["${local.base_policy_arn}${local.policy_names.permission_boundary}*"]
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
  name = local.policy_names.doublecloud
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
      "ec2:CreateVpcEndpoint",
      "ec2:CreateLaunchTemplate",
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
      "arn:aws:ec2:${local.region}:${local.account_id}:vpc-endpoint/*",
      "arn:aws:ec2:${local.region}:${local.account_id}:launch-template/*",
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
        "CreateVpcEndpoint",
        "CreateLaunchTemplate",
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
    resources = ["${local.base_policy_arn}${local.policy_names.doublecloud}*"]
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
      test     = "StringLike"
      values   = ["${local.base_policy_arn}${local.policy_names.doublecloud}*"]
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
      test     = "StringNotLike"
      values   = ["${local.base_policy_arn}${local.policy_names.doublecloud}*"]
      variable = "iam:PermissionsBoundary"
    }
  }
}

resource "aws_iam_policy" "doublecloud_ControlPlaneEKS" {
  name = local.policy_names.doublecloud_control_plane_EKS
  path = "/DoubleCloud/"

  policy = data.aws_iam_policy_document.doublecloud_control_plane_EKS_permissions.json
}

data "aws_iam_policy_document" "doublecloud_control_plane_EKS_permissions" {
  version = "2012-10-17"

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
    effect = "Allow"
    actions = [
      "autoscaling:Describe*",
      "autoscaling:Get*",
    ]
    resources = ["*"]
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
    sid    = "EC2AllowAllDoubleCloudVPC"
    effect = "Allow"
    actions = [
      "ec2:*"
    ]
    resources = [aws_vpc.doublecloud.arn]
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
      variable = "aws:ResourceTag/atDoubleCloud"
    }
  }

  statement {
    sid    = "EC2AllowAllDoubleCloudNamed"
    effect = "Allow"
    actions = [
      "ec2:*"
    ]
    resources = ["*"]
    condition {
      test     = "StringLike"
      values   = ["DoubleCloud-Airflow*"]
      variable = "aws:ResourceTag/Name"
    }
  }

  statement {
    sid = "EKSFullAccessDoubleCloud"
    actions = [
      "eks:*",
    ]
    resources = ["arn:aws:eks:${local.region}:${local.account_id}:*/DoubleCloud-Airflow-*"]
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
    sid    = "DescribeElasticLoadBalancing"
    effect = "Allow"
    actions = [
      "elasticloadbalancing:Describe*",
      "elasticloadbalancing:Get*"
    ]
    resources = ["*"]
  }

  statement {
    sid = "EKSAllowPassRolesDoubleCloud"
    actions = [
      "iam:PassRole",
    ]
    effect    = "Allow"
    resources = ["arn:aws:iam::${local.account_id}:role/*"]
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
    sid    = "SLRValidation"
    effect = "Allow"
    actions = [
      "iam:GetRole",
    ]
    resources = ["arn:aws:iam::${local.account_id}:role/*"]
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

resource "aws_iam_policy" "doublecloud_permission_boundary_eks_cluster" {
  name = local.policy_names.permission_boundary_eks_cluster
  path = "/DoubleCloud/"

  policy = data.aws_iam_policy_document.doublecloud_permission_boundary_eks_cluster.json
}

data "aws_iam_policy_document" "doublecloud_permission_boundary_eks_cluster" {
  version = "2012-10-17"

  statement {
    sid    = "AmazonEKSClusterPolicyCreateDescribeV6"
    effect = "Allow"
    actions = [
      "autoscaling:DescribeAutoScalingGroups",
      "autoscaling:UpdateAutoScalingGroup",
      "ec2:AttachVolume",
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:Create*",
      "ec2:Describe*",
      "elasticloadbalancing:AddTags",
      "elasticloadbalancing:ApplySecurityGroupsToLoadBalancer",
      "elasticloadbalancing:AttachLoadBalancerToSubnets",
      "elasticloadbalancing:ConfigureHealthCheck",
      "elasticloadbalancing:Create*",
      "elasticloadbalancing:Describe*",
      "elasticloadbalancing:Register*",
      "elasticloadbalancing:SetLoadBalancerPoliciesForBackendServer",
      "elasticloadbalancing:SetLoadBalancerPoliciesOfListener",
      "kms:DescribeKey"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "AmazonEKSClusterPolicyModifyDeleteEC2V6"
    effect = "Allow"
    actions = [
      "ec2:DeleteRoute",
      "ec2:DeleteSecurityGroup",
      "ec2:DeleteVolume",
      "ec2:DetachVolume",
      "ec2:ModifyInstanceAttribute",
      "ec2:ModifyVolume",
      "ec2:RevokeSecurityGroupIngress",
    ]
    resources = ["*"]
    condition {
      test     = "StringLike"
      variable = "aws:ResourceTag/kubernetes.io/cluster/DoubleCloud-Airflow-*"
      values   = ["owned"]
    }
  }

  statement {
    sid    = "AmazonEKSClusterPolicyModifyDeleteELBV6"
    effect = "Allow"
    actions = [
      "elasticloadbalancing:DeleteListener",
      "elasticloadbalancing:DeleteLoadBalancer",
      "elasticloadbalancing:DeleteLoadBalancerListeners",
      "elasticloadbalancing:DeleteTargetGroup",
      "elasticloadbalancing:DeregisterInstancesFromLoadBalancer",
      "elasticloadbalancing:DeregisterTargets",
      "elasticloadbalancing:DetachLoadBalancerFromSubnets",
      "elasticloadbalancing:ModifyListener",
      "elasticloadbalancing:ModifyLoadBalancerAttributes",
      "elasticloadbalancing:ModifyTargetGroup",
      "elasticloadbalancing:ModifyTargetGroupAttributes",
    ]
    resources = ["*"]
    condition {
      test     = "StringLike"
      variable = "aws:ResourceTag/elbv2.k8s.aws/cluster"
      values   = ["DoubleCloud-Airflow-*"]
    }
  }

  statement {
    sid       = "AmazonEKSClusterPolicyCreateServiceLinkedRoleV6"
    effect    = "Allow"
    actions   = ["iam:CreateServiceLinkedRole"]
    resources = ["arn:aws:iam::*:role/aws-service-role/*"]
    condition {
      test     = "StringEquals"
      values   = ["elasticloadbalancing.amazonaws.com"]
      variable = "iam:AWSServiceName"
    }
  }
}

resource "aws_iam_policy" "doublecloud_permission_boundary_eks_node" {
  name = local.policy_names.permission_boundary_eks_node
  path = "/DoubleCloud/"

  policy = data.aws_iam_policy_document.doublecloud_permission_boundary_eks_node.json
}

data "aws_iam_policy_document" "doublecloud_permission_boundary_eks_node" {
  version = "2012-10-17"

  statement {
    sid    = "AmazonEC2ContainerRegistryReadOnlyV3"
    effect = "Allow"
    actions = [
      "ecr:BatchCheck*",
      "ecr:BatchGet*",
      "ecr:Describe*",
      "ecr:Get*",
      "ecr:List*",
    ]
    resources = ["*"]
  }
  statement {
    sid    = "AmazonEKSCNIPolicyCreateDescribeV5"
    effect = "Allow"
    actions = [
      "ec2:AssignPrivateIpAddresses",
      "ec2:AssignIpv6Addresses",
      "ec2:AttachNetworkInterface",
      "ec2:CreateNetworkInterface",
      "ec2:Describe*",
    ]
    resources = ["*"]
  }
  statement {
    sid    = "AmazonEKSCNIPolicyModifyDeleteV5"
    effect = "Allow"
    actions = [
      "ec2:DeleteNetworkInterface",
      "ec2:DetachNetworkInterface",
      "ec2:ModifyNetworkInterfaceAttribute",
      "ec2:UnassignPrivateIpAddresses"
    ]
    resources = ["*"]
    condition {
      test     = "StringLike"
      variable = "aws:ResourceTag/cluster.k8s.amazonaws.com/name"
      values   = ["DoubleCloud-Airflow-*"]
    }
  }
  statement {
    sid       = "AmazonEKSCNIPolicyTagsV5"
    effect    = "Allow"
    actions   = ["ec2:CreateTags"]
    resources = ["arn:aws:ec2:*:*:network-interface/*"]
  }
  statement {
    sid    = "AmazonEKSWorkerNodePolicyV3"
    effect = "Allow"
    actions = [
      "ec2:Describe*",
      "eks-auth:AssumeRoleForPodIdentity"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "doublecloud_permission_boundary_eks_node_platform" {
  name = local.policy_names.permission_boundary_eks_node_platform
  path = "/DoubleCloud/"

  policy = data.aws_iam_policy_document.doublecloud_permission_boundary_eks_node_platform.json
}

data "aws_iam_policy_document" "doublecloud_permission_boundary_eks_node_platform" {
  version = "2012-10-17"

  statement {
    sid    = "AmazonEC2ContainerRegistryReadOnlyV3"
    effect = "Allow"
    actions = [
      "ecr:BatchCheck*",
      "ecr:BatchGet*",
      "ecr:Describe*",
      "ecr:Get*",
      "ecr:List*",
    ]
    resources = ["*"]
  }
  statement {
    sid    = "AmazonEKSCNIPolicyCreateDescribeV5"
    effect = "Allow"
    actions = [
      "ec2:AssignPrivateIpAddresses",
      "ec2:AssignIpv6Addresses",
      "ec2:AttachNetworkInterface",
      "ec2:CreateNetworkInterface",
      "ec2:Describe*",
    ]
    resources = ["*"]
  }
  statement {
    sid    = "AmazonEKSCNIPolicyModifyDeleteV5"
    effect = "Allow"
    actions = [
      "ec2:DeleteNetworkInterface",
      "ec2:DetachNetworkInterface",
      "ec2:ModifyNetworkInterfaceAttribute",
      "ec2:UnassignPrivateIpAddresses"
    ]
    resources = ["*"]
    condition {
      test     = "StringLike"
      variable = "aws:ResourceTag/cluster.k8s.amazonaws.com/name"
      values   = ["DoubleCloud-Airflow-*"]
    }
  }
  statement {
    sid       = "AmazonEKSCNIPolicyTagsV5"
    effect    = "Allow"
    actions   = ["ec2:CreateTags"]
    resources = ["arn:aws:ec2:*:*:network-interface/*"]
  }
  statement {
    sid    = "AmazonEKSWorkerNodePolicyV3"
    effect = "Allow"
    actions = [
      "ec2:Describe*",
      "eks-auth:AssumeRoleForPodIdentity"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "AmazonEBSCSIDriverPolicyEC2CreateDescribeV2"
    effect = "Allow"
    actions = [
      "ec2:CreateSnapshot",
      "ec2:AttachVolume",
      "ec2:DetachVolume",
      "ec2:ModifyVolume",
      "ec2:Describe*",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "AmazonEBSCSIDriverPolicyEC2ModifyDeleteV2"
    effect = "Allow"
    actions = [
      "ec2:DetachVolume",
      "ec2:ModifyVolume",
    ]
    resources = ["*"]
    condition {
      test     = "StringLike"
      variable = "ec2:ResourceId"
      values   = ["vol-*DoubleCloud*"]
    }
  }
  statement {
    sid       = "AmazonEBSCSIDriverPolicyEC2CreateV2"
    effect    = "Allow"
    actions   = ["ec2:Create*"]
    resources = ["*"]
  }
  statement {
    sid     = "AmazonEBSCSIDriverPolicyEC2DeleteTagsV2"
    effect  = "Allow"
    actions = ["ec2:DeleteTags"]
    resources = [
      "arn:aws:ec2:*:*:volume/*",
      "arn:aws:ec2:*:*:snapshot/*"
    ]
    condition {
      test     = "StringLike"
      values   = ["DoubleCloud-Airflow-*"]
      variable = "ec2:ResourceTag/KubernetesCluster"
    }
  }
  statement {
    sid       = "AmazonEBSCSIDriverPolicyEC2DeleteVolumeV2"
    effect    = "Allow"
    actions   = ["ec2:DeleteVolume"]
    resources = ["*"]
    condition {
      test     = "StringLike"
      values   = ["DoubleCloud-Airflow-*"]
      variable = "ec2:ResourceTag/KubernetesCluster"
    }
    condition {
      test     = "StringLike"
      values   = ["true"]
      variable = "ec2:ResourceTag/ebs.csi.aws.com/cluster"
    }
    condition {
      test     = "StringLike"
      values   = ["*"]
      variable = "ec2:ResourceTag/CSIVolumeName"
    }
    condition {
      test     = "StringLike"
      values   = ["*"]
      variable = "ec2:ResourceTag/kubernetes.io/created-for/pvc/name"
    }
  }
  statement {
    sid       = "AmazonEBSCSIDriverPolicyEC2DeleteSnapshotV2"
    effect    = "Allow"
    actions   = ["ec2:DeleteSnapshot"]
    resources = ["*"]
    condition {
      test     = "StringLike"
      values   = ["DoubleCloud-Airflow-*"]
      variable = "ec2:ResourceTag/KubernetesCluster"
    }
    condition {
      test     = "StringLike"
      values   = ["*"]
      variable = "ec2:ResourceTag/CSIVolumeSnapshotName"
    }
    condition {
      test     = "StringLike"
      values   = ["true"]
      variable = "ec2:ResourceTag/ebs.csi.aws.com/cluster"
    }
  }
  statement {
    sid = "DCNodeAutoScalerDescribeGet"
    actions = [
      "ec2:Describe*",
      "ec2:Get*",
      "autoscaling:Describe*",
    ]
    effect    = "Allow"
    resources = ["*"]
  }
  statement {
    sid = "DCNodeAutoScalerTerminateSet"
    actions = [
      "autoscaling:TerminateInstanceInAutoScalingGroup",
      "autoscaling:SetDesiredCapacity"
    ]
    effect = "Allow"
    resources = [
      "arn:aws:autoscaling:${local.region}:${local.account_id}:autoScalingGroup:*:autoScalingGroupName/*"
    ]
  }
}
