resource "aws_iam_user" "github_actions" {
  name = "${var.environment}-github-actions-user"
  tags = {
    Environment = var.environment
  }
}

resource "aws_iam_user_policy" "github_actions_policy" {
  name   = "${var.environment}-github-actions-policy"
  user   = aws_iam_user.github_actions.name
  policy = data.aws_iam_policy_document.github_actions_policy.json
}

data "aws_iam_policy_document" "github_actions_policy" {
  statement {
    sid    = "EC2Permissions"
    effect = "Allow"
    actions = [
      "ec2:Describe*",
      "ec2:RunInstances",
      "ec2:TerminateInstances",
      "ec2:CreateTags",
      "ec2:ModifyInstanceAttribute",
      "ec2:StartInstances",
      "ec2:StopInstances"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "ECRPermissions"
    effect = "Allow"
    actions = [
      "ecr:GetAuthorizationToken",
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:GetRepositoryPolicy",
      "ecr:DescribeRepositories",
      "ecr:ListImages",
      "ecr:DescribeImages",
      "ecr:BatchGetImage",
      "ecr:InitiateLayerUpload",
      "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload",
      "ecr:PutImage",
      "ecr:CreateRepository",
      "ecr:DeleteRepository"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "S3Permissions"
    effect = "Allow"
    actions = [
      "s3:CreateBucket",
      "s3:DeleteBucket",
      "s3:PutObject",
      "s3:GetObject",
      "s3:DeleteObject",
      "s3:ListBucket",
      "s3:PutBucketPolicy"
    ]
    resources = ["arn:aws:s3:::${var.environment}-app-bucket*"]
  }

  statement {
    sid    = "RDSPermissions"
    effect = "Allow"
    actions = [
      "rds:CreateDBInstance",
      "rds:DeleteDBInstance",
      "rds:DescribeDBInstances",
      "rds:ModifyDBInstance",
      "rds:CreateDBSubnetGroup",
      "rds:DeleteDBSubnetGroup",
      "rds:DescribeDBSubnetGroups"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "SecretsManagerPermissions"
    effect = "Allow"
    actions = [
      "secretsmanager:CreateSecret",
      "secretsmanager:DeleteSecret",
      "secretsmanager:DescribeSecret",
      "secretsmanager:PutSecretValue",
      "secretsmanager:GetSecretValue"
    ]
    resources = ["arn:aws:secretsmanager:*:*:secret:${var.environment}-app-secrets*"]
  }

  statement {
    sid    = "CloudWatchPermissions"
    effect = "Allow"
    actions = [
      "cloudwatch:PutMetricAlarm",
      "cloudwatch:DeleteAlarms",
      "cloudwatch:DescribeAlarms",
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DeleteLogGroup"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "SSMPermissions"
    effect = "Allow"
    actions = [
      "ssm:SendCommand",
      "ssm:GetCommandInvocation",
      "ssm:DescribeInstanceInformation"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "IAMPassRole"
    effect = "Allow"
    actions = [
      "iam:PassRole"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_access_key" "github_actions_key" {
  user = aws_iam_user.github_actions.name
}

output "access_key_id" {
  value     = aws_iam_access_key.github_actions_key.id
  sensitive = true
}

output "secret_access_key" {
  value     = aws_iam_access_key.github_actions_key.secret
  sensitive = true
}