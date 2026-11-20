# Least-privilege role for the response Lambda: it can do exactly what the
# code needs and nothing else.

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda" {
  name               = "${var.project_name}-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "lambda" {
  #checkov:skip=CKV_AWS_356:Describe* and X-Ray write actions do not support resource-level permissions.
  #checkov:skip=CKV_AWS_355:Describe* and X-Ray write actions do not support resource-level permissions.
  #checkov:skip=CKV_AWS_111:Write actions are scoped to resource ARNs; only X-Ray needs "*".
  #checkov:skip=CKV_AWS_290:Write actions are scoped to resource ARNs; only X-Ray needs "*".

  # Write its own logs.
  statement {
    sid       = "Logs"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.lambda.arn}:*"]
  }

  # Read-only lookups. These EC2 actions cannot be limited to specific resources.
  statement {
    sid       = "DescribeEc2"
    effect    = "Allow"
    actions   = ["ec2:DescribeInstances", "ec2:DescribeSecurityGroups"]
    resources = ["*"]
  }

  # Create the quarantine security group and remove its outbound rules.
  statement {
    sid     = "QuarantineSecurityGroup"
    effect  = "Allow"
    actions = ["ec2:CreateSecurityGroup", "ec2:RevokeSecurityGroupEgress"]
    resources = [
      "arn:aws:ec2:${local.region}:${local.account_id}:security-group/*",
      "arn:aws:ec2:${local.region}:${local.account_id}:vpc/*",
    ]
  }

  # Swap the instance's security groups for the quarantine group.
  statement {
    sid     = "IsolateInstance"
    effect  = "Allow"
    actions = ["ec2:ModifyInstanceAttribute"]
    resources = [
      "arn:aws:ec2:${local.region}:${local.account_id}:instance/*",
      "arn:aws:ec2:${local.region}:${local.account_id}:security-group/*",
    ]
  }

  # Forensic snapshots of the instance's volumes.
  statement {
    sid     = "ForensicSnapshots"
    effect  = "Allow"
    actions = ["ec2:CreateSnapshot"]
    resources = [
      "arn:aws:ec2:${local.region}:${local.account_id}:volume/*",
      "arn:aws:ec2:${local.region}::snapshot/*",
    ]
  }

  # Tag what it touched (instance, quarantine group, snapshots).
  statement {
    sid     = "Tagging"
    effect  = "Allow"
    actions = ["ec2:CreateTags"]
    resources = [
      "arn:aws:ec2:${local.region}:${local.account_id}:instance/*",
      "arn:aws:ec2:${local.region}:${local.account_id}:security-group/*",
      "arn:aws:ec2:${local.region}::snapshot/*",
    ]
  }

  # Deactivate (never delete) a compromised IAM user access key.
  statement {
    sid       = "DeactivateAccessKey"
    effect    = "Allow"
    actions   = ["iam:UpdateAccessKey"]
    resources = ["arn:aws:iam::${local.account_id}:user/*"]
  }

  statement {
    sid       = "PublishAlerts"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }

  statement {
    sid       = "DeadLetterQueue"
    effect    = "Allow"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dlq.arn]
  }

  # Use the project key for the encrypted topic, queue and environment variables.
  statement {
    sid       = "UseProjectKey"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey*", "kms:Decrypt"]
    resources = [aws_kms_key.this.arn]
  }

  statement {
    sid       = "Tracing"
    effect    = "Allow"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "lambda" {
  name   = "${var.project_name}-lambda"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda.json
}
