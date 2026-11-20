# One customer-managed key encrypts the SNS topic, the dead-letter queue,
# the Lambda log group and the Lambda's environment variables.

data "aws_iam_policy_document" "kms" {
  #checkov:skip=CKV_AWS_109:Key policy - "*" resource means "this key" only.
  #checkov:skip=CKV_AWS_111:Key policy - "*" resource means "this key" only.
  #checkov:skip=CKV_AWS_356:Key policy - "*" resource means "this key" only.
  #checkov:skip=CKV_AWS_355:Key policy - "*" resource means "this key" only.
  #checkov:skip=CKV_AWS_289:Key policy - "*" resource means "this key" only.
  #checkov:skip=CKV_AWS_290:Key policy - "*" resource means "this key" only.

  statement {
    sid       = "AccountAdministration"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
  }

  statement {
    sid    = "CloudWatchLogsUse"
    effect = "Allow"
    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*",
    ]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["logs.${local.region}.amazonaws.com"]
    }

    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${local.region}:${local.account_id}:log-group:/aws/lambda/${var.project_name}"]
    }
  }

  statement {
    sid       = "EventBridgeDeadLetterQueueUse"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_kms_key" "this" {
  description             = "${var.project_name}: encrypts alerts, dead-letter queue, logs and Lambda settings"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.kms.json
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.project_name}"
  target_key_id = aws_kms_key.this.key_id
}
