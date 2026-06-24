# KMS key policies are scoped to "this key" by convention, so Resource "*"
# here is the standard AWS pattern (the resource is implicit -- the key the
# policy is attached to) and is not a broad grant across other resources.
data "aws_iam_policy_document" "logs_key" {
  #checkov:skip=CKV_AWS_109:Resource "*" in a KMS key policy refers to the key the policy is attached to, not all resources.
  #checkov:skip=CKV_AWS_111:Resource "*" in a KMS key policy refers to the key the policy is attached to, not all resources.
  #checkov:skip=CKV_AWS_356:Resource "*" in a KMS key policy refers to the key the policy is attached to, not all resources.
  statement {
    sid       = "AllowRootAccountFullAccess"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid    = "AllowCloudWatchLogsEncryption"
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
      identifiers = ["logs.${var.aws_region}.amazonaws.com"]
    }
  }

  statement {
    sid       = "AllowSnsEncryption"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey*", "kms:Decrypt*"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["sns.amazonaws.com"]
    }
  }
}

resource "aws_kms_key" "remediation" {
  description             = "Encrypts logs and SNS notifications for ${var.project_name}."
  deletion_window_in_days = 7
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.logs_key.json
}

resource "aws_kms_alias" "remediation" {
  name          = "alias/${var.project_name}"
  target_key_id = aws_kms_key.remediation.key_id
}
