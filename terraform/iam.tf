data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "remediator" {
  name               = "${var.project_name}-remediator"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

# Least-privilege policy: only the specific actions each remediation module
# needs, scoped to the narrowest resource type that AWS supports for that
# action. S3 bucket-level actions and several EC2 actions (security groups,
# tag/describe APIs) do not support resource-level restriction beyond the
# service/resource-type wildcard, so those are scoped as tightly as IAM allows.
data "aws_iam_policy_document" "remediator" {
  statement {
    sid    = "S3PublicAccessRemediation"
    effect = "Allow"
    actions = [
      "s3:GetBucketAcl",
      "s3:PutBucketAcl",
      "s3:GetPublicAccessBlock",
      "s3:PutPublicAccessBlock",
    ]
    resources = ["arn:aws:s3:::*"]
  }

  statement {
    sid    = "SecurityGroupRemediation"
    effect = "Allow"
    actions = [
      "ec2:DescribeSecurityGroups",
      "ec2:RevokeSecurityGroupIngress",
    ]
    resources = [
      "arn:aws:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:security-group/*",
    ]
  }

  statement {
    sid    = "EbsVolumeRemediation"
    effect = "Allow"
    actions = [
      "ec2:CreateTags",
    ]
    resources = [
      "arn:aws:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:volume/*",
    ]
  }

  statement {
    sid    = "EbsVolumeDescribe"
    effect = "Allow"
    actions = [
      "ec2:DescribeTags",
      "ec2:DescribeVolumes",
    ]
    # ec2:Describe* actions do not support resource-level permissions.
    resources = ["*"]
  }

  statement {
    sid       = "PublishRemediationNotifications"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.remediation_alerts.arn]
  }

  statement {
    sid    = "WriteLambdaLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.remediator.arn}:*"]
  }

  statement {
    sid    = "WriteXrayTraces"
    effect = "Allow"
    actions = [
      "xray:PutTraceSegments",
      "xray:PutTelemetryRecords",
    ]
    # X-Ray write actions do not support resource-level permissions.
    resources = ["*"]
  }

  statement {
    sid       = "SendToDeadLetterQueue"
    effect    = "Allow"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.remediator_dlq.arn]
  }
}

resource "aws_iam_role_policy" "remediator" {
  name   = "${var.project_name}-remediator-policy"
  role   = aws_iam_role.remediator.id
  policy = data.aws_iam_policy_document.remediator.json
}
