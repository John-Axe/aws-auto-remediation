# Optional, off by default. Creates a private S3 bucket you can deliberately
# misconfigure during a live demo of the remediation flow. It holds no real
# data and is torn down with `terraform destroy`, so production-grade
# durability/audit controls below are intentionally skipped as out of scope
# for a throwaway demo resource.
resource "aws_s3_bucket" "demo" {
  #checkov:skip=CKV2_AWS_62:Demo-only bucket holding no real data; event notifications add no value.
  #checkov:skip=CKV_AWS_21:Demo-only bucket; versioning adds no value for a resource destroyed after the demo.
  #checkov:skip=CKV_AWS_144:Demo-only bucket; cross-region replication is unnecessary for a throwaway resource.
  #checkov:skip=CKV2_AWS_61:Demo-only bucket; no objects are retained long enough to need a lifecycle policy.
  #checkov:skip=CKV_AWS_18:Demo-only bucket; access logging adds no value for a resource destroyed after the demo.
  count  = var.create_demo_bucket ? 1 : 0
  bucket = "${var.project_name}-demo-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "demo" {
  count  = var.create_demo_bucket ? 1 : 0
  bucket = aws_s3_bucket.demo[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "demo" {
  count  = var.create_demo_bucket ? 1 : 0
  bucket = aws_s3_bucket.demo[0].id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "demo" {
  #checkov:skip=CKV2_AWS_65:ACLs must stay enabled so this bucket can demonstrate the public-ACL misconfiguration the Lambda remediates.
  count  = var.create_demo_bucket ? 1 : 0
  bucket = aws_s3_bucket.demo[0].id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}
