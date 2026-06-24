import boto3
from moto import mock_aws

from remediations import s3_public

PUBLIC_ACCESS_BLOCK_ALL_TRUE = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def make_detail(bucket_name, event_name="PutBucketAcl"):
    return {
        "eventSource": "s3.amazonaws.com",
        "eventName": event_name,
        "requestParameters": {"bucketName": bucket_name},
    }


@mock_aws
def test_remediates_public_acl_bucket():
    s3 = boto3.client("s3", region_name="us-east-1")
    bucket = "test-public-bucket"
    s3.create_bucket(Bucket=bucket)
    s3.put_bucket_acl(Bucket=bucket, ACL="public-read")

    result = s3_public.remediate(make_detail(bucket), dry_run=False, s3_client=s3)

    assert result["status"] == "remediated"
    assert "reset_acl_to_private" in result["actions_taken"]
    assert "applied_public_access_block" in result["actions_taken"]

    acl = s3.get_bucket_acl(Bucket=bucket)
    grantee_uris = {grant["Grantee"].get("URI") for grant in acl["Grants"]}
    assert "http://acs.amazonaws.com/groups/global/AllUsers" not in grantee_uris

    pab = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    assert all(pab.values())


@mock_aws
def test_dry_run_makes_no_changes():
    s3 = boto3.client("s3", region_name="us-east-1")
    bucket = "test-dry-run-bucket"
    s3.create_bucket(Bucket=bucket)
    s3.put_bucket_acl(Bucket=bucket, ACL="public-read")

    result = s3_public.remediate(make_detail(bucket), dry_run=True, s3_client=s3)

    assert result["status"] == "dry_run"
    assert result["would_reset_acl"] is True
    assert result["would_apply_public_access_block"] is True

    acl = s3.get_bucket_acl(Bucket=bucket)
    grantee_uris = {grant["Grantee"].get("URI") for grant in acl["Grants"]}
    assert "http://acs.amazonaws.com/groups/global/AllUsers" in grantee_uris


@mock_aws
def test_compliant_bucket_is_noop():
    s3 = boto3.client("s3", region_name="us-east-1")
    bucket = "test-private-bucket"
    s3.create_bucket(Bucket=bucket)
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration=PUBLIC_ACCESS_BLOCK_ALL_TRUE,
    )

    result = s3_public.remediate(make_detail(bucket), dry_run=False, s3_client=s3)
    assert result["status"] == "compliant"


@mock_aws
def test_remediation_is_idempotent():
    s3 = boto3.client("s3", region_name="us-east-1")
    bucket = "test-idempotent-bucket"
    s3.create_bucket(Bucket=bucket)
    s3.put_bucket_acl(Bucket=bucket, ACL="public-read")

    first = s3_public.remediate(make_detail(bucket), dry_run=False, s3_client=s3)
    second = s3_public.remediate(make_detail(bucket), dry_run=False, s3_client=s3)

    assert first["status"] == "remediated"
    assert second["status"] == "compliant"


@mock_aws
def test_missing_bucket_name_returns_error():
    result = s3_public.remediate({"requestParameters": {}}, dry_run=False)
    assert result["status"] == "error"
