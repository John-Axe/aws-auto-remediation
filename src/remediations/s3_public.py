import logging

import boto3
from botocore.exceptions import ClientError

from utils.notify import publish

logger = logging.getLogger()

PUBLIC_ACL_GRANTEE_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}

FULL_PUBLIC_ACCESS_BLOCK = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}

FINDING = "s3_public_bucket"


def _extract_bucket_name(detail):
    return (detail.get("requestParameters") or {}).get("bucketName")


def _is_acl_public(bucket_name, s3_client):
    acl = s3_client.get_bucket_acl(Bucket=bucket_name)
    for grant in acl.get("Grants", []):
        if grant.get("Grantee", {}).get("URI") in PUBLIC_ACL_GRANTEE_URIS:
            return True
    return False


def _has_full_public_access_block(bucket_name, s3_client):
    try:
        config = s3_client.get_public_access_block(Bucket=bucket_name)["PublicAccessBlockConfiguration"]
        return all(config.get(key) for key in FULL_PUBLIC_ACCESS_BLOCK)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return False
        raise


def remediate(detail, dry_run=False, s3_client=None):
    """Re-applies S3 Block Public Access and resets public ACL grants.

    Reapplying Block Public Access neutralizes both a public ACL and a public
    bucket policy without needing to parse/rewrite arbitrary policy JSON.
    """
    s3_client = s3_client or boto3.client("s3")
    bucket_name = _extract_bucket_name(detail)

    if not bucket_name:
        return {"status": "error", "reason": "no_bucket_name", "finding": FINDING}

    is_acl_public = _is_acl_public(bucket_name, s3_client)
    has_block = _has_full_public_access_block(bucket_name, s3_client)

    if not is_acl_public and has_block:
        return {"status": "compliant", "bucket": bucket_name, "finding": FINDING}

    if dry_run:
        return {
            "status": "dry_run",
            "bucket": bucket_name,
            "finding": FINDING,
            "would_reset_acl": is_acl_public,
            "would_apply_public_access_block": not has_block,
        }

    actions_taken = []

    if is_acl_public:
        s3_client.put_bucket_acl(Bucket=bucket_name, ACL="private")
        actions_taken.append("reset_acl_to_private")

    if not has_block:
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration=FULL_PUBLIC_ACCESS_BLOCK,
        )
        actions_taken.append("applied_public_access_block")

    result = {
        "status": "remediated",
        "bucket": bucket_name,
        "finding": FINDING,
        "actions_taken": actions_taken,
    }
    publish(subject="S3 bucket public access remediated", message=result)
    return result
