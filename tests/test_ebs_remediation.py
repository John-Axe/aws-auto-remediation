import boto3
from moto import mock_aws

from remediations import ebs_unencrypted


def make_detail(volume_id, encrypted=False):
    return {
        "eventSource": "ec2.amazonaws.com",
        "eventName": "CreateVolume",
        "responseElements": {"volumeId": volume_id, "encrypted": encrypted},
    }


@mock_aws
def test_tags_unencrypted_volume_and_alerts():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    volume_id = ec2.create_volume(Size=8, AvailabilityZone="us-east-1a", Encrypted=False)["VolumeId"]

    result = ebs_unencrypted.remediate(make_detail(volume_id, encrypted=False), dry_run=False, ec2_client=ec2)

    assert result["status"] == "tagged_and_alerted"

    tags = ec2.describe_tags(Filters=[{"Name": "resource-id", "Values": [volume_id]}])["Tags"]
    tag_map = {tag["Key"]: tag["Value"] for tag in tags}
    assert tag_map.get("ComplianceStatus") == "NON_COMPLIANT_UNENCRYPTED"


@mock_aws
def test_encrypted_volume_is_compliant():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    volume_id = ec2.create_volume(Size=8, AvailabilityZone="us-east-1a", Encrypted=True)["VolumeId"]

    result = ebs_unencrypted.remediate(make_detail(volume_id, encrypted=True), dry_run=False, ec2_client=ec2)
    assert result["status"] == "compliant"


@mock_aws
def test_dry_run_does_not_tag():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    volume_id = ec2.create_volume(Size=8, AvailabilityZone="us-east-1a", Encrypted=False)["VolumeId"]

    result = ebs_unencrypted.remediate(make_detail(volume_id, encrypted=False), dry_run=True, ec2_client=ec2)

    assert result["status"] == "dry_run"
    tags = ec2.describe_tags(Filters=[{"Name": "resource-id", "Values": [volume_id]}])["Tags"]
    assert tags == []


@mock_aws
def test_missing_volume_id_returns_error():
    result = ebs_unencrypted.remediate({"responseElements": {}}, dry_run=False)
    assert result["status"] == "error"
