import boto3
from moto import mock_aws

from remediations import security_group


def make_detail(group_id, from_port=22, to_port=22, protocol="tcp", cidr="0.0.0.0/0"):
    return {
        "eventSource": "ec2.amazonaws.com",
        "eventName": "AuthorizeSecurityGroupIngress",
        "requestParameters": {
            "groupId": group_id,
            "ipPermissions": {
                "items": [
                    {
                        "ipProtocol": protocol,
                        "fromPort": from_port,
                        "toPort": to_port,
                        "ipRanges": {"items": [{"cidrIp": cidr}]},
                    }
                ]
            },
        },
    }


def _create_security_group(ec2, name):
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    sg = ec2.create_security_group(GroupName=name, Description="test", VpcId=vpc["VpcId"])
    return sg["GroupId"]


@mock_aws
def test_revokes_open_ssh_ingress():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    group_id = _create_security_group(ec2, "test-sg-ssh")
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        ],
    )

    result = security_group.remediate(make_detail(group_id), dry_run=False, ec2_client=ec2)

    assert result["status"] == "remediated"
    assert result["rules_revoked"] == 1

    rules = ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"][0]["IpPermissions"]
    assert rules == []


@mock_aws
def test_ignores_non_sensitive_port():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    group_id = _create_security_group(ec2, "test-sg-http")
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 8080, "ToPort": 8080, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        ],
    )

    detail = make_detail(group_id, from_port=8080, to_port=8080)
    result = security_group.remediate(detail, dry_run=False, ec2_client=ec2)

    assert result["status"] == "compliant"
    rules = ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"][0]["IpPermissions"]
    assert len(rules) == 1


@mock_aws
def test_ignores_sensitive_port_restricted_to_private_cidr():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    group_id = _create_security_group(ec2, "test-sg-private")
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/16"}]}
        ],
    )

    detail = make_detail(group_id, cidr="10.0.0.0/16")
    result = security_group.remediate(detail, dry_run=False, ec2_client=ec2)

    assert result["status"] == "compliant"


@mock_aws
def test_dry_run_makes_no_changes():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    group_id = _create_security_group(ec2, "test-sg-dry-run")
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        ],
    )

    detail = make_detail(group_id, from_port=3389, to_port=3389)
    result = security_group.remediate(detail, dry_run=True, ec2_client=ec2)

    assert result["status"] == "dry_run"
    assert result["would_revoke_rules"] == 1

    rules = ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"][0]["IpPermissions"]
    assert len(rules) == 1


@mock_aws
def test_missing_group_id_returns_error():
    result = security_group.remediate({"requestParameters": {}}, dry_run=False)
    assert result["status"] == "error"
