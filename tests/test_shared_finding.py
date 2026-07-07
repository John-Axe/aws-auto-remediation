from utils.shared_finding import to_shared_finding


def test_s3_remediated_maps_to_critical_finding():
    result = {
        "status": "remediated",
        "bucket": "test-public-bucket",
        "finding": "s3_public_bucket",
        "actions_taken": ["reset_acl_to_private", "applied_public_access_block"],
    }

    finding = to_shared_finding(result)

    assert finding["source"] == "aws-auto-remediation"
    assert finding["severity"] == "critical"
    assert finding["category"] == "cloud-misconfig"
    assert finding["resource"] == "test-public-bucket"
    assert finding["mitre_attack"] == ["T1530"]
    assert finding["remediation"] == "reset_acl_to_private, applied_public_access_block"
    assert finding["raw"]["bucket"] == "test-public-bucket"
    assert "status" not in finding["raw"]
    assert "finding" not in finding["raw"]


def test_sg_remediated_maps_to_high_finding_with_no_mitre():
    result = {
        "status": "remediated",
        "group_id": "sg-12345",
        "finding": "sg_open_ingress",
        "rules_revoked": 2,
    }

    finding = to_shared_finding(result)

    assert finding["severity"] == "high"
    assert finding["resource"] == "sg-12345"
    assert finding["mitre_attack"] == []
    assert finding["remediation"] == "revoked 2 ingress rule(s)"


def test_sg_no_action_still_produces_a_finding():
    # revoke_security_group_ingress failed for every offending rule -- the
    # misconfiguration is still real even though nothing got fixed.
    result = {"status": "no_action", "group_id": "sg-99999", "finding": "sg_open_ingress", "rules_revoked": 0}

    finding = to_shared_finding(result)

    assert finding is not None
    assert finding["remediation"] == "revoked 0 ingress rule(s)"


def test_ebs_tagged_maps_to_medium_finding():
    result = {"status": "tagged_and_alerted", "volume_id": "vol-abc123", "finding": "ebs_unencrypted"}

    finding = to_shared_finding(result)

    assert finding["severity"] == "medium"
    assert finding["resource"] == "vol-abc123"
    assert finding["mitre_attack"] == []
    assert finding["remediation"] is None


def test_dry_run_produces_a_would_finding():
    result = {
        "status": "dry_run",
        "bucket": "test-dry-run-bucket",
        "finding": "s3_public_bucket",
        "would_reset_acl": True,
        "would_apply_public_access_block": True,
    }

    finding = to_shared_finding(result)

    assert finding is not None
    assert finding["remediation"] == "would_reset_acl, would_apply_public_access_block"


def test_compliant_result_is_not_a_finding():
    result = {"status": "compliant", "bucket": "test-private-bucket", "finding": "s3_public_bucket"}
    assert to_shared_finding(result) is None


def test_error_result_is_not_a_finding():
    result = {"status": "error", "reason": "no_bucket_name", "finding": "s3_public_bucket"}
    assert to_shared_finding(result) is None
