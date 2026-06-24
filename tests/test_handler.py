import importlib

import handler as handler_module


def setup_function(_):
    importlib.reload(handler_module)


def test_dispatches_to_s3_remediation(monkeypatch):
    captured = {}

    def fake_remediate(detail, dry_run=False):
        captured["detail"] = detail
        captured["dry_run"] = dry_run
        return {"status": "remediated", "finding": "s3_public_bucket"}

    monkeypatch.setattr(handler_module.s3_public, "remediate", fake_remediate)
    monkeypatch.setenv("DRY_RUN", "false")

    event = {"detail": {"eventSource": "s3.amazonaws.com", "eventName": "PutBucketAcl"}}
    result = handler_module.handler(event, None)

    assert captured["dry_run"] is False
    assert result["status"] == "remediated"


def test_dry_run_env_var_is_propagated(monkeypatch):
    captured = {}

    def fake_remediate(detail, dry_run=False):
        captured["dry_run"] = dry_run
        return {"status": "dry_run", "finding": "sg_open_ingress"}

    monkeypatch.setattr(handler_module.security_group, "remediate", fake_remediate)
    monkeypatch.setenv("DRY_RUN", "true")

    event = {"detail": {"eventSource": "ec2.amazonaws.com", "eventName": "AuthorizeSecurityGroupIngress"}}
    handler_module.handler(event, None)

    assert captured["dry_run"] is True


def test_unhandled_event_returns_ignored(monkeypatch):
    monkeypatch.setenv("DRY_RUN", "false")
    event = {"detail": {"eventSource": "foo.amazonaws.com", "eventName": "Bar"}}
    result = handler_module.handler(event, None)
    assert result["status"] == "ignored"
