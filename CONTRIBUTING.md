# Contributing

## Reporting bugs

Open a [GitHub Issue](https://github.com/John-Axe/aws-auto-remediation/issues/new?template=bug_report.md) using the bug report template. Include Lambda logs and the CloudTrail event that triggered (or failed to trigger) the remediation.

## Suggesting a new remediation

Open a [GitHub Issue](https://github.com/John-Axe/aws-auto-remediation/issues/new?template=feature_request.md) describing the misconfiguration, the CloudTrail event that signals it, and the desired fix.

## Submitting a pull request

1. Fork the repo and create a branch from `main`.
2. Make your changes. Add or update tests for any changed behaviour.
3. Verify everything passes locally:
   ```bash
   pytest -v
   terraform fmt -check -recursive
   ```
4. Open a PR against `main`. Fill in the PR template.
5. A maintainer will review and merge.

## Adding a new remediation module

Each remediation lives in `src/` as a single file (e.g. `src/s3_public_access.py`) with a matching test file in `tests/`. The handler in `handler.py` dispatches to it based on the CloudTrail event name. Follow the pattern of an existing module:

- Accept `(event, dry_run)` parameters.
- Return a dict with at least `action` and `resource` keys.
- Publish a notification via `utils.notify()`.
- Use moto to mock AWS in tests — no real credentials required.

## Development setup

```bash
pip install -r requirements-dev.txt
pytest -v
```

## Updating dependencies

Edit `requirements-dev.in`, then regenerate the lockfile:

```bash
pip-compile --generate-hashes requirements-dev.in -o requirements-dev.txt
```
