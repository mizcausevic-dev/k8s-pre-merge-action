# Security Policy

`k8s-pre-merge-action` runs inside GitHub Actions runners as a Node 20 action. It reads YAML files from the workspace, aggregates findings, optionally posts a PR comment via the GitHub REST API, and writes outputs to `$GITHUB_OUTPUT`. No remote code fetch, no execution of user-supplied scripts.

The `github-token` input is used only to POST one PR comment with the consolidated Markdown report. The token is never logged.

## Supported versions

Only the latest tagged release is supported.

## Reporting a vulnerability

Please use GitHub Security Advisories for private disclosure:

- [Open a security advisory](https://github.com/mizcausevic-dev/k8s-pre-merge-action/security/advisories/new)

Do not file public issues for security reports.
