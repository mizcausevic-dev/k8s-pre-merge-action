# Changelog

## v0.1.0 — 2026-05-27

- Initial release: composite Node 20 GitHub Action bundling minimal versions of `k8s-deprecated-api-scanner`, `k8s-rbac-overscope-finder`, `k8s-pod-security-audit`, and (when `chart-dir` is set) `helm-chart-values-coverage`.
- Aggregates findings into a single severity-ranked Markdown report, posts as PR comment (auto on `pull_request`), and fails on configurable severity threshold (`high` / `medium` / `none`).
- Inputs: `manifests-dir`, `chart-dir`, `fail-on`, `comment-on-pr`, `github-token`. Outputs: `total-findings`, `high`, `medium`, `low`.
- Self-contained — no peer-deps on the four standalone scanners. `dist/index.js` committed so consumers can pin to a SHA or tag without running a build step.
- Companion turnkey form of the lane-#3 K8s pre-merge gate kit.
- Node 20 runner CI (lint, typecheck, coverage, build, demo, `npm audit`), AGPL-3.0-or-later, Dependabot.
