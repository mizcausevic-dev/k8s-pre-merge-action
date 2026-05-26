# k8s-pre-merge-action

Composite GitHub Action that runs the **lane-#3 K8s pre-merge scanner kit** against a manifests directory + optional Helm chart, aggregates findings into a single Markdown report, posts as a PR comment, and fails the run when findings exceed a configurable severity threshold.

Bundles minimal versions of:

- [**`k8s-deprecated-api-scanner`**](https://github.com/mizcausevic-dev/k8s-deprecated-api-scanner) — flag deprecated `apiVersion`/`kind`
- [**`k8s-rbac-overscope-finder`**](https://github.com/mizcausevic-dev/k8s-rbac-overscope-finder) — wildcard verbs / escalation / cluster-admin / system:masters
- [**`k8s-pod-security-audit`**](https://github.com/mizcausevic-dev/k8s-pod-security-audit) — privileged / host namespaces / hostPath / dangerous capabilities
- [**`helm-chart-values-coverage`**](https://github.com/mizcausevic-dev/helm-chart-values-coverage) — `{{ .Values.* }}` vs `values.yaml` (when `chart-dir` is set)

> Status: v0.1.0 — Node 20 runner. AGPL-3.0-or-later.

## Usage

```yaml
- uses: actions/checkout@v4

- uses: mizcausevic-dev/k8s-pre-merge-action@v0.1.0
  with:
    manifests-dir: ./deploy/manifests
    chart-dir: ./charts/my-app       # optional
    fail-on: high                    # high | medium | none
    comment-on-pr: auto              # auto | true | false
```

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `manifests-dir` | yes | — | Directory of K8s YAML to scan. |
| `chart-dir` | no | — | Optional Helm chart root with `templates/` + `values.yaml`. |
| `fail-on` | no | `high` | Severity threshold that fails the run: `high`, `medium`, or `none`. |
| `comment-on-pr` | no | `auto` | Post the consolidated Markdown report as a PR comment (`auto` = post only on `pull_request` events). |
| `github-token` | no | `${{ github.token }}` | Token used to post the PR comment. |

## Outputs

| Output | Description |
|---|---|
| `total-findings` | Total findings across all four scanners. |
| `high` / `medium` / `low` | Counts per severity. |

## Why this Action exists

Each underlying scanner is self-contained — you can install them individually if you only need one. This Action is the **turnkey form**: one workflow step, one PR comment, one severity gate. Useful for repos that ship Helm charts or raw manifests and want a single pre-merge check.

For deeper / configurable scans (per-scanner `--ignore-*` flags, custom dangerous-capability lists, deprecation-catalog overrides), call the individual CLIs directly.

## Develop

```
npm install
npm run lint && npm run typecheck && npm run coverage && npm run build
npm run demo
```

The action's runtime entry is `dist/index.js` — built artifacts are committed so consumers can pin to a SHA or tag without running a build step.

## License

[AGPL-3.0-or-later](LICENSE)
