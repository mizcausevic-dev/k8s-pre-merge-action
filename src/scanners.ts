// Minimal embedded versions of the four lane-#3 scanners.
// Full implementations:
//   - k8s-deprecated-api-scanner
//   - k8s-rbac-overscope-finder
//   - k8s-pod-security-audit
//   - helm-chart-values-coverage

import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { join, relative, sep } from "node:path";

import { parseAllDocuments, parse } from "yaml";

export type Severity = "high" | "medium" | "low" | "info";

export interface Finding {
  /** Scanner that produced this finding. */
  scanner: "deprecated-api" | "rbac" | "pod-security" | "helm-values";
  code: string;
  severity: Severity;
  message: string;
  source: string;
  subject?: string;
}

export interface ScannerOptions {
  /** Limit how many findings per scanner are surfaced (caps PR comment size). Default 50. */
  maxFindings?: number;
}

const DEFAULT_MAX = 50;

// ─── shared helpers ──────────────────────────────────────────────────────
function listYamlFiles(root: string): string[] {
  const out: string[] = [];
  const visit = (dir: string): void => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      const st = statSync(full);
      if (st.isDirectory()) visit(full);
      else if (/\.ya?ml$/i.test(entry)) out.push(full);
    }
  };
  if (existsSync(root)) visit(root);
  return out.sort();
}

// ─── deprecated-api ──────────────────────────────────────────────────────
const DEPRECATED_APIS = new Map<string, { replacement: string; removedIn?: string }>([
  ["extensions/v1beta1/Deployment", { replacement: "apps/v1", removedIn: "1.16" }],
  ["extensions/v1beta1/DaemonSet", { replacement: "apps/v1", removedIn: "1.16" }],
  ["extensions/v1beta1/ReplicaSet", { replacement: "apps/v1", removedIn: "1.16" }],
  ["extensions/v1beta1/Ingress", { replacement: "networking.k8s.io/v1", removedIn: "1.22" }],
  ["extensions/v1beta1/NetworkPolicy", { replacement: "networking.k8s.io/v1", removedIn: "1.16" }],
  ["apps/v1beta1/Deployment", { replacement: "apps/v1", removedIn: "1.16" }],
  ["apps/v1beta2/Deployment", { replacement: "apps/v1", removedIn: "1.16" }],
  ["apps/v1beta1/StatefulSet", { replacement: "apps/v1", removedIn: "1.16" }],
  ["networking.k8s.io/v1beta1/Ingress", { replacement: "networking.k8s.io/v1", removedIn: "1.22" }],
  ["batch/v1beta1/CronJob", { replacement: "batch/v1", removedIn: "1.25" }],
  ["policy/v1beta1/PodSecurityPolicy", { replacement: "(use Pod Security Admission)", removedIn: "1.25" }],
  ["policy/v1beta1/PodDisruptionBudget", { replacement: "policy/v1", removedIn: "1.25" }],
  ["autoscaling/v2beta1/HorizontalPodAutoscaler", { replacement: "autoscaling/v2", removedIn: "1.25" }],
  ["autoscaling/v2beta2/HorizontalPodAutoscaler", { replacement: "autoscaling/v2", removedIn: "1.26" }],
  ["rbac.authorization.k8s.io/v1beta1/Role", { replacement: "rbac.authorization.k8s.io/v1", removedIn: "1.22" }],
  ["rbac.authorization.k8s.io/v1beta1/RoleBinding", { replacement: "rbac.authorization.k8s.io/v1", removedIn: "1.22" }],
  ["rbac.authorization.k8s.io/v1beta1/ClusterRole", { replacement: "rbac.authorization.k8s.io/v1", removedIn: "1.22" }],
  ["rbac.authorization.k8s.io/v1beta1/ClusterRoleBinding", { replacement: "rbac.authorization.k8s.io/v1", removedIn: "1.22" }]
]);

export function scanDeprecatedApi(manifestsDir: string, opts: ScannerOptions = {}): Finding[] {
  const findings: Finding[] = [];
  const max = opts.maxFindings ?? DEFAULT_MAX;
  for (const file of listYamlFiles(manifestsDir)) {
    if (findings.length >= max) break;
    const parsed = parseAllDocuments(readFileSync(file, "utf8"));
    parsed.forEach((d, idx) => {
      if (findings.length >= max) return;
      const json = d.toJSON() as { apiVersion?: string; kind?: string } | null;
      if (!json || !json.apiVersion || !json.kind) return;
      const dep = DEPRECATED_APIS.get(`${json.apiVersion}/${json.kind}`);
      if (!dep) return;
      findings.push({
        scanner: "deprecated-api",
        code: "deprecated-api",
        severity: "high",
        message: `${json.apiVersion}/${json.kind} → ${dep.replacement}${dep.removedIn ? ` (removed in ${dep.removedIn})` : ""}`,
        source: parsed.length > 1 ? `${file}:${idx}` : file
      });
    });
  }
  return findings;
}

// ─── rbac over-scope (minimal: wildcard verbs + escalation verbs) ───────
const ESCALATION_VERBS = new Set(["escalate", "bind", "impersonate"]);

export function scanRbac(manifestsDir: string, opts: ScannerOptions = {}): Finding[] {
  const findings: Finding[] = [];
  const max = opts.maxFindings ?? DEFAULT_MAX;
  for (const file of listYamlFiles(manifestsDir)) {
    if (findings.length >= max) break;
    const parsed = parseAllDocuments(readFileSync(file, "utf8"));
    parsed.forEach((d, idx) => {
      if (findings.length >= max) return;
      const json = d.toJSON() as { kind?: string; metadata?: { name?: string }; rules?: Array<{ verbs?: string[]; resources?: string[]; apiGroups?: string[] }>; subjects?: Array<{ kind?: string; name?: string }>; roleRef?: { kind?: string; name?: string } } | null;
      if (!json || !json.kind) return;
      const source = parsed.length > 1 ? `${file}:${idx}` : file;
      const subject = json.metadata?.name;
      if (json.kind === "Role" || json.kind === "ClusterRole") {
        for (const rule of json.rules ?? []) {
          if ((rule.verbs ?? []).includes("*")) {
            findings.push({ scanner: "rbac", code: "wildcard-verbs", severity: "high", message: `${json.kind} grants verbs=*`, source, ...(subject && { subject }) });
          }
          for (const verb of rule.verbs ?? []) {
            if (ESCALATION_VERBS.has(verb)) {
              findings.push({ scanner: "rbac", code: "escalation-verb", severity: "high", message: `${json.kind} grants the privileged verb "${verb}"`, source, ...(subject && { subject }) });
            }
          }
        }
      } else if (json.kind === "ClusterRoleBinding" && json.roleRef?.kind === "ClusterRole" && json.roleRef.name === "cluster-admin") {
        findings.push({ scanner: "rbac", code: "cluster-admin-binding", severity: "high", message: `ClusterRoleBinding grants cluster-admin`, source, ...(subject && { subject }) });
      }
      if ((json.subjects ?? []).some((s) => s.kind === "Group" && s.name === "system:masters")) {
        findings.push({ scanner: "rbac", code: "system-masters-binding", severity: "high", message: `Binding targets the system:masters group`, source, ...(subject && { subject }) });
      }
    });
  }
  return findings;
}

// ─── pod-security (minimal: privileged + hostPath + hostNetwork) ────────
const WORKLOAD_KINDS = new Set(["Pod", "Deployment", "DaemonSet", "StatefulSet", "Job", "CronJob", "ReplicaSet"]);

interface PodSpec {
  hostNetwork?: boolean;
  hostPID?: boolean;
  hostIPC?: boolean;
  containers?: Array<{ name: string; securityContext?: { privileged?: boolean; allowPrivilegeEscalation?: boolean; capabilities?: { add?: string[] } } }>;
  volumes?: Array<{ name: string; hostPath?: { path: string } }>;
}

function podSpecOf(json: { kind?: string; spec?: { jobTemplate?: { spec?: { template?: { spec?: PodSpec } } }; template?: { spec?: PodSpec } } }): PodSpec | undefined {
  if (!json.kind || !WORKLOAD_KINDS.has(json.kind)) return undefined;
  if (json.kind === "Pod") return json.spec as PodSpec | undefined;
  if (json.kind === "CronJob") return json.spec?.jobTemplate?.spec?.template?.spec;
  return json.spec?.template?.spec;
}

export function scanPodSecurity(manifestsDir: string, opts: ScannerOptions = {}): Finding[] {
  const findings: Finding[] = [];
  const max = opts.maxFindings ?? DEFAULT_MAX;
  for (const file of listYamlFiles(manifestsDir)) {
    if (findings.length >= max) break;
    const parsed = parseAllDocuments(readFileSync(file, "utf8"));
    parsed.forEach((d, idx) => {
      if (findings.length >= max) return;
      const json = d.toJSON() as Parameters<typeof podSpecOf>[0] & { metadata?: { name?: string } } | null;
      if (!json) return;
      const pod = podSpecOf(json);
      if (!pod) return;
      const source = parsed.length > 1 ? `${file}:${idx}` : file;
      const subject = json.metadata?.name;
      if (pod.hostNetwork || pod.hostPID || pod.hostIPC) {
        findings.push({ scanner: "pod-security", code: "host-namespace", severity: "high", message: `Pod uses host namespaces`, source, ...(subject && { subject }) });
      }
      for (const vol of pod.volumes ?? []) {
        if (vol.hostPath) {
          findings.push({ scanner: "pod-security", code: "host-path-mount", severity: "high", message: `Volume mounts host path ${vol.hostPath.path}`, source, ...(subject && { subject }) });
        }
      }
      for (const c of pod.containers ?? []) {
        if (c.securityContext?.privileged === true) {
          findings.push({ scanner: "pod-security", code: "privileged-container", severity: "high", message: `Container "${c.name}" is privileged`, source, ...(subject && { subject }) });
        }
        if (c.securityContext?.allowPrivilegeEscalation === true) {
          findings.push({ scanner: "pod-security", code: "privilege-escalation-allowed", severity: "high", message: `Container "${c.name}" allows privilege escalation`, source, ...(subject && { subject }) });
        }
        for (const cap of c.securityContext?.capabilities?.add ?? []) {
          if (["SYS_ADMIN", "NET_ADMIN", "NET_RAW", "SYS_PTRACE"].includes(cap)) {
            findings.push({ scanner: "pod-security", code: "added-dangerous-capability", severity: "high", message: `Container adds dangerous capability "${cap}"`, source, ...(subject && { subject }) });
          }
        }
      }
    });
  }
  return findings;
}

// ─── helm-values coverage (minimal: missing-default) ────────────────────
const REF_REGEX = /\.Values\.([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)/g;

function declaredPaths(values: unknown, prefix = ""): Set<string> {
  const out = new Set<string>();
  if (values === null || values === undefined) {
    if (prefix) out.add(prefix);
    return out;
  }
  if (typeof values !== "object" || Array.isArray(values)) {
    if (prefix) out.add(prefix);
    return out;
  }
  for (const [k, v] of Object.entries(values as Record<string, unknown>)) {
    const child = prefix ? `${prefix}.${k}` : k;
    if (v !== null && typeof v === "object" && !Array.isArray(v) && Object.keys(v as object).length > 0) {
      for (const p of declaredPaths(v, child)) out.add(p);
    } else {
      out.add(child);
    }
  }
  return out;
}

function pathCovered(path: string, declared: Set<string>): boolean {
  if (declared.has(path)) return true;
  for (const d of declared) if (path.startsWith(`${d}.`) || d.startsWith(`${path}.`)) return true;
  return false;
}

export function scanHelmValues(chartRoot: string, opts: ScannerOptions = {}): Finding[] {
  const findings: Finding[] = [];
  const max = opts.maxFindings ?? DEFAULT_MAX;
  const valuesPath = join(chartRoot, "values.yaml");
  const templatesDir = join(chartRoot, "templates");
  if (!existsSync(valuesPath) || !existsSync(templatesDir)) return findings;
  const declared = declaredPaths(parse(readFileSync(valuesPath, "utf8")) as unknown);
  for (const file of listYamlFiles(templatesDir)) {
    if (findings.length >= max) break;
    const rel = "templates" + sep + relative(templatesDir, file);
    const text = readFileSync(file, "utf8");
    const seen = new Set<string>();
    for (const line of text.split(/\r?\n/)) {
      REF_REGEX.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = REF_REGEX.exec(line)) !== null) {
        const path = m[1];
        if (seen.has(path)) continue;
        seen.add(path);
        if (!pathCovered(path, declared)) {
          if (findings.length >= max) break;
          findings.push({
            scanner: "helm-values",
            code: "missing-default",
            severity: "high",
            message: `.Values.${path} referenced but no default`,
            source: rel.replace(/\\/g, "/")
          });
        }
      }
    }
  }
  return findings;
}
