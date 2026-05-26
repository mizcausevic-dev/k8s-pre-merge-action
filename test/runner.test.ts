import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";

import { run } from "../src/runner.js";
import { scanDeprecatedApi, scanHelmValues, scanPodSecurity, scanRbac } from "../src/scanners.js";

const here = fileURLToPath(new URL(".", import.meta.url));
const MANIFESTS = `${here}/../fixtures/manifests`;
const CHART = `${here}/../fixtures/chart`;

describe("individual scanners", () => {
  it("scanDeprecatedApi flags Ingress networking.k8s.io/v1beta1", () => {
    const f = scanDeprecatedApi(MANIFESTS);
    expect(f.some((x) => x.code === "deprecated-api")).toBe(true);
    expect(f.every((x) => x.severity === "high")).toBe(true);
  });

  it("scanRbac flags wildcard-verbs as high", () => {
    const f = scanRbac(MANIFESTS);
    expect(f.some((x) => x.code === "wildcard-verbs")).toBe(true);
  });

  it("scanPodSecurity flags privileged + hostPath + hostNetwork + dangerous capability", () => {
    const f = scanPodSecurity(MANIFESTS);
    const codes = new Set(f.map((x) => x.code));
    expect(codes.has("privileged-container")).toBe(true);
    expect(codes.has("host-namespace")).toBe(true);
    expect(codes.has("host-path-mount")).toBe(true);
    expect(codes.has("added-dangerous-capability")).toBe(true);
  });

  it("scanHelmValues flags missing-default for image.tag", () => {
    const f = scanHelmValues(CHART);
    expect(f.some((x) => x.code === "missing-default" && x.message.includes("image.tag"))).toBe(true);
  });

  it("scanHelmValues returns [] when chart-dir is missing", () => {
    expect(scanHelmValues("/non/existent/path")).toEqual([]);
  });

  it("maxFindings:0 disables the scanner", () => {
    expect(scanPodSecurity(MANIFESTS, { maxFindings: 0 })).toEqual([]);
  });
});

describe("run (composite action)", () => {
  it("returns exit 1 with fail-on=high when high findings exist", async () => {
    const r = await run({
      inputs: { manifests_dir: MANIFESTS, fail_on: "high" },
      write: () => undefined
    });
    expect(r.exitCode).toBe(1);
    expect(r.counts.high).toBeGreaterThan(0);
  });

  it("returns exit 0 with fail-on=none even when high findings exist", async () => {
    const r = await run({
      inputs: { manifests_dir: MANIFESTS, fail_on: "none" },
      write: () => undefined
    });
    expect(r.exitCode).toBe(0);
  });

  it("includes helm-values findings when chart_dir is supplied", async () => {
    const r = await run({
      inputs: { manifests_dir: MANIFESTS, chart_dir: CHART, fail_on: "none" },
      write: () => undefined
    });
    expect(r.findings.some((f) => f.scanner === "helm-values")).toBe(true);
  });

  it("posts a PR comment when comment-on-pr=true and event payload has number", async () => {
    const poster = vi.fn(async () => undefined);
    const r = await run({
      inputs: { manifests_dir: MANIFESTS, fail_on: "none", comment_on_pr: "true", github_token: "ghs_test" },
      GITHUB_REPOSITORY: "mizcausevic-dev/k8s-pre-merge-action",
      GITHUB_EVENT_PATH: "/tmp/event-pr.json",
      readFile: () => JSON.stringify({ number: 42 }),
      postComment: poster,
      write: () => undefined
    });
    expect(r.commentPosted).toBe(true);
    expect(poster.mock.calls[0][0].issueNumber).toBe(42);
  });

  it("auto-posts only on pull_request event", async () => {
    const poster = vi.fn(async () => undefined);
    const r = await run({
      inputs: { manifests_dir: MANIFESTS, fail_on: "none", comment_on_pr: "auto", github_token: "ghs_test" },
      GITHUB_EVENT_NAME: "push",
      GITHUB_REPOSITORY: "x/y",
      GITHUB_EVENT_PATH: "/tmp/event-pr.json",
      readFile: () => JSON.stringify({ number: 42 }),
      postComment: poster,
      write: () => undefined
    });
    expect(r.commentPosted).toBe(false);
    expect(poster).not.toHaveBeenCalled();
  });

  it("returns reason='no github-token provided' when token missing", async () => {
    const r = await run({
      inputs: { manifests_dir: MANIFESTS, fail_on: "none", comment_on_pr: "true" },
      write: () => undefined
    });
    expect(r.commentPosted).toBe(false);
    expect(r.reason).toBe("no github-token provided");
  });

  it("throws on missing manifests-dir input", async () => {
    await expect(run({ inputs: {}, write: () => undefined })).rejects.toThrow(/manifests-dir/);
  });

  it("throws on invalid fail-on", async () => {
    await expect(
      run({ inputs: { manifests_dir: MANIFESTS, fail_on: "bogus" }, write: () => undefined })
    ).rejects.toThrow(/fail-on/);
  });
});
