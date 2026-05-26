import { run } from "../src/runner.js";

const r = await run({
  inputs: {
    manifests_dir: "fixtures/manifests",
    chart_dir: "fixtures/chart",
    fail_on: "none"
  }
});
console.log(`total: ${r.findings.length} · high: ${r.counts.high} · medium: ${r.counts.medium} · low: ${r.counts.low}`);
