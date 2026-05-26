import { type Finding, type Severity } from "./scanners.js";
export type FailOn = "high" | "medium" | "none";
export interface RunnerInputs {
    manifests_dir?: string;
    chart_dir?: string;
    fail_on?: string;
    comment_on_pr?: string;
    github_token?: string;
}
export interface RunnerEnv {
    inputs: RunnerInputs;
    GITHUB_OUTPUT?: string;
    GITHUB_EVENT_NAME?: string;
    GITHUB_REPOSITORY?: string;
    GITHUB_EVENT_PATH?: string;
    readFile?: (path: string) => string;
    write?: (line: string) => void;
    postComment?: (args: {
        token: string;
        repo: string;
        issueNumber: number;
        body: string;
    }) => Promise<void>;
}
export interface RunnerResult {
    exitCode: 0 | 1;
    findings: Finding[];
    counts: Record<Severity, number>;
    reason?: string;
    commentPosted: boolean;
}
export declare function run(env: RunnerEnv): Promise<RunnerResult>;
