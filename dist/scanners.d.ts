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
export declare function scanDeprecatedApi(manifestsDir: string, opts?: ScannerOptions): Finding[];
export declare function scanRbac(manifestsDir: string, opts?: ScannerOptions): Finding[];
export declare function scanPodSecurity(manifestsDir: string, opts?: ScannerOptions): Finding[];
export declare function scanHelmValues(chartRoot: string, opts?: ScannerOptions): Finding[];
