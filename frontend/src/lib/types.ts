export type Language =
  | "auto"
  | "python"
  | "rust"
  | "javascript"
  | "typescript"
  | "go"
  | "java"
  | "ruby"
  | "c"
  | "cpp";

export type Severity = "critical" | "high" | "medium" | "low";
export type Label = "tp" | "fp";

export interface Finding {
  id: string;
  rule_id: string;
  message: string;
  severity: Severity;
  line_start: number;
  line_end: number;
  code_snippet: string;
  confidence: number;
  is_uncertain: boolean;
  cwe: string | null;
  source: string;
  trace_graph?: TraceGraph | null;
  exploration_plan?: ExplorationPlan | null;
}

export interface TraceGraph {
  nodes: TraceGraphNode[];
  edges: TraceGraphEdge[];
}

export interface TraceGraphNode {
  id: string;
  kind: "source" | "function" | "sink" | "finding" | string;
  label: string;
  file?: string | null;
  line_start?: number | null;
  line_end?: number | null;
  detail?: string | null;
  meta?: TraceGraphNodeMeta | null;
}

export interface TraceGraphNodeMeta {
  findingId?: string | null;
  relatedFindingIds?: string[];
  severity?: Severity | null;
  severities?: Severity[];
  cwe?: string | null;
  cwes?: string[];
  message?: string | null;
  ruleId?: string | null;
  source?: string | null;
  confidence?: number | null;
  ordinal?: number | null;
}

export interface TraceGraphEdge {
  id: string;
  source: string;
  target: string;
  kind: "flows_to" | "reports" | string;
  label?: string | null;
}

export interface ExplorationPlan {
  kind: string;
  title: string;
  objective: string;
  priority: number;
  rationale: string;
  steps: ExplorationStep[];
  feedback_signals: string[];
  required_evidence: string[];
}

export interface ExplorationStep {
  id: string;
  kind: "source" | "function" | "sink" | "finding" | string;
  label: string;
  file?: string | null;
  line_start?: number | null;
  line_end?: number | null;
  detail?: string | null;
}

export interface ScanResponse {
  scan_id: string;
  findings: Finding[];
  language: string;
  lines_scanned: number;
}

export interface ProjectScanFileRequest {
  path: string;
  code: string;
  language?: Language;
}

export interface ProjectScanFileResult {
  path: string;
  scan_id: string;
  findings: Finding[];
  language: Language;
  lines_scanned: number;
}

export interface ProjectScanResponse {
  scan_id: string;
  files: ProjectScanFileResult[];
  language: Language;
  lines_scanned: number;
}

export interface Stats {
  total_labels: number;
  tp_count: number;
  fp_count: number;
  model_stage: string;
  labels_until_next_stage: number;
}

export interface ModelMetrics {
  trained_at: string;
  samples: number;
  tp: number;
  fp: number;
  stage: string;
  elapsed_ms: number;
  split: string;
  val_samples?: number;
  val_accuracy?: number;
  val_precision?: number;
  val_recall?: number;
  val_prob_mean_tp?: number | null;
  val_prob_mean_fp?: number | null;
  run_id?: string | null;
  dataset_hash?: string | null;
  class_weighting?: string | null;
  skipped_invalid_vectors?: number | null;
  group_count?: number | null;
  grouped_samples?: number | null;
  solo_samples?: number | null;
}

export interface VerifyCase {
  caseNo: number;
  cveId?: string | null;
  code: string;
  language: Language;
  findings: Finding[];
  submittedAt: string;
  labels: Record<string, Label>;
}

export interface FileNode {
  name: string;
  path: string;
  type: "file" | "dir";
  language?: Language;
  content?: string;
  children?: FileNode[];
}

export interface KnowledgeCase {
  caseNo: number;
  cveId?: string | null;
  code: string;
  language: Language;
  findings: Finding[];
  labels: Record<string, string>;
  submittedAt: string;
  verifiedAt: string;
}

export type AuditProvider = "openai" | "anthropic";

export interface AuditCase {
  id: string;
  scanId: string | null;
  code: string;
  language: Language;
  findings: Finding[];
  createdAt: string;
}

export type AuditStepStatus = "idle" | "running" | "complete" | "error";

export interface AuditStepResult {
  id: string;
  title: string;
  status: AuditStepStatus;
  output: string;
  error: string | null;
  durationMs: number | null;
}

export interface AuditRunResponse {
  results: AuditStepResult[];
  reportMarkdown: string;
  reportSections: import("$lib/auditReport").AuditReportSection[];
}
