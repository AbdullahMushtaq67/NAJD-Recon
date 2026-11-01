// Mirrors backend/app/models.py

export type ScanStatus = "queued" | "running" | "enriching" | "completed" | "failed";
export type Severity = "critical" | "high" | "medium" | "low" | "none" | "unknown";

export interface Technique {
  id: string;
  name: string;
  flag: string;
  description: string;
  requires_privileges: boolean;
  available: boolean;
}

export interface TimingTemplate {
  level: number;
  name: string;
  description: string;
}

export interface PortPreset {
  id: string;
  name: string;
  description: string;
}

export interface Options {
  techniques: Technique[];
  timing_templates: TimingTemplate[];
  port_presets: PortPreset[];
  privileged: boolean;
  os_detection_available: boolean;
  allowed_targets: string[];
  ai_enabled: boolean;
  ai_provider: string | null;
  demo_mode: boolean;
}

export interface ScanRequest {
  target: string;
  technique: string;
  timing: number;
  port_preset: string;
  custom_ports?: string;
  service_detection: boolean;
  cve_detection: boolean;
  os_detection: boolean;
  skip_host_discovery: boolean;
  authorized: boolean;
}

export interface CommandPreview {
  target: string;
  resolved_ip: string;
  argv: string[];
  command: string;
  explanation: { flag: string; help: string }[];
}

export interface CVE {
  id: string;
  cvss: number | null;
  severity: Severity;
  source: string;
  is_exploit: boolean;
  epss: number | null;
  epss_percentile: number | null;
  in_kev: boolean;
  kev_date_added: string | null;
  kev_ransomware: boolean;
  description: string | null;
  cvss_vector: string | null;
  cvss_version: string | null;
  published: string | null;
  cwe: string[];
  references: string[];
  url: string | null;
}

export interface Port {
  port: number;
  protocol: string;
  state: string;
  reason: string | null;
  reason_ttl: number | null;
  service: string | null;
  product: string | null;
  version: string | null;
  extrainfo: string | null;
  service_tunnel: string | null;
  service_method: string | null;
  service_confidence: number | null;
  cpes: string[];
  scripts: { id: string; output: string }[];
  cves: CVE[];
}

export interface NetworkAddress {
  address: string;
  kind: string;
  vendor: string | null;
}

export interface PortStateCount {
  state: string;
  count: number;
  reasons: string[];
}

export interface TraceHop {
  ttl: number;
  address: string | null;
  hostname: string | null;
  rtt: string | null;
}

export interface Host {
  address: string;
  hostnames: string[];
  status: string;
  status_reason: string | null;
  status_reason_ttl: number | null;
  addresses: NetworkAddress[];
  os_matches: { name: string; accuracy: number }[];
  uptime_seconds: number | null;
  uptime_last_boot: string | null;
  distance_hops: number | null;
  extra_port_states: PortStateCount[];
  scripts: { id: string; output: string }[];
  trace_hops: TraceHop[];
  ports: Port[];
}

export interface ScanResult {
  nmap_version: string | null;
  command: string | null;
  started_at: string | null;
  elapsed_seconds: number | null;
  summary: string | null;
  hosts_up: number | null;
  hosts_down: number | null;
  hosts_total: number | null;
  hosts: Host[];
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
}

export interface ScanJob {
  id: string;
  target: string;
  resolved_ip: string;
  options: Record<string, unknown>;
  command: string[];
  status: ScanStatus;
  progress: number;
  current_task: string | null;
  error: string | null;
  created_at: string;
  finished_at: string | null;
  result: ScanResult | null;
  severity_counts: SeverityCounts | null;
}

export interface ScanSummary {
  id: string;
  target: string;
  status: ScanStatus;
  created_at: string;
  open_ports: number;
  cve_count: number;
  severity_counts: SeverityCounts | null;
}

export interface Asset {
  id: string;
  name: string;
  target: string;
  owner: string;
  environment: string;
  criticality: "critical" | "high" | "medium" | "low";
  tags: string[];
  notes: string;
  created_at: string;
  updated_at: string;
  scan_count: number;
  latest_scan_at: string | null;
}

export interface FindingRecord {
  finding_id: string;
  scan_id: string;
  target: string;
  host: string;
  port: number;
  protocol: string;
  service: string | null;
  product: string | null;
  version: string | null;
  last_seen: string;
  cve: CVE;
  status: "open" | "in_progress" | "accepted" | "resolved";
  assignee: string;
  due_date: string | null;
  note: string;
}

export interface SavedView {
  id: string;
  name: string;
  filters: Record<string, string | boolean | null>;
  created_at: string;
}

export interface WorkspaceSettings {
  workspace_name: string;
  report_subtitle: string;
  report_contact: string;
  report_footer: string;
  notify_critical: boolean;
  notify_new_scan: boolean;
  notify_scan_failure: boolean;
}

export interface Notification {
  id: string;
  kind: string;
  title: string;
  message: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  scan_id: string | null;
  target: string | null;
  created_at: string;
  read_at: string | null;
}

export interface ProgressEvent {
  status: ScanStatus;
  progress: number;
  current_task: string | null;
  error: string | null;
}

export interface Explanation {
  cve_id: string;
  summary: string;
  impact: string;
  who_is_affected: string;
  remediation: string[];
  risk_level: string;
  provider: string;
  model: string;
  cached: boolean;
}
