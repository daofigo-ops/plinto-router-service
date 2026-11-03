export const API_BASE = import.meta.env.VITE_PLINTO_API_BASE || 'http://127.0.0.1:8787';

export type RiskLevel = 'Low' | 'Medium' | 'High' | 'Critical' | string;

export interface ScanSummary {
  target: string;
  started_at: string;
  finished_at: string;
  unique_hosts: number;
  service_count: number;
  http_only_count: number;
  https_count: number;
  router_like_count: number;
  admin_like_count: number;
  server_error_count: number;
  dns_checked_count: number;
  dns_needs_review_count: number;
  pentest_attempt_count: number;
  pentest_success_count: number;
  highest_risk_level: RiskLevel;
  highest_risk_score: number;
  risk_counts: Record<string, number>;
  top_actions: string[];
}

export interface DNSAudit {
  checked: boolean;
  status: string;
  recommendation: string;
  resolvers: Array<{ ip: string; status: string; provider: string }>;
}

export interface PentestAttempt {
  target: string;
  url: string;
  auth_type: string;
  credential_label: string;
  result: string;
  status_code?: number | null;
  reason: string;
  attempted_at: string;
}

export interface Finding {
  ip: string;
  port: number;
  scheme: string;
  url: string;
  status_code?: number | null;
  server?: string | null;
  title?: string | null;
  content_type?: string | null;
  auth_header?: string | null;
  redirect_location?: string | null;
  vendor_guess: string;
  device_type: string;
  confidence: number;
  evidence: string[];
  risk_score: number;
  risk_level: RiskLevel;
  risk_reasons: string[];
  recommendations: string[];
  dns_audit: DNSAudit;
  pentest_attempts: PentestAttempt[];
  pentest_notes: string[];
  scanned_at: string;
}

export interface LatestReport {
  tool?: string;
  version?: string;
  summary: ScanSummary | null;
  finding_count: number;
  findings: Finding[];
  inventory_changes?: Record<string, unknown> | null;
}

export interface HistoryItem {
  id: string;
  path: string;
  summary: ScanSummary | null;
  finding_count: number;
  reports: Record<string, { exists: boolean; path: string; size_bytes?: number; modified_at?: string }>;
}

export interface RunScanPayload {
  mode: 'local' | 'gateway' | 'custom';
  target?: string;
  ports?: string;
  timeout?: number;
  concurrency?: number;
  report_format: 'json' | 'csv' | 'html' | 'both' | 'all';
  deep_fingerprint: boolean;
  dns_audit: boolean;
  save_history: boolean;
  update_inventory: boolean;
  pentest: boolean;
  ownership_confirmed: boolean;
  apply_pentest: boolean;
  check_defaults: boolean;
  credentials_file?: string;
}

export async function apiGet<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`);
  if (!res.ok) {
    throw new Error(`${res.status} ${res.statusText}: ${await res.text()}`);
  }
  return res.json();
}

export async function apiPost<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    throw new Error(`${res.status} ${res.statusText}: ${await res.text()}`);
  }
  return res.json();
}

export const reportUrl = (kind: 'html' | 'json' | 'csv') => `${API_BASE}/api/reports/latest/${kind}`;
