import type {
  CommandPreview,
  Asset,
  Explanation,
  FindingRecord,
  Notification,
  Options,
  SavedView,
  ScanJob,
  ScanRequest,
  ScanSummary,
  WorkspaceSettings,
} from "../types";

const BASE = (import.meta.env.VITE_API_URL as string | undefined) ?? "";

export function formatCommandLine(argv: string[]): string {
  return argv
    .map(argument =>
      argument.includes(" ") || argument.includes("\t")
        ? `"${argument.replace(/"/g, '\\"')}"`
        : argument,
    )
    .join(" ");
}

export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
  if (!res.ok) {
    let message = `Request failed (${res.status})`;
    try {
      const body = await res.json();
      if (typeof body.detail === "string") message = body.detail;
      else if (Array.isArray(body.detail)) message = body.detail.map((d: { msg: string }) => d.msg).join("; ");
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(message, res.status);
  }
  return res.status === 204 ? (undefined as T) : res.json();
}

async function downloadReport(scanId: string): Promise<void> {
  const res = await fetch(`${BASE}/api/scans/${encodeURIComponent(scanId)}/report.pdf`);
  if (!res.ok) {
    let message = `Could not download report (${res.status})`;
    try {
      const body = await res.json();
      if (typeof body.detail === "string") message = body.detail;
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(message, res.status);
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `najd-recon-${scanId}-report.pdf`;
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export const api = {
  options: () => request<Options>("/api/options"),
  preview: (body: ScanRequest) =>
    request<CommandPreview>("/api/scans/preview", { method: "POST", body: JSON.stringify(body) }),
  createScan: (body: ScanRequest) =>
    request<ScanJob>("/api/scans", { method: "POST", body: JSON.stringify(body) }),
  getScan: (id: string) => request<ScanJob>(`/api/scans/${id}`),
  downloadReport,
  listScans: () => request<ScanSummary[]>("/api/scans"),
  deleteScan: (id: string) => request<void>(`/api/scans/${id}`, { method: "DELETE" }),
  assets: () => request<Asset[]>("/api/assets"),
  createAsset: (body: Omit<Asset, "id" | "created_at" | "updated_at" | "scan_count" | "latest_scan_at">) =>
    request<Asset>("/api/assets", { method: "POST", body: JSON.stringify(body) }),
  updateAsset: (id: string, body: Omit<Asset, "id" | "created_at" | "updated_at" | "scan_count" | "latest_scan_at">) =>
    request<Asset>(`/api/assets/${id}`, { method: "PUT", body: JSON.stringify(body) }),
  deleteAsset: (id: string) => request<void>(`/api/assets/${id}`, { method: "DELETE" }),
  findings: () => request<FindingRecord[]>("/api/findings"),
  updateFinding: (id: string, body: Pick<FindingRecord, "status" | "assignee" | "due_date" | "note">) =>
    request<FindingRecord>(`/api/findings/${id}`, { method: "PUT", body: JSON.stringify(body) }),
  savedViews: () => request<SavedView[]>("/api/saved-views"),
  createSavedView: (body: Pick<SavedView, "name" | "filters">) =>
    request<SavedView>("/api/saved-views", { method: "POST", body: JSON.stringify(body) }),
  deleteSavedView: (id: string) => request<void>(`/api/saved-views/${id}`, { method: "DELETE" }),
  workspaceSettings: () => request<WorkspaceSettings>("/api/workspace-settings"),
  updateWorkspaceSettings: (body: WorkspaceSettings) =>
    request<WorkspaceSettings>("/api/workspace-settings", { method: "PUT", body: JSON.stringify(body) }),
  notifications: () => request<Notification[]>("/api/notifications"),
  markNotificationRead: (id: string) =>
    request<void>(`/api/notifications/${id}/read`, { method: "POST" }),
  markAllNotificationsRead: () => request<{ updated: number }>("/api/notifications/read-all", { method: "POST" }),
  explain: (
    cveId: string,
    ctx: { product?: string | null; version?: string | null; port?: number; cvss?: number | null; is_exploit?: boolean },
  ) =>
    request<Explanation>(`/api/cves/${cveId}/explain`, { method: "POST", body: JSON.stringify(ctx) }),
  eventsUrl: (id: string) => `${BASE}/api/scans/${id}/events`,
};
