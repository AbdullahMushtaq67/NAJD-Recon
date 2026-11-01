import type { ReactNode } from "react";
import type { ScanStatus, Severity } from "../types";

export const SEVERITY_STYLES: Record<Severity, string> = {
  critical: "bg-sev-critical/15 text-sev-critical ring-sev-critical/40",
  high: "bg-sev-high/15 text-sev-high ring-sev-high/40",
  medium: "bg-sev-medium/15 text-sev-medium ring-sev-medium/40",
  low: "bg-sev-low/15 text-sev-low ring-sev-low/40",
  none: "bg-sev-unknown/15 text-sev-unknown ring-sev-unknown/40",
  unknown: "bg-sev-unknown/15 text-sev-unknown ring-sev-unknown/40",
};

export function SeverityBadge({ severity, score }: { severity: Severity; score?: number | null }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-semibold uppercase ring-1 ring-inset ${SEVERITY_STYLES[severity]}`}
    >
      {score != null && <span className="font-mono">{score.toFixed(1)}</span>}
      {severity}
    </span>
  );
}

export function Tag({ children, tone = "neutral", title }: { children: ReactNode; tone?: "danger" | "warn" | "neutral" | "accent"; title?: string }) {
  const tones = {
    danger: "bg-sev-critical/10 text-sev-critical ring-sev-critical/30",
    warn: "bg-sev-high/10 text-sev-high ring-sev-high/30",
    neutral: "bg-ink-800 text-ink-300 ring-ink-700",
    accent: "bg-accent/10 text-accent ring-accent/30",
  };
  return (
    <span
      title={title}
      className={`inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-medium ring-1 ring-inset ${tones[tone]}`}
    >
      {children}
    </span>
  );
}

/** EPSS is a probability; show it the way FIRST and vulners do (e.g. "94%", ">99%", "<1%"). */
export function formatEpss(epss: number): string {
  if (epss >= 0.995) return ">99%";
  if (epss >= 0.01) return `${Math.round(epss * 100)}%`;
  return "<1%";
}

export function EpssBadge({ epss, percentile }: { epss: number; percentile?: number | null }) {
  const tone =
    epss >= 0.1
      ? "bg-sev-high/15 text-sev-high ring-sev-high/40"
      : epss >= 0.01
        ? "bg-sev-medium/10 text-sev-medium ring-sev-medium/30"
        : "bg-ink-800 text-ink-300 ring-ink-700";
  const title =
    "EPSS: estimated probability this vulnerability is exploited in the next 30 days" +
    (percentile != null ? ` (higher than ${Math.floor(percentile * 100)}% of all CVEs)` : "");
  return (
    <span
      title={title}
      className={`inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-semibold ring-1 ring-inset ${tone}`}
    >
      <span className="font-normal opacity-80">EPSS</span>
      <span className="font-mono">{formatEpss(epss)}</span>
    </span>
  );
}

const STATUS_DOT: Record<ScanStatus, string> = {
  queued: "bg-ink-400",
  running: "bg-accent animate-pulse",
  enriching: "bg-sky-400 animate-pulse",
  completed: "bg-accent",
  failed: "bg-sev-critical",
};

export function StatusDot({ status }: { status: ScanStatus }) {
  return <span className={`inline-block h-2 w-2 shrink-0 rounded-full ${STATUS_DOT[status]}`} />;
}
