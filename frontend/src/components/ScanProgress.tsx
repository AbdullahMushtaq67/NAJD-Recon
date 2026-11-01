import type { ProgressEvent } from "../types";

const LABELS: Record<string, string> = {
  queued: "Queued",
  running: "Scanning with nmap",
  enriching: "Enriching CVEs",
  completed: "Complete",
  failed: "Failed",
};

export function ScanProgress({ target, event }: { target: string; event: ProgressEvent | null }) {
  const status = event?.status ?? "queued";
  const progress = event?.progress ?? 0;

  return (
    <div className="card p-6">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs uppercase tracking-wider text-ink-400">{LABELS[status]}</p>
          <p className="mt-1 font-mono text-lg">{target}</p>
        </div>
        <Radar />
      </div>
      <div className="mt-5 h-2 overflow-hidden rounded-full bg-ink-800">
        <div
          className="h-full rounded-full bg-gradient-to-r from-accent/60 to-accent transition-all duration-500"
          style={{ width: `${Math.max(progress, 3)}%` }}
        />
      </div>
      <div className="mt-2 flex justify-between text-xs text-ink-400">
        <span>{event?.current_task ?? "Waiting for a scanner slot…"}</span>
        <span className="font-mono">{progress.toFixed(0)}%</span>
      </div>
      {status === "enriching" && (
        <p className="mt-4 text-xs text-ink-400">
          Without an NVD API key, lookups are limited to 5 every 30 seconds, so this step can take
          a minute. Results are cached for next time.
        </p>
      )}
    </div>
  );
}

function Radar() {
  return (
    <div className="relative h-12 w-12">
      <div className="absolute inset-0 rounded-full border border-accent/30" />
      <div className="absolute inset-3 rounded-full border border-accent/20" />
      <div className="absolute inset-0 animate-spin rounded-full [animation-duration:2s]"
        style={{ background: "conic-gradient(from 0deg, transparent 75%, rgb(52 211 153 / 0.5))" }} />
    </div>
  );
}
