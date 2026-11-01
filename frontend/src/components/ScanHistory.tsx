import { useState } from "react";
import { useLocalState } from "../hooks/useLocalState";
import type { ScanSummary } from "../types";
import { StatusDot } from "./Badges";

interface Props {
  scans: ScanSummary[];
  activeId: string | null;
  onSelect: (id: string) => void;
  onDelete: (id: string) => void;
}

export function ScanHistory({ scans, activeId, onSelect, onDelete }: Props) {
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("all");
  const [starredOnly, setStarredOnly] = useState(false);
  const [stars, setStars, storageError] = useLocalState<string[]>("dir-starred", []);
  const visible = scans.filter(s => s.target.toLowerCase().includes(query.toLowerCase()) && (status === "all" || s.status === status) && (!starredOnly || stars.includes(s.id)));
  return (
    <div className="card p-4">
      <h2 className="label">History</h2>
      <div className="mb-3 space-y-2 no-print">
        <input aria-label="Search scan history" className="input" value={query} onChange={e => setQuery(e.target.value)} placeholder="Search targets…" />
        <select aria-label="Filter history by status" className="input" value={status} onChange={e => setStatus(e.target.value)}>{["all","queued","running","enriching","completed","failed"].map(s => <option key={s}>{s}</option>)}</select>
        <label className="text-xs"><input type="checkbox" checked={starredOnly} onChange={e => setStarredOnly(e.target.checked)} /> Bookmarked only</label>
        {storageError && <p role="alert">{storageError}</p>}
      </div>
      {scans.length > 0 && !visible.length && <p className="py-2 text-xs">No scans match your filters.</p>}
      {scans.length === 0 ? (
        <p className="py-2 text-xs text-ink-400">No scans yet.</p>
      ) : (
        <ul className="-mx-1 max-h-80 space-y-0.5 overflow-y-auto">
          {visible.map((s) => (
            <li key={s.id} className="group flex items-center">
              <button className="btn-ghost" aria-label={`Bookmark ${s.target}`} aria-pressed={stars.includes(s.id)} onClick={() => setStars(stars.includes(s.id) ? stars.filter(id => id !== s.id) : [...stars, s.id])}>{stars.includes(s.id) ? "★" : "☆"}</button>
              <button
                type="button"
                onClick={() => onSelect(s.id)}
                className={`flex min-w-0 flex-1 items-center gap-2.5 rounded-lg px-2 py-2 text-left transition ${
                  s.id === activeId ? "bg-ink-800" : "hover:bg-ink-800/60"
                }`}
              >
                <StatusDot status={s.status} />
                <span className="min-w-0 flex-1">
                  <span className="block truncate font-mono text-xs">{s.target}</span>
                  <span className="block text-[11px] text-ink-400">
                    {new Date(s.created_at).toLocaleString()} Â· {s.open_ports} open Â· {s.cve_count} CVEs
                  </span>
                </span>
                {!!s.severity_counts?.critical && (
                  <span className="rounded bg-sev-critical/15 px-1.5 text-[11px] font-semibold text-sev-critical">
                    {s.severity_counts.critical}
                  </span>
                )}
              </button>
              <button
                type="button"
                aria-label={`Delete scan of ${s.target}`}
                onClick={() => onDelete(s.id)}
                className="ml-1 rounded px-1.5 py-1 text-xs text-ink-400 opacity-0 transition hover:text-sev-critical group-hover:opacity-100 focus:opacity-100"
              >
                âœ•
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
