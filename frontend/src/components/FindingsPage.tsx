import { useEffect, useMemo, useState, type FormEvent } from "react";
import { api } from "../api/client";
import type { FindingRecord, SavedView } from "../types";
import { EpssBadge, SeverityBadge, Tag } from "./Badges";
import { EmptyMessage, Metric, PageIntro } from "./AssetsPage";

type Filters = { query: string; severity: string; status: string; kev: boolean };
const DEFAULT_FILTERS: Filters = { query: "", severity: "all", status: "active", kev: false };

export function FindingsPage({ search }: { search: string }) {
  const [all, setAll] = useState<FindingRecord[]>([]);
  const [views, setViews] = useState<SavedView[]>([]);
  const [filters, setFilters] = useState<Filters>(DEFAULT_FILTERS);
  const [selected, setSelected] = useState<FindingRecord | null>(null);
  const [error, setError] = useState("");
  const [saveName, setSaveName] = useState("");
  const [saving, setSaving] = useState(false);

  async function refresh() {
    try {
      const [items, saved] = await Promise.all([api.findings(), api.savedViews()]);
      setAll(items);
      setViews(saved);
    } catch (e) { setError((e as Error).message); }
  }
  useEffect(() => { void refresh(); }, []);
  useEffect(() => { if (search) setFilters(current => ({ ...current, query: search })); }, [search]);

  const records = useMemo(() => {
    const query = filters.query.trim().toLowerCase();
    return all.filter(item => {
      const matchesQuery = !query || [item.target, item.host, item.cve.id, item.service, item.product, item.version, item.cve.description]
        .join(" ").toLowerCase().includes(query);
      const matchesSeverity = filters.severity === "all" || item.cve.severity === filters.severity;
      const matchesStatus = filters.status === "all" || (filters.status === "active" ? item.status !== "resolved" : item.status === filters.status);
      return matchesQuery && matchesSeverity && matchesStatus && (!filters.kev || item.cve.in_kev);
    });
  }, [all, filters]);

  async function saveView(event: FormEvent) {
    event.preventDefault();
    if (!saveName.trim()) return;
    setSaving(true);
    try {
      const view = await api.createSavedView({ name: saveName.trim(), filters });
      setViews(current => [view, ...current]);
      setSaveName("");
      setError("");
    } catch (e) { setError((e as Error).message); }
    finally { setSaving(false); }
  }

  async function update(item: FindingRecord, body: Pick<FindingRecord, "status" | "assignee" | "due_date" | "note">) {
    try {
      const updated = await api.updateFinding(item.finding_id, body);
      setAll(current => current.map(record => record.finding_id === updated.finding_id ? updated : record));
      setSelected(updated);
      setError("");
    } catch (e) { setError((e as Error).message); }
  }

  async function removeView(id: string) {
    try { await api.deleteSavedView(id); setViews(current => current.filter(view => view.id !== id)); }
    catch (e) { setError((e as Error).message); }
  }

  function applyView(view: SavedView) {
    setFilters({ ...DEFAULT_FILTERS, ...view.filters } as Filters);
  }

  return (
    <section className="page-stack">
      <PageIntro index="04" title="Findings" description="Prioritize, assign, and track vulnerability work across completed assessments." />
      <div className="metric-row">
        <Metric label="Active findings" value={all.filter(item => item.status !== "resolved" && item.status !== "accepted").length} />
        <Metric label="Critical / high" value={all.filter(item => item.status !== "resolved" && ["critical", "high"].includes(item.cve.severity)).length} />
        <Metric label="In CISA KEV" value={all.filter(item => item.status !== "resolved" && item.cve.in_kev).length} />
        <Metric label="Resolved" value={all.filter(item => item.status === "resolved").length} />
      </div>
      <div className="card space-y-4 p-4">
        <label className="block text-xs font-medium text-ink-300">Search findings
          <input className="input mt-2" value={filters.query} onChange={event => setFilters({ ...filters, query: event.target.value })} placeholder="CVE, host, service, product, or description…" />
        </label>
        <div className="grid gap-3 sm:grid-cols-3">
          <label className="text-xs text-ink-300">Severity<select className="input mt-1.5" value={filters.severity} onChange={event => setFilters({ ...filters, severity: event.target.value })}>{["all", "critical", "high", "medium", "low", "unknown"].map(value => <option key={value}>{value}</option>)}</select></label>
          <label className="text-xs text-ink-300">Workflow status<select className="input mt-1.5" value={filters.status} onChange={event => setFilters({ ...filters, status: event.target.value })}>{[["active", "All active"], ["all", "All statuses"], ["open", "Open"], ["in_progress", "In progress"], ["accepted", "Accepted risk"], ["resolved", "Resolved"]].map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
          <label className="flex items-center gap-2 self-end pb-2 text-xs text-ink-300"><input type="checkbox" checked={filters.kev} onChange={event => setFilters({ ...filters, kev: event.target.checked })} /> CISA KEV only</label>
        </div>
        <div className="saved-views">
          <span className="text-xs font-semibold text-ink-400">SAVED VIEWS</span>
          {views.map(view => <span className="saved-view-chip" key={view.id}><button onClick={() => applyView(view)}>{view.name}</button><button aria-label={`Delete saved view ${view.name}`} onClick={() => void removeView(view.id)}>×</button></span>)}
          <form className="ml-auto flex gap-2" onSubmit={saveView}><input className="input max-w-48" maxLength={80} aria-label="Saved view name" placeholder="Name this view" value={saveName} onChange={event => setSaveName(event.target.value)} /><button className="btn-ghost" disabled={saving || !saveName.trim()}>{saving ? "Saving…" : "Save filters"}</button></form>
        </div>
      </div>
      {error && <p role="alert" className="text-sm text-sev-critical">{error}</p>}
      <div className="card overflow-hidden">
        <div className="flex items-center justify-between border-b border-ink-700/70 p-4"><div><h2 className="font-semibold">Finding register</h2><p className="mt-1 text-xs text-ink-400">{records.length} result(s) · review state is shared by this installation</p></div></div>
        {records.length === 0 ? <EmptyMessage title={all.length ? "No findings match these filters" : "No findings yet"} body={all.length ? "Change your filters or choose a saved view." : "Complete an assessment with CVE detection to populate the register."} /> : (
          <div className="finding-table-wrap"><table className="finding-table"><thead><tr><th>Finding</th><th>Asset / service</th><th>Priority</th><th>Workflow</th><th>Last observed</th></tr></thead><tbody>
            {records.map(item => <tr key={item.finding_id}>
              <td><button className="finding-open" onClick={() => setSelected(item)}><span>{item.cve.id}</span><SeverityBadge severity={item.cve.severity} score={item.cve.cvss} /></button></td>
              <td><span className="block font-mono text-xs">{item.target}:{item.port}/{item.protocol}</span><span className="text-xs text-ink-400">{[item.service, item.product, item.version].filter(Boolean).join(" ") || "Unknown service"}</span></td>
              <td><div className="flex flex-wrap gap-1">{item.cve.in_kev && <Tag tone="danger">CISA KEV</Tag>}{item.cve.epss != null && <EpssBadge epss={item.cve.epss} percentile={item.cve.epss_percentile} />}</div></td>
              <td><Tag tone={item.status === "resolved" ? "accent" : item.status === "in_progress" ? "warn" : "neutral"}>{item.status.replace("_", " ")}</Tag>{item.assignee && <span className="mt-1 block text-xs text-ink-400">{item.assignee}</span>}</td>
              <td className="text-xs text-ink-400">{new Date(item.last_seen).toLocaleDateString()}</td>
            </tr>)}
          </tbody></table></div>
        )}
      </div>
      {selected && <FindingDrawer item={selected} onClose={() => setSelected(null)} onSave={body => void update(selected, body)} />}
    </section>
  );
}

function FindingDrawer({ item, onClose, onSave }: {
  item: FindingRecord;
  onClose: () => void;
  onSave: (body: Pick<FindingRecord, "status" | "assignee" | "due_date" | "note">) => void;
}) {
  const [status, setStatus] = useState(item.status);
  const [assignee, setAssignee] = useState(item.assignee);
  const [dueDate, setDueDate] = useState(item.due_date ?? "");
  const [note, setNote] = useState(item.note);
  return <div className="drawer-backdrop" onMouseDown={event => { if (event.target === event.currentTarget) onClose(); }}>
    <aside className="finding-drawer" role="dialog" aria-modal="true" aria-labelledby="finding-title">
      <header className="flex items-start justify-between gap-4 border-b border-ink-700 p-5"><div><p className="eyebrow">VULNERABILITY RECORD</p><h2 id="finding-title" className="mt-2 font-mono text-lg">{item.cve.id}</h2><p className="mt-1 text-xs text-ink-400">{item.target} · {item.port}/{item.protocol}</p></div><button className="btn-ghost" aria-label="Close finding details" onClick={onClose}>Close</button></header>
      <div className="drawer-body space-y-5 p-5">
        <div className="flex flex-wrap gap-2"><SeverityBadge severity={item.cve.severity} score={item.cve.cvss} />{item.cve.in_kev && <Tag tone="danger">Exploited in the wild</Tag>}{item.cve.epss != null && <EpssBadge epss={item.cve.epss} />}</div>
        <section><h3 className="label">Detected service</h3><p className="text-sm">{[item.product, item.version, item.service].filter(Boolean).join(" ") || "Unknown"} on {item.host}:{item.port}/{item.protocol}</p></section>
        <section><h3 className="label">Description</h3><p className="text-sm leading-6 text-ink-300">{item.cve.description || "No description was returned for this CVE."}</p></section>
        <section className="flex flex-wrap gap-2">{item.cve.cwe.map(value => <Tag key={value}>{value}</Tag>)}{item.cve.url && <a className="btn-ghost" href={item.cve.url} target="_blank" rel="noreferrer">NVD reference ↗</a>}</section>
        <label className="block space-y-1.5 text-xs text-ink-300">Workflow status<select className="input" value={status} onChange={event => setStatus(event.target.value as FindingRecord["status"])}><option value="open">Open</option><option value="in_progress">In progress</option><option value="accepted">Accepted risk</option><option value="resolved">Resolved</option></select></label>
        <label className="block space-y-1.5 text-xs text-ink-300">Assignee<input className="input" maxLength={120} value={assignee} onChange={event => setAssignee(event.target.value)} placeholder="Team or owner" /></label>
        <label className="block space-y-1.5 text-xs text-ink-300">Remediation due date<input className="input" type="date" value={dueDate} onChange={event => setDueDate(event.target.value)} /></label>
        <label className="block space-y-1.5 text-xs text-ink-300">Review notes<textarea className="input min-h-24" maxLength={2000} value={note} onChange={event => setNote(event.target.value)} placeholder="Verification evidence, patch reference, or exception rationale…" /></label>
        <button className="btn-primary w-full" onClick={() => onSave({ status, assignee, due_date: dueDate || null, note })}>Save workflow update</button>
      </div>
    </aside>
  </div>;
}
