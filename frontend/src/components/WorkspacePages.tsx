import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../api/client";
import type { Asset, FindingRecord, Notification, ScanJob, ScanSummary, WorkspaceSettings } from "../types";
import { StatusDot, Tag } from "./Badges";
import { EmptyMessage, Metric, PageIntro } from "./AssetsPage";
import { difference, findings, inventory } from "../api/reports";

export function OverviewPage({
  scans,
  onOpenScan,
}: {
  scans: ScanSummary[];
  onOpenScan: (id: string) => void;
}) {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [findingsData, setFindingsData] = useState<FindingRecord[]>([]);
  const [error, setError] = useState("");
  useEffect(() => {
    Promise.all([api.assets(), api.findings()])
      .then(([assetRows, findingRows]) => { setAssets(assetRows); setFindingsData(findingRows); })
      .catch(e => setError((e as Error).message));
  }, []);

  const recent = scans.slice(0, 8);
  const risk = useMemo(() => {
    const active = findingsData.filter(item => item.status !== "resolved" && item.status !== "accepted");
    return {
      critical: active.filter(item => item.cve.severity === "critical").length,
      high: active.filter(item => item.cve.severity === "high").length,
      kev: active.filter(item => item.cve.in_kev).length,
    };
  }, [findingsData]);
  const trend = useMemo(() => {
    const buckets = Array.from({ length: 7 }, (_, index) => {
      const date = new Date();
      date.setDate(date.getDate() - (6 - index));
      const key = date.toLocaleDateString(undefined, { month: "short", day: "numeric" });
      return { key, count: scans.filter(scan => new Date(scan.created_at).toDateString() === date.toDateString()).length };
    });
    const max = Math.max(1, ...buckets.map(bucket => bucket.count));
    return buckets.map(bucket => ({ ...bucket, height: Math.max(6, bucket.count / max * 100) }));
  }, [scans]);

  return <section className="page-stack">
    <PageIntro index="01" title="Security overview" description="A clear view of your registered assets, assessment activity, and prioritized exposure." />
    <div className="metric-row">
      <Metric label="Registered assets" value={assets.length} hint="in the workspace" />
      <Metric label="Completed scans" value={scans.filter(scan => scan.status === "completed").length} hint="saved assessments" />
      <Metric label="Active critical" value={risk.critical} hint={`${risk.high} high severity`} />
      <Metric label="CISA KEV findings" value={risk.kev} hint="known exploited" />
    </div>
    <div className="overview-grid">
      <section className="card p-5"><div className="flex items-start justify-between"><div><h2 className="font-semibold">Assessment activity</h2><p className="mt-1 text-xs text-ink-400">Completed scans · last 7 calendar days</p></div><Tag>7 days</Tag></div>
        <div className="activity-chart" role="img" aria-label={`Scan activity: ${trend.map(point => `${point.key}, ${point.count} scans`).join("; ")}`}>
          {trend.map(point => <div className="activity-column" key={point.key}><span className="activity-bar" style={{ height: `${point.height}%` }} title={`${point.count} scan(s)`} /><span>{point.key}</span></div>)}
        </div>
      </section>
      <section className="card p-5"><h2 className="font-semibold">Priority distribution</h2><p className="mt-1 text-xs text-ink-400">Active finding instances</p>
        <div className="risk-distribution"><RiskLine label="Critical" count={risk.critical} color="critical" total={findingsData.length} /><RiskLine label="High" count={risk.high} color="high" total={findingsData.length} /><RiskLine label="Known exploited" count={risk.kev} color="kev" total={findingsData.length} /></div>
      </section>
    </div>
    {error && <p role="alert" className="text-sm text-sev-critical">{error}</p>}
    <section className="card overflow-hidden"><div className="border-b border-ink-700/70 p-4"><h2 className="font-semibold">Recent assessments</h2><p className="mt-1 text-xs text-ink-400">Select an assessment to inspect the results.</p></div>
      {recent.length ? <div className="divide-y divide-ink-700/60">{recent.map(scan => <button key={scan.id} className="recent-scan-row" onClick={() => onOpenScan(scan.id)}><StatusDot status={scan.status} /><span className="min-w-0 flex-1 text-left"><strong className="block truncate font-mono text-xs">{scan.target}</strong><span className="mt-1 block text-xs text-ink-400">{new Date(scan.created_at).toLocaleString()} · {scan.open_ports} open ports · {scan.cve_count} CVEs</span></span><span className="text-xs text-ink-400">{scan.status}</span></button>)}</div> : <EmptyMessage title="No assessments yet" body="Create an authorized scan to start building an exposure history." />}
    </section>
  </section>;
}

export function ScansPage({
  scans,
  search,
  onOpenScan,
}: {
  scans: ScanSummary[];
  search: string;
  onOpenScan: (id: string) => void;
}) {
  const [query, setQuery] = useState(search);
  const [status, setStatus] = useState("all");
  const [leftId, setLeftId] = useState("");
  const [rightId, setRightId] = useState("");
  const [left, setLeft] = useState<ScanJob | null>(null);
  const [right, setRight] = useState<ScanJob | null>(null);
  const [error, setError] = useState("");
  useEffect(() => { if (search) setQuery(search); }, [search]);
  const visible = scans.filter(scan => scan.target.toLowerCase().includes(query.toLowerCase()) && (status === "all" || scan.status === status));
  const baselineTarget = scans.find(scan => scan.id === leftId)?.target;

  async function compare() {
    if (!leftId || !rightId) return;
    setError("");
    setLeft(null);
    setRight(null);
    try {
      const [a, b] = await Promise.all([api.getScan(leftId), api.getScan(rightId)]);
      if (a.status !== "completed" || b.status !== "completed" || a.target !== b.target) {
        setError("Choose completed assessments for the same target.");
        return;
      }
      setLeft(a); setRight(b);
    } catch (e) { setError((e as Error).message); }
  }
  const portDiff = left && right ? difference(inventory(left), inventory(right)) : null;
  const cveDiff = left && right ? difference(new Set(findings(left).map(item => item.cve)), new Set(findings(right).map(item => item.cve))) : null;

  return <section className="page-stack">
    <PageIntro index="03" title="Scan history" description="Search saved assessments, review outcomes, or compare two runs side by side." />
    <div className="card space-y-3 p-4"><div className="grid gap-3 sm:grid-cols-[1fr_220px]"><label className="text-xs text-ink-300">Search target<input className="input mt-1.5" value={query} onChange={event => setQuery(event.target.value)} placeholder="Hostname or address" /></label><label className="text-xs text-ink-300">Status<select className="input mt-1.5" value={status} onChange={event => setStatus(event.target.value)}>{["all", "queued", "running", "enriching", "completed", "failed"].map(item => <option key={item}>{item}</option>)}</select></label></div></div>
    <section className="card overflow-hidden"><div className="border-b border-ink-700/70 p-4"><h2 className="font-semibold">Assessment archive</h2><p className="mt-1 text-xs text-ink-400">{visible.length} of {scans.length} scan(s)</p></div>
      {visible.length ? <div className="divide-y divide-ink-700/60">{visible.map(scan => <div key={scan.id} className="recent-scan-row"><StatusDot status={scan.status} /><button className="min-w-0 flex-1 text-left" onClick={() => onOpenScan(scan.id)}><strong className="block truncate font-mono text-xs">{scan.target}</strong><span className="mt-1 block text-xs text-ink-400">{new Date(scan.created_at).toLocaleString()} · {scan.open_ports} open · {scan.cve_count} CVEs</span></button>{scan.severity_counts?.critical ? <Tag tone="danger">{scan.severity_counts.critical} critical</Tag> : null}<button className="btn-ghost" onClick={() => onOpenScan(scan.id)}>Open</button></div>)}</div> : <EmptyMessage title="No scans found" body="Try a different search or status filter." />}
    </section>
    <section className="card space-y-4 p-5"><div><h2 className="font-semibold">Side-by-side comparison</h2><p className="mt-1 text-xs text-ink-400">Compare completed assessments of the same target. Missing findings are not proof of remediation.</p></div>
      <div className="grid gap-3 sm:grid-cols-2"><label className="text-xs text-ink-300">Baseline<select className="input mt-1.5" value={leftId} onChange={event => { setLeftId(event.target.value); setRightId(""); setLeft(null); setRight(null); setError(""); }}><option value="">Select scan</option>{scans.filter(scan => scan.status === "completed").map(scan => <option key={scan.id} value={scan.id}>{scan.target} · {new Date(scan.created_at).toLocaleString()}</option>)}</select></label><label className="text-xs text-ink-300">Current assessment<select className="input mt-1.5" value={rightId} onChange={event => { setRightId(event.target.value); setLeft(null); setRight(null); setError(""); }}><option value="">Select scan</option>{scans.filter(scan => scan.status === "completed" && scan.id !== leftId && scan.target === baselineTarget).map(scan => <option key={scan.id} value={scan.id}>{scan.target} · {new Date(scan.created_at).toLocaleString()}</option>)}</select></label></div>
      <button className="btn-primary" disabled={!leftId || !rightId} onClick={() => void compare()}>Compare assessments</button>
      {error && <p role="alert" className="text-sm text-sev-critical">{error}</p>}
      {left && right && portDiff && cveDiff && <div className="compare-grid"><CompareColumn title="Baseline" job={left} /><CompareColumn title="Current" job={right} /><CompareDiff title="Open ports added" items={portDiff.added} /><CompareDiff title="Open ports no longer observed" items={portDiff.removed} /><CompareDiff title="New CVEs" items={cveDiff.added} /><CompareDiff title="CVEs no longer observed" items={cveDiff.removed} /></div>}
    </section>
  </section>;
}

function CompareColumn({ title, job }: { title: string; job: ScanJob }) {
  return <div className="compare-cell"><span>{title}</span><strong>{job.target}</strong><small>{job.result?.hosts.flatMap(host => host.ports.filter(port => port.state === "open")).length ?? 0} open ports · {job.result?.hosts.flatMap(host => host.ports.flatMap(port => port.cves)).length ?? 0} CVEs</small><small>{new Date(job.finished_at ?? job.created_at).toLocaleString()}</small></div>;
}

function CompareDiff({ title, items }: { title: string; items: string[] }) {
  return <div className="compare-cell"><span>{title}</span>{items.length ? <ul>{items.map(item => <li key={item}>{item}</li>)}</ul> : <small>None</small>}</div>;
}

export function SettingsPage() {
  const [settings, setSettings] = useState<WorkspaceSettings | null>(null);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState(false);
  useEffect(() => { api.workspaceSettings().then(setSettings).catch(e => setError((e as Error).message)); }, []);
  const update = useCallback(<K extends keyof WorkspaceSettings>(key: K, value: WorkspaceSettings[K]) => {
    setSettings(current => current ? { ...current, [key]: value } : current);
    setSaved(false);
  }, []);
  async function save() {
    if (!settings) return;
    try { setSettings(await api.updateWorkspaceSettings(settings)); setError(""); setSaved(true); }
    catch (e) { setError((e as Error).message); }
  }
  if (!settings) return <section className="page-stack"><PageIntro index="06" title="Workspace settings" description="Configure shared report branding and notification preferences." /><p role="status">Loading workspace settings…</p></section>;
  return <section className="page-stack"><PageIntro index="06" title="Workspace settings" description="Configure shared report branding and notification preferences." />
    <section className="card space-y-4 p-5"><div><h2 className="font-semibold">Assessment identity</h2><p className="mt-1 text-xs text-ink-400">These settings apply across this installation and appear in generated reports.</p></div>
      <div className="grid gap-3 sm:grid-cols-2"><SettingsField label="Workspace name" value={settings.workspace_name} onChange={value => update("workspace_name", value)} /><SettingsField label="Report subtitle" value={settings.report_subtitle} onChange={value => update("report_subtitle", value)} /><SettingsField label="Report contact / prepared by" value={settings.report_contact} onChange={value => update("report_contact", value)} /><SettingsField label="Report confidentiality footer" value={settings.report_footer} onChange={value => update("report_footer", value)} /></div>
    </section>
    <section className="card space-y-4 p-5"><div><h2 className="font-semibold">Notification preferences</h2><p className="mt-1 text-xs text-ink-400">In-app notifications are generated for future scan results.</p></div>
      <div className="space-y-3">{([["notify_critical", "High-priority findings", "Alert on critical/high severity and CISA KEV matches."], ["notify_new_scan", "Completed assessments", "Add an activity notification when a scan completes."], ["notify_scan_failure", "Failed assessments", "Alert when a scan cannot complete."]] as const).map(([key, title, description]) => <label className="setting-toggle" key={key}><span><strong>{title}</strong><small>{description}</small></span><input type="checkbox" checked={settings[key]} onChange={event => update(key, event.target.checked)} /></label>)}</div>
    </section>
    <div className="flex flex-wrap items-center gap-3"><button className="btn-primary" onClick={() => void save()}>Save workspace settings</button>{saved && <span role="status" className="text-sm text-accent">Settings saved.</span>}{error && <span role="alert" className="text-sm text-sev-critical">{error}</span>}</div>
    <p className="text-xs text-ink-400">This is currently one shared workspace with no user accounts. Add authentication before deploying to untrusted users or separate organizations.</p>
  </section>;
}

export function NotificationCenter({ onOpenScan }: { onOpenScan: (id: string) => void }) {
  const [items, setItems] = useState<Notification[]>([]);
  const [open, setOpen] = useState(false);
  const [error, setError] = useState("");
  const refresh = useCallback(() => {
    api.notifications().then(setItems).catch(e => setError((e as Error).message));
  }, []);
  useEffect(() => {
    refresh();
    const timer = window.setInterval(refresh, 30000);
    return () => window.clearInterval(timer);
  }, [refresh]);
  const unread = items.filter(item => !item.read_at).length;
  async function markAll() {
    try { await api.markAllNotificationsRead(); refresh(); }
    catch (e) { setError((e as Error).message); }
  }
  async function openItem(item: Notification) {
    try {
      if (!item.read_at) await api.markNotificationRead(item.id);
      setOpen(false);
      refresh();
      if (item.scan_id) onOpenScan(item.scan_id);
    } catch (e) { setError((e as Error).message); }
  }
  return <div className="notification-center">
    <button className="notification-trigger" aria-label={`Notifications${unread ? `, ${unread} unread` : ""}`} aria-expanded={open} onClick={() => setOpen(current => !current)}><span aria-hidden="true">♧</span><span className="notification-trigger-label">Alerts</span>{unread > 0 && <span className="notification-count">{unread > 9 ? "9+" : unread}</span>}</button>
    {open && <div className="notification-popover" role="dialog" aria-label="Notifications"><header><div><strong>Notifications</strong><small>{unread} unread</small></div><button className="btn-ghost" disabled={!unread} onClick={() => void markAll()}>Mark all read</button></header>{error && <p role="alert" className="px-4 pt-3 text-xs text-sev-critical">{error}</p>}{items.length ? <ul>{items.slice(0, 20).map(item => <li key={item.id}><button className={`notification-item ${item.read_at ? "" : "is-unread"}`} onClick={() => void openItem(item)}><span className={`notification-severity ${item.severity}`} /><span><strong>{item.title}</strong><small>{item.message}</small><small>{new Date(item.created_at).toLocaleString()}</small></span></button></li>)}</ul> : <EmptyMessage title="No alerts yet" body="Scan updates and important findings will appear here." />}</div>}
  </div>;
}

function RiskLine({ label, count, color, total }: { label: string; count: number; color: string; total: number }) {
  return <div className="risk-line"><span>{label}</span><div className="risk-track"><span className={`risk-fill ${color}`} style={{ width: `${total ? Math.max(count / total * 100, count ? 3 : 0) : 0}%` }} /></div><strong>{count}</strong></div>;
}

function SettingsField({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) {
  return <label className="block space-y-1.5 text-xs text-ink-300">{label}<input className="input" maxLength={200} value={value} onChange={event => onChange(event.target.value)} /></label>;
}
