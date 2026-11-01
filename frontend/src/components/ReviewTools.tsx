import { useState } from 'react';
import { api, formatCommandLine } from '../api/client';
import { developer, difference, download, findings, inventory, toCsv } from '../api/reports';
import { useLocalState } from '../hooks/useLocalState';
import type { ScanJob, ScanSummary } from '../types';

export function ReviewTools({ job, history }: { job: ScanJob; history: ScanSummary[] }) {
  const [notes, setNotes, storageError] = useLocalState<Record<string, string>>('dir-notes', {});
  const [baseline, setBaseline] = useState<ScanJob | null>(null);
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const peers = history.filter(s => s.id !== job.id && s.target === job.target && s.status === 'completed');
  const ports = baseline ? difference(inventory(baseline), inventory(job)) : null;
  const cves = baseline ? difference(new Set(findings(baseline).map(c => c.cve)), new Set(findings(job).map(c => c.cve))) : null;
  async function compare(id: string) {
    setBaseline(null); setMessage(''); if (!id) return;
    setBusy(true);
    try { setBaseline(await api.getScan(id)); } catch(e) { setMessage((e as Error).message); }
    finally { setBusy(false); }
  }
  return <section className="card space-y-4 p-5 review-tools">
    <h2 className="font-semibold">Assessment workspace</h2>
    <p className="text-xs text-ink-400">Developed by {developer}. Notes and review decisions are saved only in this browser.</p>
    <div className="flex flex-wrap gap-2 no-print">
      <button className="btn-ghost" onClick={() => download(`najd-recon-${job.id}.json`, JSON.stringify({ app: 'NAJD Recon', developer, scan: job, notes: notes[job.id] ?? '' }, null, 2), 'application/json')}>Export JSON</button>
      <button className="btn-ghost" onClick={() => download(`najd-recon-${job.id}.csv`, toCsv(job), 'text/csv;charset=utf-8')}>Export CVE CSV</button>
      <button className="btn-ghost" onClick={() => window.print()}>Print / save PDF</button>
      <button className="btn-ghost" onClick={async () => { try { await navigator.clipboard.writeText(formatCommandLine(job.command)); setMessage('Command copied.'); } catch { setMessage('Clipboard unavailable. Copy the command shown below.'); } }}>Copy command</button>
    </div>
    <pre className="overflow-auto text-xs">{formatCommandLine(job.command)}</pre>
    <label className="block text-sm no-print">Assessment notes<textarea className="input mt-2" rows={3} maxLength={10000} value={notes[job.id] ?? ''} onChange={e => setNotes({ ...notes, [job.id]: e.target.value })} placeholder="Scope, verification evidence, and next actions…" /></label>
    <p className="print-notes whitespace-pre-wrap">Assessment notes: {notes[job.id] || "None"}</p>
    {storageError && <p role="alert">{storageError}</p>}
    <label className="block text-sm no-print">Compare with another completed scan of {job.target}
      <select className="input mt-2" disabled={busy} defaultValue="" onChange={e => void compare(e.target.value)}><option value="">Select baseline ({peers.length} available)</option>{peers.map(s => <option key={s.id} value={s.id}>{new Date(s.created_at).toLocaleString()} · {s.id.slice(0,8)}</option>)}</select>
    </label>
    {busy && <p role="status">Loading baseline…</p>}
    {ports && cves && <div className="space-y-2 text-sm"><p>Compared with {baseline?.created_at}. Disappeared findings need verification; they do not prove remediation.</p>{[['New open ports',ports.added],['No longer observed open ports',ports.removed],['New CVEs',cves.added],['No longer observed CVEs',cves.removed]].map(([label, values]) => <p key={label as string}><strong>{label}: </strong>{(values as string[]).join(', ') || 'None'}</p>)}</div>}
    {message && <p role="status" className="text-sm">{message}</p>}
  </section>;
}
