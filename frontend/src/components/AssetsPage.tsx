import { useEffect, useState, type FormEvent } from "react";
import { api } from "../api/client";
import type { Asset, ScanSummary } from "../types";
import { Tag } from "./Badges";

type AssetDraft = Pick<Asset, "name" | "target" | "owner" | "environment" | "criticality" | "tags" | "notes">;
const EMPTY: AssetDraft = {
  name: "",
  target: "",
  owner: "",
  environment: "production",
  criticality: "medium",
  tags: [],
  notes: "",
};

export function AssetsPage({ scans, search, onOpenScan }: { scans: ScanSummary[]; search: string; onOpenScan: (id: string) => void }) {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [draft, setDraft] = useState<AssetDraft>(EMPTY);
  const [editing, setEditing] = useState<string | null>(null);
  const [tagText, setTagText] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const visibleAssets = assets.filter(asset => [asset.name, asset.target, asset.owner, asset.environment, ...asset.tags].join(" ").toLowerCase().includes(search.toLowerCase()));

  async function refresh() {
    try { setAssets(await api.assets()); } catch (e) { setError((e as Error).message); }
  }
  useEffect(() => { void refresh(); }, []);

  function edit(asset: Asset) {
    setEditing(asset.id);
    setDraft({ name: asset.name, target: asset.target, owner: asset.owner, environment: asset.environment, criticality: asset.criticality, tags: asset.tags, notes: asset.notes });
    setTagText(asset.tags.join(", "));
    setError("");
    document.getElementById("asset-form")?.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    const body = { ...draft, tags: tagText.split(",").map(tag => tag.trim()).filter(Boolean) };
    try {
      if (editing) await api.updateAsset(editing, body);
      else await api.createAsset(body);
      setDraft(EMPTY);
      setTagText("");
      setEditing(null);
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally { setBusy(false); }
  }

  async function remove(asset: Asset) {
    if (!window.confirm(`Remove ${asset.name} from the asset inventory? Scan history will remain.`)) return;
    try { await api.deleteAsset(asset.id); await refresh(); }
    catch (e) { setError((e as Error).message); }
  }

  return (
    <section className="page-stack">
      <PageIntro index="02" title="Asset inventory" description="Keep an organized record of in-scope systems and their assessment history." />
      <div className="metric-row">
        <Metric label="Registered assets" value={assets.length} />
        <Metric label="Production" value={assets.filter(asset => asset.environment.toLowerCase() === "production").length} />
        <Metric label="Critical assets" value={assets.filter(asset => asset.criticality === "critical").length} />
        <Metric label="Assets assessed" value={assets.filter(asset => asset.scan_count > 0).length} />
      </div>
      <form id="asset-form" className="card space-y-4 p-5" onSubmit={submit}>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div><h2 className="font-semibold">{editing ? "Update asset" : "Register an asset"}</h2><p className="mt-1 text-xs text-ink-400">Inventory records do not expand scan authorization; each scan still follows the server allowlist.</p></div>
          {editing && <button className="btn-ghost" type="button" onClick={() => { setEditing(null); setDraft(EMPTY); setTagText(""); }}>Cancel edit</button>}
        </div>
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          <Field label="Asset name"><input className="input" required maxLength={120} value={draft.name} onChange={e => setDraft({ ...draft, name: e.target.value })} placeholder="Public web server" /></Field>
          <Field label="Host / target"><input className="input font-mono" required maxLength={253} value={draft.target} onChange={e => setDraft({ ...draft, target: e.target.value })} placeholder="192.0.2.10 or host.example" /></Field>
          <Field label="Owner"><input className="input" maxLength={120} value={draft.owner} onChange={e => setDraft({ ...draft, owner: e.target.value })} placeholder="Platform team" /></Field>
          <Field label="Environment"><select className="input" value={draft.environment} onChange={e => setDraft({ ...draft, environment: e.target.value })}>{["production", "staging", "development", "lab", "other"].map(item => <option key={item}>{item}</option>)}</select></Field>
          <Field label="Business criticality"><select className="input" value={draft.criticality} onChange={e => setDraft({ ...draft, criticality: e.target.value as AssetDraft["criticality"] })}>{["critical", "high", "medium", "low"].map(item => <option key={item}>{item}</option>)}</select></Field>
          <Field label="Tags (comma separated)"><input className="input" value={tagText} onChange={e => setTagText(e.target.value)} placeholder="internet-facing, pci" /></Field>
          <Field label="Assessment notes"><textarea className="input min-h-20 sm:col-span-2 xl:col-span-3" maxLength={2000} value={draft.notes} onChange={e => setDraft({ ...draft, notes: e.target.value })} placeholder="Purpose, ownership context, verification notes…" /></Field>
        </div>
        {error && <p role="alert" className="text-sm text-sev-critical">{error}</p>}
        <button className="btn-primary" type="submit" disabled={busy}>{busy ? "Saving…" : editing ? "Save asset" : "Add to inventory"}</button>
      </form>

      <div className="card overflow-hidden">
        <div className="border-b border-ink-700/70 p-4"><h2 className="font-semibold">Managed assets</h2><p className="mt-1 text-xs text-ink-400">Shared workspace inventory · {assets.length} record(s)</p></div>
        {visibleAssets.length === 0 ? <EmptyMessage title={assets.length ? "No assets match your search" : "No assets registered"} body={assets.length ? "Try a different search term." : "Add the systems your team is authorized to assess."} /> : (
          <div className="divide-y divide-ink-700/60">
            {visibleAssets.map(asset => {
              const latest = scans.find(scan => scan.target.toLowerCase() === asset.target.toLowerCase() && scan.status === "completed");
              return <article key={asset.id} className="asset-row">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2"><h3 className="font-semibold">{asset.name}</h3><Tag tone={asset.criticality === "critical" ? "danger" : asset.criticality === "high" ? "warn" : "neutral"}>{asset.criticality} criticality</Tag><Tag>{asset.environment}</Tag></div>
                  <p className="mt-1 font-mono text-xs text-ink-300">{asset.target}</p>
                  <p className="mt-2 text-xs text-ink-400">{asset.owner || "No owner"} · {asset.scan_count} completed scan(s){asset.latest_scan_at ? ` · Last ${new Date(asset.latest_scan_at).toLocaleString()}` : " · Not scanned yet"}</p>
                  {!!asset.tags.length && <div className="mt-2 flex flex-wrap gap-1">{asset.tags.map(tag => <Tag key={tag}>{tag}</Tag>)}</div>}
                  {asset.notes && <p className="mt-2 text-xs text-ink-400">{asset.notes}</p>}
                </div>
                <div className="flex flex-wrap gap-2">
                  {latest && <button className="btn-ghost" onClick={() => onOpenScan(latest.id)}>Latest scan</button>}
                  <button className="btn-ghost" onClick={() => edit(asset)}>Edit</button>
                  <button className="btn-ghost" aria-label={`Remove ${asset.name}`} onClick={() => void remove(asset)}>Remove</button>
                </div>
              </article>;
            })}
          </div>
        )}
      </div>
    </section>
  );
}

export function PageIntro({ index, title, description, action }: { index: string; title: string; description: string; action?: import("react").ReactNode }) {
  return <header className="page-intro"><div><p className="eyebrow"><span className="eyebrow-mark">{index}</span> NAJD RECON WORKSPACE</p><h1>{title}</h1><p>{description}</p></div>{action}</header>;
}

export function Metric({ label, value, hint }: { label: string; value: string | number; hint?: string }) {
  return <div className="metric-card"><span className="metric-label">{label}</span><strong>{value}</strong>{hint && <small>{hint}</small>}</div>;
}

export function EmptyMessage({ title, body }: { title: string; body: string }) {
  return <div className="empty-message"><strong>{title}</strong><p>{body}</p></div>;
}

function Field({ label, children }: { label: string; children: import("react").ReactNode }) {
  return <label className="block space-y-1.5 text-xs font-medium text-ink-300">{label}{children}</label>;
}
