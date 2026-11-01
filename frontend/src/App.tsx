import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "./api/client";
import { Tag } from "./components/Badges";
import { AssetsPage } from "./components/AssetsPage";
import { FindingsPage } from "./components/FindingsPage";
import { ReportsPage } from "./components/ReportsPage";
import { ReviewTools } from "./components/ReviewTools";
import { ScanForm } from "./components/ScanForm";
import { ScanHistory } from "./components/ScanHistory";
import { ScanProgress } from "./components/ScanProgress";
import { ScanResults } from "./components/ScanResults";
import {
  NotificationCenter,
  OverviewPage,
  ScansPage,
  SettingsPage,
} from "./components/WorkspacePages";
import { useScanEvents } from "./hooks/useScanEvents";
import type { Options, ScanJob, ScanRequest, ScanSummary } from "./types";

type Page = "overview" | "assets" | "scans" | "findings" | "reports" | "settings";
const NAV_ITEMS: { id: Page; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "assets", label: "Assets" },
  { id: "scans", label: "Scans" },
  { id: "findings", label: "Findings" },
  { id: "reports", label: "Reports" },
  { id: "settings", label: "Settings" },
];
const isFinished = (job: ScanJob | null) =>
  job?.status === "completed" || job?.status === "failed";

export default function App() {
  const [page, setPage] = useState<Page>("overview");
  const [globalSearch, setGlobalSearch] = useState("");
  const [options, setOptions] = useState<Options | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [history, setHistory] = useState<ScanSummary[]>([]);
  const [job, setJob] = useState<ScanJob | null>(null);
  const mainRef = useRef<HTMLElement>(null);
  const jobId = job?.id;

  useEffect(() => {
    if (jobId && page === "overview") mainRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [jobId, page]);

  const refreshHistory = useCallback(() => {
    api.listScans().then(setHistory).catch(() => undefined);
  }, []);

  useEffect(() => {
    api.options().then(setOptions).catch((error: Error) => setLoadError(error.message));
    refreshHistory();
  }, [refreshHistory]);

  const live = job !== null && !isFinished(job);
  const event = useScanEvents(job?.id ?? null, live);
  useEffect(() => {
    if (!job || !event || (event.status !== "completed" && event.status !== "failed")) return;
    api.getScan(job.id).then(full => {
      setJob(full);
      refreshHistory();
    }).catch((error: Error) => setActionError(error.message));
  }, [event, job, refreshHistory]);

  async function startScan(request: ScanRequest) {
    const created = await api.createScan(request);
    setJob(created);
    refreshHistory();
  }

  async function selectScan(id: string) {
    try { setJob(await api.getScan(id)); setActionError(null); }
    catch (error) { setActionError((error as Error).message); }
  }

  async function openScan(id: string) {
    await selectScan(id);
    setPage("overview");
  }

  async function deleteScan(id: string) {
    try { await api.deleteScan(id); }
    catch (error) { setActionError((error as Error).message); return; }
    if (job?.id === id) setJob(null);
    refreshHistory();
  }

  return (
    <div className="app-shell min-h-screen px-4 pb-10 sm:px-6">
      <header className="topbar mx-auto flex max-w-[1600px] flex-wrap items-center gap-5 py-5">
        <a className="brand-lockup" href="#top" aria-label="NAJD Recon home" onClick={() => setPage("overview")}>
          <img src="/najd-recon-logo.png" alt="NAJD Recon" className="brand-logo" />
        </a>
        <div className="hidden items-center gap-2 text-xs text-ink-400 md:flex">
          <span className="status-pulse" />
          <span>RECONNAISSANCE WORKSPACE</span>
        </div>
        <nav className="top-nav ml-auto flex items-center gap-1" aria-label="Main navigation">
          {NAV_ITEMS.map(item => (
            <button key={item.id} type="button" className={page === item.id ? "is-active" : ""}
              aria-current={page === item.id ? "page" : undefined} onClick={() => setPage(item.id)}>
              {item.label}
            </button>
          ))}
        </nav>
        <div className="header-actions flex w-full items-center gap-2 border-t border-ink-700/70 pt-3 sm:w-auto sm:border-0 sm:pt-0">
          <label className="global-search">
            <span className="sr-only">Search workspace</span>
            <input aria-label="Search workspace" value={globalSearch} onChange={event => setGlobalSearch(event.target.value)} placeholder="Search workspace…" />
            <span aria-hidden="true">⌕</span>
          </label>
          <NotificationCenter onOpenScan={id => void openScan(id)} />
          {options && <Tag tone={options.demo_mode ? "warn" : "accent"}>{options.demo_mode ? "Demo replay" : "Live Nmap"}</Tag>}
          {options && <Tag tone={options.ai_enabled ? "accent" : "neutral"}>AI {options.ai_enabled ? `· ${options.ai_provider}` : "· off"}</Tag>}
        </div>
      </header>

      {loadError && <div className="card mx-auto mb-6 max-w-[1600px] border-sev-critical/40 p-4 text-sm text-sev-critical">Can't reach the API ({loadError}). Is the backend running on port 8000?</div>}
      {actionError && <p role="alert" className="card mx-auto mb-4 max-w-[1600px] p-4 text-sev-critical">{actionError}</p>}

      {page === "overview" && <section id="top" className="hero-band mx-auto mb-7 max-w-[1600px]">
        <div>
          <p className="eyebrow"><span className="eyebrow-mark">01</span> ASSET INTELLIGENCE · AUTHORIZED SCANNING</p>
          <h1>See your exposure.<br /><span>Know what matters.</span></h1>
          <p className="hero-copy">Assess reachable services, understand vulnerability risk, and keep a clear record of what changed.</p>
        </div>
        <div className="hero-side-note"><span className="hero-side-label">BUILT FOR DEFENSIVE SECURITY</span><span>Permission-first assessments</span><span>Actionable, prioritized findings</span></div>
      </section>}

      <div className={`workspace-grid mx-auto max-w-[1600px] ${page === "overview" ? "grid grid-cols-1 gap-5 lg:grid-cols-[370px_minmax(0,1fr)]" : ""}`}>
        {page === "overview" && <aside className="min-w-0 space-y-5">
          <div className="section-heading"><span className="section-index">01</span><div><h2>Assessment setup</h2><p>Configure an authorized scan</p></div></div>
          {options && <ScanForm options={options} busy={live} onSubmit={startScan} />}
          <div className="section-heading section-heading-history"><span className="section-index">02</span><div><h2>Recent activity</h2><p>Saved scan history</p></div></div>
          <ScanHistory scans={history} activeId={job?.id ?? null} onSelect={selectScan} onDelete={deleteScan} />
        </aside>}
        <main id="results" ref={mainRef} className={`min-w-0 scroll-mt-6 ${page === "overview" ? "space-y-5" : ""}`}>
          {page === "overview" && <>
            <OverviewPage scans={history} onOpenScan={id => void openScan(id)} />
            {job && live && <ScanProgress target={job.target} event={event} />}
            {job && isFinished(job) && <ScanResults key={`results-${job.id}`} job={job} aiEnabled={!!options?.ai_enabled} />}
            {job?.status === "completed" && <ReviewTools key={`review-${job.id}`} job={job} history={history} />}
          </>}
          {page === "assets" && <AssetsPage scans={history} search={globalSearch} onOpenScan={id => void openScan(id)} />}
          {page === "scans" && <ScansPage scans={history} search={globalSearch} onOpenScan={id => void openScan(id)} />}
          {page === "findings" && <FindingsPage search={globalSearch} />}
          {page === "reports" && <ReportsPage scans={history} />}
          {page === "settings" && <SettingsPage />}
        </main>
      </div>

      <footer className="app-footer mx-auto mt-12 flex max-w-[1600px] flex-wrap justify-between gap-3 border-t border-ink-800 pt-5 text-xs text-ink-400">
        <span>NAJD Recon · Developed by Abdullah Bin Mohammad Mushtaq</span>
        <span>Only scan systems you own or have explicit permission to test.</span>
      </footer>
    </div>
  );
}
