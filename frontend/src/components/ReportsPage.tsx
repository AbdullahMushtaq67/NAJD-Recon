import { useEffect, useMemo, useState } from "react";
import { api, formatCommandLine } from "../api/client";
import { developer, difference, download, findings, inventory, toCsv } from "../api/reports";
import type { FindingRecord, ScanJob, ScanSummary, WorkspaceSettings } from "../types";
import { SeverityBadge, Tag } from "./Badges";
import { EmptyMessage, PageIntro } from "./AssetsPage";

type ReportSection = "executive" | "hosts" | "findings" | "methodology" | "notes" | "comparison";
const SECTION_LABELS: Record<ReportSection, string> = {
  executive: "Executive summary and risk profile",
  hosts: "Hosts, services, and open-port inventory",
  findings: "Detailed vulnerability register",
  methodology: "Scope, scan settings, and evidence",
  notes: "Assessment notes",
  comparison: "Baseline comparison",
};

export function ReportsPage({ scans }: { scans: ScanSummary[] }) {
  const completed = scans.filter(scan => scan.status === "completed");
  const [scanId, setScanId] = useState(completed[0]?.id ?? "");
  const [baselineId, setBaselineId] = useState("");
  const [job, setJob] = useState<ScanJob | null>(null);
  const [baseline, setBaseline] = useState<ScanJob | null>(null);
  const [settings, setSettings] = useState<WorkspaceSettings | null>(null);
  const [findingReviews, setFindingReviews] = useState<FindingRecord[]>([]);
  const [sections, setSections] = useState<ReportSection[]>(["executive", "hosts", "findings", "methodology", "notes"]);
  const [notes, setNotes] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([api.workspaceSettings(), api.findings()])
      .then(([workspaceSettings, records]) => {
        setSettings(workspaceSettings);
        setFindingReviews(records);
      })
      .catch(e => setError((e as Error).message));
  }, []);
  useEffect(() => {
    if (!scanId) { setJob(null); return; }
    setLoading(true);
    api.getScan(scanId).then(setJob).catch(e => setError((e as Error).message)).finally(() => setLoading(false));
  }, [scanId]);
  useEffect(() => {
    if (!baselineId) { setBaseline(null); return; }
    api.getScan(baselineId).then(setBaseline).catch(e => setError((e as Error).message));
  }, [baselineId]);

  const allFindings = useMemo(() => job ? findings(job) : [], [job]);
  const ports = job ? inventory(job) : new Set<string>();
  const portDiff = baseline && job ? difference(inventory(baseline), inventory(job)) : null;
  const cveDiff = baseline && job ? difference(
    new Set(findings(baseline).map(row => row.cve)),
    new Set(findings(job).map(row => row.cve)),
  ) : null;
  const counts = job?.severity_counts;

  function toggle(section: ReportSection) {
    setSections(current => current.includes(section) ? current.filter(value => value !== section) : [...current, section]);
  }

  if (!completed.length) return <section className="page-stack"><PageIntro index="05" title="Assessment reports" description="Build a detailed, branded assessment report from completed scan evidence." /><EmptyMessage title="No completed assessments" body="Complete a scan before creating a report." /></section>;

  return (
    <section className="page-stack report-page">
      <PageIntro index="05" title="Assessment reports" description="Build a detailed, branded report. Print to paper or choose Save as PDF in your browser." />
      <div className="report-controls card space-y-4 p-5 no-print">
        <div className="grid gap-3 sm:grid-cols-2">
          <label className="text-xs text-ink-300">Assessment<select className="input mt-1.5" value={scanId} onChange={event => { setScanId(event.target.value); setBaselineId(""); setBaseline(null); }}>{completed.map(scan => <option key={scan.id} value={scan.id}>{scan.target} · {new Date(scan.created_at).toLocaleString()}</option>)}</select></label>
          <label className="text-xs text-ink-300">Compare against (optional)<select className="input mt-1.5" value={baselineId} onChange={event => setBaselineId(event.target.value)}><option value="">No comparison</option>{completed.filter(scan => scan.id !== scanId && scan.target === job?.target).map(scan => <option key={scan.id} value={scan.id}>{new Date(scan.created_at).toLocaleString()}</option>)}</select></label>
        </div>
        <fieldset><legend className="label">Report sections</legend><div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">{(Object.keys(SECTION_LABELS) as ReportSection[]).map(section => <label key={section} className="flex items-center gap-2 text-xs text-ink-300"><input type="checkbox" checked={sections.includes(section)} disabled={section === "comparison" && !baseline} onChange={() => toggle(section)} />{SECTION_LABELS[section]}</label>)}</div></fieldset>
        <label className="block space-y-1.5 text-xs text-ink-300">Report notes<textarea className="input min-h-20" maxLength={10000} value={notes} onChange={event => setNotes(event.target.value)} placeholder="Scope exclusions, verification notes, recommendations…" /></label>
        {error && <p role="alert" className="text-sm text-sev-critical">{error}</p>}
        <div className="flex flex-wrap gap-2">
          <button className="btn-primary" disabled={!job || loading} onClick={() => window.print()}>{loading ? "Preparing…" : "Print / save detailed PDF"}</button>
          {job && <button className="btn-ghost" onClick={() => download(`najd-recon-${job.id}-assessment.json`, JSON.stringify({ workspace: settings?.workspace_name ?? "NAJD Recon", developer, reportSettings: settings, scan: job, baseline, notes, sections }, null, 2), "application/json")}>Export JSON report</button>}
          {job && <button className="btn-ghost" onClick={() => download(`najd-recon-${job.id}-findings.csv`, toCsv(job), "text/csv;charset=utf-8")}>Export findings CSV</button>}
        </div>
      </div>

      {job && <article className="report-document">
        <header className="report-cover">
          <img src="/najd-recon-logo.png" alt="NAJD Recon" />
          <p className="report-kicker">{settings?.report_subtitle || "Authorized Security Assessment"}</p>
          <h1>Security Assessment<br /><span>Report</span></h1>
          <div className="report-cover-meta"><div><span>ASSESSMENT TARGET</span><strong>{job.target}</strong></div><div><span>ASSESSMENT DATE</span><strong>{new Date(job.finished_at ?? job.created_at).toLocaleString()}</strong></div><div><span>PREPARED BY</span><strong>{settings?.report_contact || developer}</strong></div></div>
          <p className="report-confidential">{settings?.report_footer || "Confidential — For authorized recipients only"}</p>
        </header>

        {sections.includes("executive") && <section className="report-section">
          <ReportHeading number="01" title="Executive summary" />
          <p className="report-prose">NAJD Recon assessed <strong>{job.target}</strong> on {new Date(job.created_at).toLocaleString()}. The scan identified {job.result?.hosts.length ?? 0} host(s), {ports.size} open service port(s), and {allFindings.length} CVE finding instance(s). Findings are based on service/version matching and should be verified against vendor patch information.</p>
          <div className="report-metrics"><ReportStat label="Open ports" value={ports.size} /><ReportStat label="CVEs" value={allFindings.length} /><ReportStat label="Critical" value={counts?.critical ?? 0} tone="critical" /><ReportStat label="High" value={counts?.high ?? 0} tone="high" /><ReportStat label="CISA KEV" value={allFindings.filter(item => item.kev).length} tone="critical" /></div>
          <div className="report-priority"><h3>Priority guidance</h3><ol><li>Address vulnerabilities listed in CISA KEV, especially on internet-facing services.</li><li>Prioritize critical/high findings on business-critical assets and review EPSS likelihood.</li><li>Verify installed patch levels; version-based matches can be false positives due to vendor backports.</li></ol></div>
        </section>}

        {sections.includes("hosts") && <section className="report-section page-break">
          <ReportHeading number="02" title="Asset and service inventory" />
          {(job.result?.hosts ?? []).map(host => <div className="report-host" key={host.address}><div className="report-host-head"><strong>{host.address}</strong><span>{host.status} {host.hostnames.length ? `· ${host.hostnames.join(", ")}` : ""}</span></div><table className="report-table"><thead><tr><th>Port</th><th>State</th><th>Service</th><th>Detected product / version</th><th>CVEs</th></tr></thead><tbody>{host.ports.map(port => <tr key={`${port.protocol}-${port.port}`}><td>{port.port}/{port.protocol}</td><td>{port.state}</td><td>{port.service || "Unknown"}</td><td>{[port.product, port.version].filter(Boolean).join(" ") || "Not identified"}</td><td>{port.cves.length}</td></tr>)}</tbody></table></div>)}
        </section>}

        {sections.includes("findings") && <section className="report-section page-break">
          <ReportHeading number="03" title="Detailed vulnerability register" />
          {allFindings.length ? <div className="report-findings">{allFindings.map((item, index) => {
            const cve = job.result?.hosts.flatMap(host => host.ports.flatMap(port => port.cves)).find(value => value.id === item.cve);
            const review = findingReviews.find(record =>
              record.target === item.target && record.host === item.host
              && record.port === item.port && record.protocol === item.protocol
              && record.cve.id === item.cve,
            );
            return <article className="report-finding" key={`${item.host}-${item.port}-${item.cve}`}><div className="report-finding-head"><span className="report-finding-number">{String(index + 1).padStart(2, "0")}</span><strong>{item.cve}</strong>{cve && <SeverityBadge severity={cve.severity} score={cve.cvss} />}{item.kev && <Tag tone="danger">CISA KEV</Tag>}</div><p className="report-finding-location">{item.host} · {item.port}/{item.protocol} · {item.service || "Unknown service"} {item.product} {item.version}</p><p className="report-prose">{cve?.description || "No vulnerability description was available in the enrichment response."}</p><div className="report-finding-scores"><span>CVSS: {item.cvss ?? "Unknown"}</span><span>EPSS: {item.epss == null ? "Unavailable" : `${(item.epss * 100).toFixed(1)}%`}</span><span>Exploit known: {cve?.is_exploit ? "Yes" : "No"}</span><span>Workflow: {review?.status ?? "open"}</span>{review?.assignee && <span>Assignee: {review.assignee}</span>}{review?.due_date && <span>Due: {review.due_date}</span>}</div>{review?.note && <p className="report-prose"><strong>Review note:</strong> {review.note}</p>}<p className="report-remediation"><strong>Suggested action:</strong> Confirm applicability and patch level with the software vendor, apply the supported security update, and verify exposure in a follow-up assessment.</p>{cve?.references.length ? <p className="report-reference">References: {cve.references.slice(0, 3).join(" · ")}</p> : null}</article>;
          })}</div> : <p className="report-prose">No CVE findings were recorded for the selected assessment.</p>}
        </section>}

        {sections.includes("methodology") && <section className="report-section page-break">
          <ReportHeading number="04" title="Scope and methodology" />
          <dl className="report-method"><div><dt>Authorized target</dt><dd>{job.target} ({job.resolved_ip})</dd></div><div><dt>Scan status</dt><dd>{job.status}</dd></div><div><dt>Started</dt><dd>{new Date(job.created_at).toLocaleString()}</dd></div><div><dt>Finished</dt><dd>{job.finished_at ? new Date(job.finished_at).toLocaleString() : "Unavailable"}</dd></div><div><dt>Duration</dt><dd>{job.result?.elapsed_seconds == null ? "Unavailable" : `${job.result.elapsed_seconds.toFixed(1)} seconds`}</dd></div><div><dt>Nmap version</dt><dd>{job.result?.nmap_version || "Unavailable"}</dd></div><div><dt>Scan profile</dt><dd>{Object.entries(job.options).map(([key, value]) => `${key}: ${String(value)}`).join(" · ") || "Unavailable"}</dd></div><div><dt>Command evidence</dt><dd className="font-mono">{formatCommandLine(job.command)}</dd></div></dl>
          <p className="report-caveat">This report reflects the scan output and vulnerability intelligence available at assessment time. Nmap/version-based CVE detection is indicative, not proof of exploitability. Confirm patch status and configuration with the asset owner before remediation decisions.</p>
        </section>}

        {sections.includes("notes") && <section className="report-section"><ReportHeading number="05" title="Assessment notes" /><p className="report-notes-content">{notes.trim() || "No additional assessment notes were provided."}</p></section>}

        {sections.includes("comparison") && baseline && portDiff && cveDiff && <section className="report-section page-break"><ReportHeading number="06" title="Baseline comparison" /><p className="report-prose">Compared with assessment from {new Date(baseline.finished_at ?? baseline.created_at).toLocaleString()}. A finding disappearing from scan output does not, by itself, prove remediation.</p><div className="report-comparison-grid"><div><h3>Open ports added</h3><ul>{portDiff.added.map(value => <li key={value}>{value}</li>)}</ul></div><div><h3>Open ports no longer observed</h3><ul>{portDiff.removed.map(value => <li key={value}>{value}</li>)}</ul></div><div><h3>New CVEs</h3><ul>{cveDiff.added.map(value => <li key={value}>{value}</li>)}</ul></div><div><h3>CVEs no longer observed</h3><ul>{cveDiff.removed.map(value => <li key={value}>{value}</li>)}</ul></div></div></section>}

        <footer className="report-footer"><span>{settings?.workspace_name || "NAJD Recon"} · {settings?.report_footer || "Confidential"}</span><span>Generated {new Date().toLocaleString()}</span></footer>
      </article>}
    </section>
  );
}

function ReportHeading({ number, title }: { number: string; title: string }) {
  return <div className="report-section-heading"><span>{number}</span><h2>{title}</h2></div>;
}

function ReportStat({ label, value, tone }: { label: string; value: number; tone?: "critical" | "high" }) {
  return <div className="report-stat"><span>{label}</span><strong className={tone ? `text-sev-${tone}` : ""}>{value}</strong></div>;
}
