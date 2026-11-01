import { useState } from "react";
import { api } from "../api/client";
import type { CVE, Explanation, Port } from "../types";
import { EpssBadge, SeverityBadge, Tag } from "./Badges";

export function CveRow({ cve, port, aiEnabled }: { cve: CVE; port: Port; aiEnabled: boolean }) {
  const [open, setOpen] = useState(false);
  const [explanation, setExplanation] = useState<Explanation | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function explain() {
    setLoading(true);
    setError(null);
    try {
      setExplanation(
        await api.explain(cve.id, {
          product: port.product,
          version: port.version,
          port: port.port,
          cvss: cve.cvss,
          is_exploit: cve.is_exploit,
        }),
      );
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <li className="border-t border-ink-700/60 first:border-t-0">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="flex w-full flex-wrap items-center gap-x-3 gap-y-1.5 px-4 py-2.5 text-left transition hover:bg-ink-800/50"
      >
        <span className={`text-ink-400 transition ${open ? "rotate-90" : ""}`}>›</span>
        <span className="font-mono text-sm">{cve.id}</span>
        <SeverityBadge severity={cve.severity} score={cve.cvss} />
        {cve.epss != null && <EpssBadge epss={cve.epss} percentile={cve.epss_percentile} />}
        {cve.in_kev && (
          <Tag tone="danger" title={`Added to CISA KEV on ${cve.kev_date_added}`}>
            Exploited in the wild
          </Tag>
        )}
        {cve.kev_ransomware && <Tag tone="danger">Ransomware</Tag>}
        {cve.is_exploit && !cve.in_kev && <Tag tone="warn">Public exploit</Tag>}
        <span className="ml-auto hidden text-xs text-ink-400 sm:inline">
          {cve.published ?? ""}
        </span>
      </button>

      {open && (
        <div className="space-y-4 px-4 pb-4 pl-10">
          <p className="text-sm leading-relaxed text-ink-300">
            {cve.description ?? "No NVD description loaded (NVD lookup disabled, rate-limited or offline)."}
          </p>

          <div className="flex flex-wrap gap-1.5 text-xs">
            {cve.cvss_vector && <Tag>{cve.cvss_vector}</Tag>}
            {cve.epss_percentile != null && (
              <Tag title="EPSS percentile among all scored CVEs">
                EPSS percentile: {(Math.floor(cve.epss_percentile * 1000) / 10).toFixed(1)}
              </Tag>
            )}
            {cve.cwe.map((c) => (
              <a key={c} href={`https://cwe.mitre.org/data/definitions/${c.slice(4)}.html`} target="_blank" rel="noreferrer">
                <Tag>{c}</Tag>
              </a>
            ))}
            <Tag>score source: {cve.source}</Tag>
          </div>

          <div className="flex flex-wrap gap-2">
            {cve.url && (
              <a className="btn-ghost" href={cve.url} target="_blank" rel="noreferrer">NVD entry ↗</a>
            )}
            {aiEnabled && !explanation && (
              <button type="button" className="btn-ghost border-accent/40 text-accent" onClick={explain} disabled={loading}>
                {loading ? "Thinking…" : "✦ Explain in plain language"}
              </button>
            )}
          </div>

          {error && <p className="text-xs text-sev-critical">{error}</p>}
          {explanation && <ExplanationPanel e={explanation} />}

          {cve.references.length > 0 && (
            <details className="text-xs text-ink-400">
              <summary className="cursor-pointer hover:text-ink-300">References</summary>
              <ul className="mt-2 space-y-1">
                {cve.references.map((r) => (
                  <li key={r} className="truncate">
                    <a href={r} target="_blank" rel="noreferrer" className="hover:text-accent">{r}</a>
                  </li>
                ))}
              </ul>
            </details>
          )}
        </div>
      )}
    </li>
  );
}

function ExplanationPanel({ e }: { e: Explanation }) {
  return (
    <div className="rounded-xl border border-accent/25 bg-accent/[0.04] p-4">
      <div className="mb-3 flex items-center justify-between">
        <span className="text-xs font-semibold uppercase tracking-wider text-accent">✦ AI explanation</span>
        <span className="text-[11px] text-ink-400">
          {e.provider} · {e.model}
          {e.cached && " · cached"}
        </span>
      </div>
      <p className="text-sm leading-relaxed">{e.summary}</p>
      <dl className="mt-4 grid gap-4 text-sm sm:grid-cols-2">
        <div>
          <dt className="label">What could happen</dt>
          <dd className="text-ink-300">{e.impact}</dd>
        </div>
        <div>
          <dt className="label">Who is affected</dt>
          <dd className="text-ink-300">{e.who_is_affected}</dd>
        </div>
      </dl>
      <div className="mt-4">
        <p className="label">How to fix it</p>
        <ol className="list-decimal space-y-1 pl-5 text-sm text-ink-300">
          {e.remediation.map((step) => (
            <li key={step}>{step}</li>
          ))}
        </ol>
      </div>
      <p className="mt-4 rounded-lg bg-ink-850 px-3 py-2 text-xs text-ink-300">{e.risk_level}</p>
      <p className="mt-3 text-[11px] text-ink-400">
        AI-generated from NVD data. Check vendor advisories before acting.
      </p>
    </div>
  );
}
