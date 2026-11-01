import { useState } from "react";
import type { CommandPreview as Preview } from "../types";

/** Shows the exact nmap command the backend will run, with each flag explained. */
export function CommandPreview({ preview, error }: { preview: Preview | null; error: string | null }) {
  const [open, setOpen] = useState(false);

  if (error) {
    return (
      <div className="rounded-lg border border-sev-critical/30 bg-sev-critical/5 px-3 py-2 text-xs text-sev-critical">
        {error}
      </div>
    );
  }
  if (!preview) return null;

  return (
    <div className="rounded-lg border border-ink-700 bg-ink-950/70">
      <div className="flex items-center justify-between border-b border-ink-700/70 px-3 py-1.5">
        <span className="text-[11px] font-semibold uppercase tracking-wider text-ink-400">
          Command preview
        </span>
        <button type="button" onClick={() => setOpen(!open)} className="text-[11px] text-accent hover:underline">
          {open ? "Hide" : "Explain"} flags
        </button>
      </div>
      <pre className="overflow-x-auto px-3 py-2 font-mono text-xs leading-relaxed text-ink-300">
        <span className="select-none text-accent">$ </span>
        {preview.command}
      </pre>
      {preview.target !== preview.resolved_ip && (
        <p className="px-3 pb-2 text-[11px] text-ink-400">
          {preview.target} resolves to <span className="font-mono">{preview.resolved_ip}</span>. The
          IP is scanned directly to prevent DNS rebinding.
        </p>
      )}
      {open && (
        <dl className="space-y-2 border-t border-ink-700/70 px-3 py-3">
          {preview.explanation.map((e) => (
            <div key={e.flag} className="grid grid-cols-[auto_1fr] gap-3 text-xs">
              <dt className="font-mono text-accent">{e.flag}</dt>
              <dd className="text-ink-300">{e.help}</dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  );
}
