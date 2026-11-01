import { useEffect, useState, type FormEvent } from "react";
import { api } from "../api/client";
import type { CommandPreview as Preview, Options, ScanRequest } from "../types";
import { CommandPreview } from "./CommandPreview";

interface Props {
  options: Options;
  busy: boolean;
  onSubmit: (req: ScanRequest) => Promise<void>;
}

const DEFAULTS: ScanRequest = {
  target: "",
  technique: "connect",
  timing: 4,
  port_preset: "top100",
  custom_ports: "",
  service_detection: true,
  cve_detection: true,
  os_detection: false,
  skip_host_discovery: true,
  authorized: false,
};

export function ScanForm({ options, busy, onSubmit }: Props) {
  const [form, setForm] = useState<ScanRequest>(DEFAULTS);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [submitError, setSubmitError] = useState<string | null>(null);

  const set = <K extends keyof ScanRequest>(key: K, value: ScanRequest[K]) =>
    setForm((f) => ({ ...f, [key]: value }));

  // Ask the backend for the exact command whenever the form changes (debounced).
  useEffect(() => {
    if (!form.target.trim()) {
      setPreview(null);
      setPreviewError(null);
      return;
    }
    const handle = setTimeout(() => {
      api
        .preview(form)
        .then((p) => {
          setPreview(p);
          setPreviewError(null);
        })
        .catch((e: Error) => {
          setPreview(null);
          setPreviewError(e.message);
        });
    }, 400);
    return () => clearTimeout(handle);
    // `authorized` doesn't affect the command, so it is left out of the dependencies.
  }, [form.target, form.technique, form.timing, form.port_preset, form.custom_ports,
      form.service_detection, form.cve_detection, form.os_detection, form.skip_host_discovery]);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setSubmitError(null);
    try {
      await onSubmit(form);
    } catch (err) {
      setSubmitError((err as Error).message);
    }
  }

  const timing = options.timing_templates.find((t) => t.level === form.timing);
  const slowTiming = form.timing <= 1;

  return (
    <form onSubmit={handleSubmit} className="card space-y-6 p-5">
      {/* Target */}
      <div>
        <label htmlFor="target" className="label">Target</label>
        <input
          id="target"
          className="input font-mono"
          placeholder="scanme.nmap.org or 172.28.0.10"
          value={form.target}
          onChange={(e) => set("target", e.target.value)}
          autoComplete="off"
          spellCheck={false}
        />
        <div className="mt-2 flex flex-wrap items-center gap-1.5 text-[11px] text-ink-400">
          <span>Allowed:</span>
          {options.allowed_targets.map((t) => (
            <button
              key={t}
              type="button"
              onClick={() => !t.includes("/") && set("target", t)}
              className={`rounded bg-ink-800 px-1.5 py-0.5 font-mono ${t.includes("/") ? "cursor-default" : "hover:text-accent"}`}
            >
              {t}
            </button>
          ))}
        </div>
      </div>

      {/* Scan type */}
      <fieldset>
        <legend className="label">Scan type</legend>
        <div className="grid gap-2">
          {options.techniques.map((t) => (
            <label
              key={t.id}
              className={`flex cursor-pointer gap-3 rounded-xl border p-3 transition ${
                form.technique === t.id
                  ? "border-accent/70 bg-accent/5"
                  : "border-ink-700 hover:border-ink-600"
              } ${!t.available ? "cursor-not-allowed opacity-45" : ""}`}
            >
              <input
                type="radio"
                name="technique"
                className="mt-1 accent-[var(--color-accent)]"
                checked={form.technique === t.id}
                disabled={!t.available}
                onChange={() => set("technique", t.id)}
              />
              <span>
                <span className="flex items-center gap-2 text-sm font-medium">
                  {t.name}
                  <code className="rounded bg-ink-800 px-1.5 text-[11px] text-ink-300">{t.flag}</code>
                  {!t.available && <span className="text-[11px] text-ink-400">needs privileges</span>}
                </span>
                <span className="mt-0.5 block text-xs leading-relaxed text-ink-400">{t.description}</span>
              </span>
            </label>
          ))}
        </div>
      </fieldset>

      {/* Timing */}
      <div>
        <div className="flex items-baseline justify-between">
          <label htmlFor="timing" className="label">Timing</label>
          <span className="font-mono text-xs text-accent">
            -T{form.timing} {timing?.name}
          </span>
        </div>
        <input
          id="timing"
          type="range"
          min={0}
          max={5}
          value={form.timing}
          onChange={(e) => set("timing", Number(e.target.value))}
          className="w-full accent-[var(--color-accent)]"
        />
        <p className={`mt-1 text-xs ${slowTiming ? "text-sev-high" : "text-ink-400"}`}>
          {timing?.description}
          {slowTiming && " The scan will probably hit the server's timeout."}
        </p>
      </div>

      {/* Ports */}
      <div>
        <span className="label">Ports</span>
        <div className="grid grid-cols-2 gap-2">
          {options.port_presets.map((p) => (
            <button
              key={p.id}
              type="button"
              title={p.description}
              onClick={() => set("port_preset", p.id)}
              className={`rounded-lg border px-3 py-2 text-left text-xs font-medium transition ${
                form.port_preset === p.id
                  ? "border-accent/70 bg-accent/5 text-ink-100"
                  : "border-ink-700 text-ink-300 hover:border-ink-600"
              }`}
            >
              {p.name}
            </button>
          ))}
        </div>
        {form.port_preset === "custom" && (
          <input
            className="input mt-2 font-mono"
            placeholder="22,80,443,8000-8100"
            value={form.custom_ports}
            onChange={(e) => set("custom_ports", e.target.value)}
          />
        )}
      </div>

      {/* Detection options */}
      <fieldset className="space-y-2">
        <legend className="label">Detection</legend>
        <Toggle
          label="Service & version detection"
          hint="-sV"
          checked={form.service_detection || form.cve_detection}
          disabled={form.cve_detection}
          onChange={(v) => set("service_detection", v)}
        />
        <Toggle
          label="CVE lookup (vulners)"
          hint="--script vulners"
          checked={form.cve_detection}
          onChange={(v) => set("cve_detection", v)}
        />
        <Toggle
          label="OS detection"
          hint="-O"
          checked={form.os_detection}
          disabled={!options.os_detection_available}
          onChange={(v) => set("os_detection", v)}
        />
        <Toggle
          label="Skip host discovery"
          hint="-Pn"
          checked={form.skip_host_discovery}
          onChange={(v) => set("skip_host_discovery", v)}
        />
      </fieldset>

      <CommandPreview preview={preview} error={previewError} />

      {/* Authorisation */}
      <label className="flex cursor-pointer gap-3 rounded-xl border border-sev-medium/30 bg-sev-medium/5 p-3 text-xs leading-relaxed text-ink-300">
        <input
          type="checkbox"
          className="mt-0.5 accent-[var(--color-accent)]"
          checked={form.authorized}
          onChange={(e) => set("authorized", e.target.checked)}
        />
        I own this target or have written permission to scan it. Unauthorised scanning may be
        illegal.
      </label>

      {submitError && <p className="text-sm text-sev-critical">{submitError}</p>}

      <button type="submit" className="btn-primary w-full" disabled={busy || !form.authorized || !preview}>
        {busy ? "Assessment in progress…" : "Launch assessment"}
      </button>
    </form>
  );
}

function Toggle(props: {
  label: string;
  hint: string;
  checked: boolean;
  disabled?: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <label className={`flex items-center justify-between gap-3 text-sm ${props.disabled ? "opacity-50" : "cursor-pointer"}`}>
      <span>
        {props.label} <code className="ml-1 text-[11px] text-ink-400">{props.hint}</code>
      </span>
      <input
        type="checkbox"
        className="peer sr-only"
        checked={props.checked}
        disabled={props.disabled}
        onChange={(e) => props.onChange(e.target.checked)}
      />
      <span className="relative h-5 w-9 shrink-0 rounded-full bg-ink-700 transition peer-checked:bg-accent after:absolute after:left-0.5 after:top-0.5 after:h-4 after:w-4 after:rounded-full after:bg-ink-100 after:transition peer-checked:after:translate-x-4 peer-focus-visible:ring-2 peer-focus-visible:ring-accent-dim" />
    </label>
  );
}
