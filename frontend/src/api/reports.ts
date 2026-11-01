import type { ScanJob } from '../types';
export const developer = 'Abdullah Bin Mohammad Mushtaq';
export function findings(job: ScanJob) {
  return (job.result?.hosts ?? []).flatMap(h => h.ports.flatMap(p => p.cves.map(c => ({
    target: job.target, host: h.address, port: p.port, protocol: p.protocol,
    service: p.service, product: p.product, version: p.version,
    cve: c.id, severity: c.severity, cvss: c.cvss, epss: c.epss, kev: c.in_kev,
  }))));
}
export function csvCell(value: unknown) {
  let text = String(value ?? '');
  if (/^[=+\-@\t\r\n]/.test(text)) text = "'" + text;
  return '"' + text.replaceAll('"', '""') + '"';
}
export function toCsv(job: ScanJob) {
  const columns = ['target','host','port','protocol','service','product','version','cve','severity','cvss','epss','kev'] as const;
  return [columns.map(csvCell).join(','), ...findings(job).map(row => columns.map(k => csvCell(row[k])).join(','))].join('\r\n');
}
export function download(name: string, content: string, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement('a'); a.href = url; a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export function inventory(job: ScanJob) {
  return new Set((job.result?.hosts ?? []).flatMap(h => h.ports.filter(p => p.state === 'open').map(p => `${h.address}:${p.port}/${p.protocol}`)));
}
export function difference(before: Set<string>, after: Set<string>) {
  return { added: [...after].filter(x => !before.has(x)), removed: [...before].filter(x => !after.has(x)) };
}
