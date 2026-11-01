import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import ts from 'typescript';
const source = readFileSync(new URL('../src/api/reports.ts', import.meta.url), 'utf8');
const { outputText } = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } });
const { csvCell, toCsv, inventory, difference, findings } = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString('base64')}`);
assert.equal(csvCell('=HYPERLINK("bad")'), '"\'=HYPERLINK(""bad"")"');
assert.equal(csvCell('hello, "world"'), '"hello, ""world"""');
assert.equal(csvCell(null), '""');
assert.equal(csvCell('@SUM(A1)'), '"\'@SUM(A1)"');
const job = { target: '127.0.0.1', result: { hosts: [{ address: '127.0.0.1', ports: [
 { port: 443, protocol: 'tcp', state: 'open', service: 'https', product: 'Example server', version: '1.2', cves: [{ id: 'CVE-TEST', severity: 'high', cvss: 8, epss: 0, in_kev: false }] },
 { port: 80, protocol: 'tcp', state: 'closed', cves: [] }
] }] } };
assert.deepEqual([...inventory(job)], ['127.0.0.1:443/tcp']);
assert.deepEqual(difference(new Set(['a','b']), new Set(['b','c'])), { added:['c'], removed:['a'] });
assert.match(toCsv(job), /"127\.0\.0\.1","127\.0\.0\.1","443","tcp","https","Example server","1\.2","CVE-TEST","high","8","0","false"/);
assert.deepEqual(findings(job)[0], {
 target: '127.0.0.1', host: '127.0.0.1', port: 443, protocol: 'tcp',
 service: 'https', product: 'Example server', version: '1.2', cve: 'CVE-TEST',
 severity: 'high', cvss: 8, epss: 0, kev: false
});
assert.equal(toCsv({ target: '127.0.0.1', result: null }).split('\r\n').length, 1);
console.log('Report tests passed: CSV quoting, formula protection, missing values, zero scores, open-port inventory and comparison.');
