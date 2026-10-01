/**
 * Engine selection and the built-in scan path.
 *
 * The built-in engine is the default, which makes two things load-bearing:
 * it must never quietly report clean on a tree it cannot read, and the
 * findings it produces must be the same findings the osv-scanner binary would
 * have produced. Both are asserted here; the network is stubbed throughout, so
 * these tests are deterministic and never touch the real OSV API or the user's
 * advisory cache.
 */

import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { UsageError } from '../dist/config.js';
import { chooseEngine, unsupportedWarnings } from '../dist/engine.js';
import { groupByAlias, runLocalScan } from '../dist/scanlocal.js';

function tempDir() {
  return mkdtempSync(path.join(tmpdir(), 'osv-guard-engine-'));
}

const base = {
  requested: 'builtin',
  explicit: false,
  offline: false,
  lockfiles: ['package-lock.json'],
  foreign: [],
  hasBinary: () => false,
};

// --- selection --------------------------------------------------------------

test('builtin is the default, and needs no binary', () => {
  const choice = chooseEngine(base);
  assert.equal(choice.engine, 'builtin');
  assert.deepEqual(choice.warnings, []);
});

test('an explicit --scanner osv-scanner is honoured', () => {
  assert.equal(chooseEngine({ ...base, requested: 'osv-scanner', explicit: true }).engine, 'osv-scanner');
});

test('auto prefers the binary when it is installed', () => {
  assert.equal(chooseEngine({ ...base, requested: 'auto', hasBinary: () => true }).engine, 'osv-scanner');
  assert.equal(chooseEngine({ ...base, requested: 'auto', hasBinary: () => false }).engine, 'builtin');
});

test('--offline switches to the binary, which is the only engine that can', () => {
  // The built-in engine queries api.osv.dev; mirroring the npm slice of OSV
  // locally is over 200 MB, so offline stays osv-scanner's job.
  const choice = chooseEngine({ ...base, offline: true });
  assert.equal(choice.engine, 'osv-scanner');
});

test('--offline with an explicit --scanner builtin is a usage error, not a silent switch', () => {
  assert.throws(
    () => chooseEngine({ ...base, offline: true, explicit: true, requested: 'builtin' }),
    (err) => err instanceof UsageError && /--offline needs the osv-scanner binary/.test(err.message),
  );
});

// --- non-Node ecosystems ----------------------------------------------------

test('non-Node manifests beside a Node lockfile warn rather than fail', () => {
  const choice = chooseEngine({
    ...base,
    foreign: [
      { file: 'go.mod', ecosystem: 'Go' },
      { file: 'api/requirements.txt', ecosystem: 'PyPI' },
    ],
  });
  assert.equal(choice.engine, 'builtin');
  assert.ok(choice.warnings.length > 0);
  const text = choice.warnings.join('\n');
  assert.match(text, /Node lockfiles only/);
  assert.match(text, /go\.mod/);
  assert.match(text, /--scanner osv-scanner/);
  assert.match(text, /Go, PyPI/);
});

test('a tree the builtin engine cannot read at all falls back to the binary', () => {
  // A pure Go repo has nothing for the built-in engine. Reporting "no lockfile"
  // when osv-scanner is sitting right there would be throwing away a real scan.
  const choice = chooseEngine({
    ...base,
    lockfiles: [],
    foreign: [{ file: 'go.mod', ecosystem: 'Go' }],
    hasBinary: () => true,
  });
  assert.equal(choice.engine, 'osv-scanner');
  assert.match(choice.reason, /no Node lockfile/);
});

test('that fallback never overrides an engine the user named', () => {
  const choice = chooseEngine({
    ...base,
    explicit: true,
    lockfiles: [],
    foreign: [{ file: 'go.mod', ecosystem: 'Go' }],
    hasBinary: () => true,
  });
  assert.equal(choice.engine, 'builtin');
  assert.ok(choice.warnings.length > 0);
});

test('with no binary to fall back to, the user is told what is unchecked', () => {
  const choice = chooseEngine({
    ...base,
    lockfiles: [],
    foreign: [{ file: 'Cargo.lock', ecosystem: 'crates.io' }],
    hasBinary: () => false,
  });
  assert.equal(choice.engine, 'builtin');
  assert.match(choice.warnings.join('\n'), /crates\.io/);
});

test('an unreadable lockfile is surfaced, not swallowed', () => {
  const warnings = unsupportedWarnings([
    { file: 'bun.lockb', ecosystem: 'npm', reason: 'binary lockfile' },
  ]);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /bun\.lockb/);
});

// --- alias grouping ---------------------------------------------------------

test('a GHSA and the CVE it aliases are one finding, not two', () => {
  const groups = groupByAlias([
    { id: 'GHSA-aaaa', aliases: ['CVE-2021-1'] },
    { id: 'CVE-2021-1', aliases: ['GHSA-aaaa'] },
    { id: 'GHSA-bbbb', aliases: [] },
  ]);
  assert.equal(groups.length, 2);
  const merged = groups.find((g) => g.ids.length === 2);
  assert.deepEqual(merged.ids, ['CVE-2021-1', 'GHSA-aaaa']);
});

test('a chain of aliases collapses into a single group', () => {
  // a -> b -> c, stated only one link at a time. Union-find is what keeps this
  // from splitting into two groups depending on iteration order.
  const groups = groupByAlias([
    { id: 'A', aliases: ['B'] },
    { id: 'B', aliases: ['C'] },
    { id: 'C', aliases: [] },
  ]);
  assert.equal(groups.length, 1);
  assert.deepEqual(groups[0].ids, ['A', 'B', 'C']);
});

test('an alias naming something OSV did not return stays an alias', () => {
  const groups = groupByAlias([{ id: 'GHSA-aaaa', aliases: ['CVE-2021-9999'] }]);
  assert.equal(groups.length, 1);
  assert.deepEqual(groups[0].ids, ['GHSA-aaaa']);
  assert.deepEqual(groups[0].aliases, ['CVE-2021-9999']);
});

// --- the built-in scan, end to end ------------------------------------------

/** A stub OSV API serving a fixed advisory set. */
function stubFetch({ byPackage, advisories, onCall }) {
  return async (url, init) => {
    onCall?.(String(url));
    if (String(url).includes('querybatch')) {
      const body = JSON.parse(init.body);
      return {
        ok: true,
        status: 200,
        json: async () => ({
          results: body.queries.map((q) => ({
            vulns: (byPackage[`${q.package.name}@${q.version}`] ?? []).map((id) => ({
              id,
              modified: '2024-01-01T00:00:00Z',
            })),
          })),
        }),
      };
    }
    const id = decodeURIComponent(String(url).split('/').pop());
    const record = advisories[id];
    if (!record) return { ok: false, status: 404, json: async () => ({}) };
    return { ok: true, status: 200, json: async () => record };
  };
}

const ADVISORIES = {
  'GHSA-crit': {
    id: 'GHSA-crit',
    aliases: ['CVE-2020-1'],
    summary: 'Prototype Pollution in minimist',
    database_specific: { severity: 'CRITICAL' },
    severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
    affected: [
      {
        package: { name: 'minimist', ecosystem: 'npm' },
        ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '0.2.4' }] }],
      },
    ],
  },
  'CVE-2020-1': {
    id: 'CVE-2020-1',
    aliases: ['GHSA-crit'],
    summary: 'Prototype Pollution in minimist',
    severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
  },
  'GHSA-gone': {
    id: 'GHSA-gone',
    withdrawn: '2023-01-01T00:00:00Z',
    summary: 'Withdrawn advisory',
    database_specific: { severity: 'CRITICAL' },
  },
};

function projectWith(lock) {
  const dir = tempDir();
  writeFileSync(path.join(dir, 'package-lock.json'), JSON.stringify(lock));
  return dir;
}

test('a vulnerable lockfile produces one finding per distinct flaw', async () => {
  const dir = projectWith({
    lockfileVersion: 3,
    packages: { '': { name: 'root' }, 'node_modules/minimist': { version: '0.0.8' } },
  });

  const scan = await runLocalScan({
    dir,
    lockfiles: ['package-lock.json'],
    useCache: false,
    fetchImpl: stubFetch({
      byPackage: { 'minimist@0.0.8': ['GHSA-crit', 'CVE-2020-1'] },
      advisories: ADVISORIES,
    }),
  });

  assert.equal(scan.packagesScanned, 1);
  // Two advisories came back; they alias each other, so they are one issue.
  assert.equal(scan.findings.length, 1);
  assert.equal(scan.findings[0].id, 'GHSA-crit');
  assert.equal(scan.findings[0].band, 'critical');
  assert.equal(scan.findings[0].score, 9.8);
  assert.equal(scan.findings[0].fixedVersion, '0.2.4');
  assert.deepEqual(scan.findings[0].aliases, ['CVE-2020-1']);
});

test('a clean lockfile reports nothing and still names what it read', async () => {
  const dir = projectWith({
    lockfileVersion: 3,
    packages: { '': { name: 'root' }, 'node_modules/left-pad': { version: '1.3.0' } },
  });
  const scan = await runLocalScan({
    dir,
    lockfiles: ['package-lock.json'],
    useCache: false,
    fetchImpl: stubFetch({ byPackage: {}, advisories: ADVISORIES }),
  });
  assert.deepEqual(scan.findings, []);
  assert.deepEqual(scan.sources, ['package-lock.json']);
  assert.equal(scan.packagesScanned, 1);
});

test('withdrawn advisories are not reported', async () => {
  const dir = projectWith({
    lockfileVersion: 3,
    packages: { '': { name: 'root' }, 'node_modules/x': { version: '1.0.0' } },
  });
  const scan = await runLocalScan({
    dir,
    lockfiles: ['package-lock.json'],
    useCache: false,
    fetchImpl: stubFetch({ byPackage: { 'x@1.0.0': ['GHSA-gone'] }, advisories: ADVISORIES }),
  });
  assert.deepEqual(scan.findings, []);
});

test('each advisory is fetched once however many packages it affects', async () => {
  // A flaw in a hoisted dependency can hit a dozen workspaces. Fetching the
  // record per package would turn one scan into a dozen round trips.
  const dir = tempDir();
  for (const pkg of ['a', 'b', 'c']) {
    mkdirSync(path.join(dir, pkg), { recursive: true });
    writeFileSync(
      path.join(dir, pkg, 'package-lock.json'),
      JSON.stringify({
        lockfileVersion: 3,
        packages: { '': { name: pkg }, 'node_modules/minimist': { version: '0.0.8' } },
      }),
    );
  }

  const calls = [];
  const scan = await runLocalScan({
    dir,
    lockfiles: ['a/package-lock.json', 'b/package-lock.json', 'c/package-lock.json'],
    useCache: false,
    fetchImpl: stubFetch({
      byPackage: { 'minimist@0.0.8': ['GHSA-crit'] },
      advisories: ADVISORIES,
      onCall: (url) => calls.push(url),
    }),
  });

  assert.equal(scan.findings.length, 3, 'one finding per workspace: each needs its own fix');
  assert.equal(calls.filter((u) => u.includes('/vulns/')).length, 1);
  assert.deepEqual(
    scan.findings.map((f) => f.source).sort(),
    ['a/package-lock.json', 'b/package-lock.json', 'c/package-lock.json'],
  );
});

test('a package list over the batch ceiling is split across requests', async () => {
  const packages = { '': { name: 'root' } };
  for (let i = 0; i < 1200; i += 1) packages[`node_modules/p${i}`] = { version: '1.0.0' };
  const dir = projectWith({ lockfileVersion: 3, packages });

  const batches = [];
  await runLocalScan({
    dir,
    lockfiles: ['package-lock.json'],
    useCache: false,
    fetchImpl: async (url, init) => {
      const body = JSON.parse(init.body);
      batches.push(body.queries.length);
      return {
        ok: true,
        status: 200,
        json: async () => ({ results: body.queries.map(() => ({})) }),
      };
    },
  });

  assert.deepEqual(batches, [1000, 200]);
});

test('an OSV outage fails loudly instead of reporting a clean tree', async () => {
  const dir = projectWith({
    lockfileVersion: 3,
    packages: { '': { name: 'root' }, 'node_modules/minimist': { version: '0.0.8' } },
  });
  await assert.rejects(
    runLocalScan({
      dir,
      lockfiles: ['package-lock.json'],
      useCache: false,
      fetchImpl: async () => {
        throw new Error('ECONNREFUSED');
      },
    }),
    /could not reach the OSV API/,
  );
});

test('one advisory that will not load does not sink the others', async () => {
  const dir = projectWith({
    lockfileVersion: 3,
    packages: {
      '': { name: 'root' },
      'node_modules/minimist': { version: '0.0.8' },
      'node_modules/x': { version: '1.0.0' },
    },
  });
  const scan = await runLocalScan({
    dir,
    lockfiles: ['package-lock.json'],
    useCache: false,
    fetchImpl: stubFetch({
      byPackage: { 'minimist@0.0.8': ['GHSA-crit'], 'x@1.0.0': ['GHSA-missing'] },
      advisories: ADVISORIES,
    }),
  });
  assert.equal(scan.findings.length, 1);
  assert.equal(scan.findings[0].id, 'GHSA-crit');
});

// --- flags and scoring ------------------------------------------------------

test('--scanner accepts the three engines and rejects anything else', async () => {
  const { parseArgv, UsageError: UE } = await import('../dist/config.js');
  assert.equal(parseArgv(['report', '--scanner', 'builtin']).cliOptions.scanner, 'builtin');
  assert.equal(parseArgv(['report', '--scanner', 'auto']).cliOptions.scanner, 'auto');
  assert.equal(parseArgv(['report', '--scanner', 'osv-scanner']).cliOptions.scanner, 'osv-scanner');
  // "binary" is the word people reach for; accepting it beats a usage error.
  assert.equal(parseArgv(['report', '--scanner', 'binary']).cliOptions.scanner, 'osv-scanner');
  assert.throws(() => parseArgv(['report', '--scanner', 'bogus']), UE);
});

test('naming a binary with --scanner-bin selects it', async () => {
  const { parseArgv } = await import('../dist/config.js');
  // Otherwise the flag would be silently ignored under the built-in default.
  assert.equal(parseArgv(['report', '--scanner-bin', '/opt/osv-scanner']).cliOptions.scanner, 'osv-scanner');
});

test('an explicit --scanner is not overridden by --scanner-bin', async () => {
  const { parseArgv } = await import('../dist/config.js');
  const parsed = parseArgv(['report', '--scanner', 'builtin', '--scanner-bin', '/opt/osv-scanner']);
  assert.equal(parsed.cliOptions.scanner, 'builtin');
});

test('a group is scored by its highest vector, not its first', async () => {
  const { normalize } = await import('../dist/normalize.js');
  // The GHSA scores 7.2 and the CVE it aliases scores 9.8. osv-scanner's
  // `max_severity` is the maximum; taking the first would under-report.
  const { findings } = normalize({
    results: [
      {
        source: { path: 'package-lock.json' },
        packages: [
          {
            package: { name: 'x', version: '1.0.0', ecosystem: 'npm' },
            groups: [{ ids: ['GHSA-low', 'CVE-high'], aliases: [] }],
            vulnerabilities: [
              {
                id: 'GHSA-low',
                severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H' }],
              },
              {
                id: 'CVE-high',
                severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
              },
            ],
          },
        ],
      },
    ],
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].score, 9.8);
  assert.equal(findings[0].band, 'critical');
});

test('a named band still reports a score when a vector is available', async () => {
  const { resolveSeverity } = await import('../dist/severity.js');
  // Without the binary there is no `max_severity`, so a GHSA rating would
  // otherwise print a band with no number beside it.
  const resolved = resolveSeverity(undefined, 'CRITICAL', [
    { type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
  ]);
  assert.equal(resolved.band, 'critical');
  assert.equal(resolved.score, 9.8);
  assert.equal(resolved.source, 'database_specific');
});

test('an osv-scanner.toml is flagged, because only the binary reads it', () => {
  // Suppressions that silently stop applying are the worst kind of regression:
  // the finding comes back, or the user believes it is still waived.
  const choice = chooseEngine({ ...base, scannerToml: true });
  assert.equal(choice.engine, 'builtin');
  const text = choice.warnings.join('\n');
  assert.match(text, /osv-scanner\.toml/);
  assert.match(text, /osv-guard\.json/);
});

test('no osv-scanner.toml, no warning about one', () => {
  assert.deepEqual(chooseEngine({ ...base, scannerToml: false }).warnings, []);
});
