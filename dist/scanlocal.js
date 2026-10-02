import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import path from 'node:path';
import { readLockfiles } from './lockfile.js';
import { normalize } from './normalize.js';
import { ScannerError } from './scanner.js';
import { VERSION } from './version.js';
/**
 * The built-in scan engine: lockfiles in, findings out, no osv-scanner binary.
 *
 * Two calls to OSV do the work. `querybatch` takes up to 1000 package/version
 * pairs at once and answers with advisory *ids* only — a real lockfile of 87
 * packages resolves in well under a second. Each id that comes back is then
 * fetched in full, because the batch response deliberately omits details.
 *
 * That split is also what makes the detail fetch nearly free in practice: the
 * batch hands back each advisory's `modified` timestamp, which is an exact
 * content validator. An advisory cached under its own `modified` can never be
 * stale, so it is kept indefinitely and only re-fetched when OSV actually
 * revises it.
 */
const QUERY_BATCH_URL = 'https://api.osv.dev/v1/querybatch';
const VULN_URL = 'https://api.osv.dev/v1/vulns';
/** OSV's documented ceiling for a single batch request. */
const MAX_BATCH = 1000;
/** Enough to keep the pipe full without looking like a crawler. */
const HYDRATE_CONCURRENCY = 8;
export async function runLocalScan(options) {
    const started = Date.now();
    const lockfileScan = readLockfiles(options.dir, options.lockfiles);
    const packages = lockfileScan.packages;
    if (packages.length === 0) {
        return {
            findings: [],
            sources: lockfileScan.parsed,
            durationMs: Date.now() - started,
            scannerVersion: `osv-guard ${VERSION} (built-in)`,
            fromCache: false,
            lockfileScan,
            packagesScanned: 0,
        };
    }
    const hits = await queryBatch(packages, options);
    // One fetch per distinct advisory, not per affected package: a flaw in a
    // widely-hoisted dependency would otherwise be fetched dozens of times.
    const wanted = new Map();
    for (const perPackage of hits) {
        for (const hit of perPackage) {
            if (!wanted.has(hit.id))
                wanted.set(hit.id, hit.modified);
        }
    }
    const records = await hydrate(wanted, options);
    const raw = assemble(packages, hits, records);
    const { findings } = normalize(raw);
    return {
        findings,
        sources: lockfileScan.parsed,
        durationMs: Date.now() - started,
        scannerVersion: `osv-guard ${VERSION} (built-in)`,
        fromCache: false,
        lockfileScan,
        packagesScanned: packages.length,
    };
}
/**
 * Ask OSV about every package at once, in chunks.
 *
 * The response is positional — one entry per query, in order — so the result
 * array is indexed back against `packages` rather than matched by name.
 */
async function queryBatch(packages, options) {
    const fetchImpl = options.fetchImpl ?? globalThis.fetch;
    const timeoutMs = options.timeoutMs ?? 20_000;
    const out = [];
    for (let start = 0; start < packages.length; start += MAX_BATCH) {
        const chunk = packages.slice(start, start + MAX_BATCH);
        const body = JSON.stringify({
            queries: chunk.map((pkg) => ({
                package: { name: pkg.name, ecosystem: pkg.ecosystem },
                version: pkg.version,
            })),
        });
        let response;
        try {
            response = await fetchImpl(QUERY_BATCH_URL, {
                method: 'POST',
                headers: { 'content-type': 'application/json', 'user-agent': userAgent() },
                body,
                signal: AbortSignal.timeout(timeoutMs),
            });
        }
        catch (err) {
            throw new ScannerError('could not reach the OSV API', [
                err.message || 'request failed',
                '',
                'The built-in scanner queries https://api.osv.dev directly.',
                'If you are offline or behind a proxy that blocks it, use the',
                'osv-scanner binary instead: --scanner osv-scanner (or --offline).',
            ].join('\n'));
        }
        if (!response.ok) {
            throw new ScannerError(`OSV API responded ${response.status}`, 'Retry, or fall back to the binary with --scanner osv-scanner.');
        }
        const data = (await response.json());
        const results = data.results ?? [];
        for (let i = 0; i < chunk.length; i += 1) {
            out.push(results[i]?.vulns ?? []);
        }
    }
    return out;
}
/** Fetch the full record for every advisory id, cache permitting. */
async function hydrate(wanted, options) {
    const records = new Map();
    const useCache = options.useCache !== false;
    const pending = [];
    for (const [id, modified] of wanted) {
        const cached = useCache ? readAdvisory(id, modified) : null;
        if (cached)
            records.set(id, cached);
        else
            pending.push([id, modified]);
    }
    let next = 0;
    const workers = Array.from({ length: Math.min(HYDRATE_CONCURRENCY, pending.length) }, async () => {
        for (;;) {
            const index = next;
            next += 1;
            const entry = pending[index];
            if (!entry)
                return;
            const [id, modified] = entry;
            const record = await fetchAdvisory(id, options);
            if (!record)
                continue;
            records.set(id, record);
            if (useCache)
                writeAdvisory(id, modified, record);
        }
    });
    await Promise.all(workers);
    return records;
}
async function fetchAdvisory(id, options) {
    const fetchImpl = options.fetchImpl ?? globalThis.fetch;
    const timeoutMs = options.timeoutMs ?? 20_000;
    try {
        const response = await fetchImpl(`${VULN_URL}/${encodeURIComponent(id)}`, {
            headers: { 'user-agent': userAgent() },
            signal: AbortSignal.timeout(timeoutMs),
        });
        if (!response.ok)
            return null;
        return (await response.json());
    }
    catch {
        // A single advisory that will not load must not sink the whole scan; the
        // batch already told us it exists, and the others still report.
        return null;
    }
}
/**
 * Shape the answers into the structure osv-scanner emits, so `normalize()`,
 * `applyPolicy()` and the whole report layer stay untouched.
 *
 * Findings are keyed by lockfile, matching osv-scanner's one-result-per-source
 * output, so a monorepo still labels each finding with the package it came from.
 */
function assemble(packages, hits, records) {
    const bySource = new Map();
    for (let i = 0; i < packages.length; i += 1) {
        const pkg = packages[i];
        const ids = (hits[i] ?? []).map((hit) => hit.id);
        const vulns = ids
            .map((id) => records.get(id))
            .filter((v) => Boolean(v) && !v?.withdrawn);
        if (vulns.length === 0)
            continue;
        const entry = {
            package: { name: pkg.name, version: pkg.version, ecosystem: pkg.ecosystem },
            groups: groupByAlias(vulns),
            vulnerabilities: vulns,
        };
        const list = bySource.get(pkg.source);
        if (list)
            list.push(entry);
        else
            bySource.set(pkg.source, [entry]);
    }
    return {
        results: [...bySource].map(([source, pkgs]) => ({
            source: { path: source, type: 'lockfile' },
            packages: pkgs,
        })),
    };
}
/**
 * Collapse advisories that describe the same flaw, the way osv-scanner's
 * `groups` do.
 *
 * The same issue routinely carries a GHSA id and a CVE id, each published as
 * its own OSV record that names the other in `aliases`. Counting both would
 * double-charge one problem against a `--max-high` budget and report it twice.
 * Union-find over the alias graph puts every mutually-referencing record in one
 * group, which is exactly the unit `normalize()` turns into a Finding.
 */
export function groupByAlias(vulns) {
    const parent = new Map();
    const find = (id) => {
        let root = parent.get(id) ?? id;
        while (root !== (parent.get(root) ?? root))
            root = parent.get(root);
        parent.set(id, root);
        return root;
    };
    const union = (a, b) => {
        const [ra, rb] = [find(a), find(b)];
        if (ra !== rb)
            parent.set(rb, ra);
    };
    const present = new Set(vulns.map((v) => v.id));
    for (const vuln of vulns) {
        parent.set(vuln.id, parent.get(vuln.id) ?? vuln.id);
        for (const alias of vuln.aliases ?? []) {
            // Only union against advisories actually in this result. An alias naming
            // something OSV did not return is still recorded as an alias below.
            if (present.has(alias))
                union(vuln.id, alias);
        }
    }
    const groups = new Map();
    for (const vuln of vulns) {
        const root = find(vuln.id);
        const group = groups.get(root) ?? { ids: [], aliases: new Set() };
        group.ids.push(vuln.id);
        for (const alias of vuln.aliases ?? [])
            group.aliases.add(alias);
        groups.set(root, group);
    }
    return [...groups.values()].map((group) => ({
        ids: group.ids.sort(),
        aliases: [...group.aliases].filter((alias) => !group.ids.includes(alias)).sort(),
    }));
}
// --- advisory cache ---------------------------------------------------------
/**
 * Advisories are cached by content, not by time.
 *
 * `modified` comes straight from the batch response and changes whenever OSV
 * revises the record, so a cache hit on a matching `modified` is provably
 * current. There is no TTL to tune and no staleness to reason about.
 */
function advisoryFile(id) {
    const base = process.env.XDG_CACHE_HOME || (homedir() ? path.join(homedir(), '.cache') : tmpdir());
    // Advisory ids are filename-safe in practice, but hashing removes any doubt
    // about path separators arriving from a remote response.
    const safe = createHash('sha256').update(id).digest('hex').slice(0, 24);
    return path.join(base, 'osv-guard', 'advisories', `${safe}.json`);
}
function readAdvisory(id, modified) {
    try {
        const entry = JSON.parse(readFileSync(advisoryFile(id), 'utf8'));
        if (entry.id !== id)
            return null;
        // No `modified` to check against means no proof of freshness; re-fetch.
        if (!modified || entry.modified !== modified)
            return null;
        return entry.record;
    }
    catch {
        return null;
    }
}
function writeAdvisory(id, modified, record) {
    if (!modified)
        return;
    try {
        const file = advisoryFile(id);
        if (!existsSync(path.dirname(file)))
            mkdirSync(path.dirname(file), { recursive: true });
        const entry = { id, modified, record };
        writeFileSync(file, JSON.stringify(entry));
    }
    catch {
        // A read-only home is a slower scan, not a broken one.
    }
}
function userAgent() {
    return `osv-guard/${VERSION} (+https://github.com/jeka911/osv-guard)`;
}
