import { type LockfileScan } from './lockfile.js';
import type { FetchLike } from './osvapi.js';
import type { OsvRawGroup, OsvRawVulnerability, ScanResult } from './types.js';
export interface LocalScanOptions {
    dir: string;
    /** Lockfile paths relative to `dir`. */
    lockfiles: string[];
    fetchImpl?: FetchLike;
    timeoutMs?: number;
    /** Off in tests, so a test run never touches the real user cache. */
    useCache?: boolean;
}
export interface LocalScanResult extends ScanResult {
    /** What the lockfile pass made of the tree, for warnings and `--verbose`. */
    lockfileScan: LockfileScan;
    packagesScanned: number;
}
export declare function runLocalScan(options: LocalScanOptions): Promise<LocalScanResult>;
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
export declare function groupByAlias(vulns: OsvRawVulnerability[]): OsvRawGroup[];
