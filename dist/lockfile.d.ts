/**
 * Turn lockfiles into a flat list of installed packages.
 *
 * This is the one job osv-scanner was doing that osv-guard could not do for
 * itself. Everything downstream — querying OSV, scoring, grouping, policy —
 * already runs on our side of the line, so parsing lockfiles here is what makes
 * the binary optional rather than required.
 *
 * Every parser is hand-written against the format rather than pulled from a
 * dependency, which keeps osv-guard at zero runtime dependencies. That matters
 * more than usual for a security tool: a guard that drags in a supply chain of
 * its own is arguing against itself.
 */
export interface LockPackage {
    name: string;
    version: string;
    /** OSV ecosystem name. Node lockfiles are always `npm`. */
    ecosystem: string;
    /** Lockfile this came from, relative to the scan root. */
    source: string;
}
export interface UnsupportedLockfile {
    file: string;
    reason: string;
    /** The ecosystem osv-scanner would have covered, when we can name it. */
    ecosystem: string | null;
}
export interface LockfileScan {
    packages: LockPackage[];
    /** Lockfiles we read successfully, relative to the scan root. */
    parsed: string[];
    /** Lockfiles we found but cannot read ourselves. */
    unsupported: UnsupportedLockfile[];
}
/**
 * Split a `name@version` key as npm means it.
 *
 * Scoped names start with `@`, so the separator is the *last* `@`, not the
 * first — `@scope/pkg@1.0.0` is `@scope/pkg` at `1.0.0`. pnpm additionally
 * appends a peer-dependency suffix in parentheses on some keys; it is
 * resolution detail, not part of the version OSV knows about.
 */
export declare function splitNameVersion(key: string): {
    name: string;
    version: string;
} | null;
/**
 * package-lock.json / npm-shrinkwrap.json, v1 through v3.
 *
 * v2 and v3 carry a flat `packages` map keyed by install path, which is both
 * easier and more accurate than the v1 tree — the same package at two versions
 * appears twice, as it should. v1 only has the nested `dependencies` tree.
 */
export declare function parseNpmLock(text: string, source: string): LockPackage[];
/**
 * pnpm-lock.yaml, v5 through v9.
 *
 * Only the top-level keys of the `packages:` block are needed, and in every
 * version they encode the name and version directly — `/lodash/4.17.15` in v5,
 * `/lodash@4.17.15` in v6, `lodash@4.17.15` in v9. That makes a line scanner
 * sufficient and saves pulling in a YAML parser for four lines of structure.
 */
export declare function parsePnpmLock(text: string, source: string): LockPackage[];
/**
 * yarn.lock, both the v1 custom format and Berry's YAML.
 *
 * The shapes differ but the shape we need does not: a block introduced by one
 * or more requirement specs, containing a `version` field. The package name is
 * the part of the first spec before its version range, and Berry additionally
 * tags the protocol (`lodash@npm:^4.17.15`), which we strip.
 */
export declare function parseYarnLock(text: string, source: string): LockPackage[];
/**
 * bun.lock — JSON with comments and trailing commas, which `JSON.parse`
 * rejects. Each `packages` entry is an array whose first element is the
 * familiar `name@version` key.
 */
export declare function parseBunLock(text: string, source: string): LockPackage[];
/**
 * Non-Node manifests anywhere under `dir`, as paths relative to it.
 *
 * Used only to warn. The built-in engine reports npm findings correctly whether
 * or not a Go module sits beside them; what it must not do is let that silence
 * read as "nothing found here".
 */
export declare function findForeignManifests(dir: string): {
    file: string;
    ecosystem: string;
}[];
/**
 * Read every lockfile in `lockfiles` (paths relative to `dir`) and return the
 * union of what they declare.
 *
 * Duplicates across lockfiles are kept apart by source, because a monorepo that
 * pins a vulnerable package in two workspaces has two things to fix, and the
 * report says so per package. Within one lockfile they are collapsed.
 */
export declare function readLockfiles(dir: string, lockfiles: string[]): LockfileScan;
/** True when `dir` looks like a Node project at all. */
export declare function hasPackageJson(dir: string): boolean;
