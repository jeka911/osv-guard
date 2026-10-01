import { existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

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
export function splitNameVersion(key: string): { name: string; version: string } | null {
  const withoutPeers = key.replace(/\(.*\)$/, '');
  const at = withoutPeers.lastIndexOf('@');
  if (at <= 0) return null;
  const name = withoutPeers.slice(0, at);
  const version = withoutPeers.slice(at + 1);
  if (!name || !version) return null;
  return { name, version };
}

/** Drop build metadata and anything that isn't a plain released version. */
function usableVersion(version: string): boolean {
  // `link:`, `file:`, `workspace:` and `portal:` point at local code, which no
  // advisory database has an opinion about.
  return /^\d/.test(version) && !version.includes(':');
}

// --- npm ---

/**
 * package-lock.json / npm-shrinkwrap.json, v1 through v3.
 *
 * v2 and v3 carry a flat `packages` map keyed by install path, which is both
 * easier and more accurate than the v1 tree — the same package at two versions
 * appears twice, as it should. v1 only has the nested `dependencies` tree.
 */
export function parseNpmLock(text: string, source: string): LockPackage[] {
  let lock: {
    packages?: Record<string, { name?: string; version?: string; link?: boolean; resolved?: string }>;
    dependencies?: Record<string, unknown>;
  };
  try {
    lock = JSON.parse(text);
  } catch {
    return [];
  }

  const out: LockPackage[] = [];

  if (lock.packages) {
    for (const [key, entry] of Object.entries(lock.packages)) {
      // "" is the project itself; a `link` entry is a workspace symlink whose
      // real dependencies are listed under their own path.
      if (key === '' || !entry || entry.link) continue;
      const marker = key.lastIndexOf('node_modules/');
      const name = entry.name ?? (marker === -1 ? key : key.slice(marker + 'node_modules/'.length));
      const version = entry.version;
      if (!name || !version || !usableVersion(version)) continue;
      out.push({ name, version, ecosystem: 'npm', source });
    }
    if (out.length > 0) return out;
  }

  // v1, or a v2 lockfile whose `packages` map held nothing usable.
  const walk = (deps: Record<string, unknown> | undefined): void => {
    for (const [name, raw] of Object.entries(deps ?? {})) {
      const entry = raw as { version?: string; dependencies?: Record<string, unknown> };
      if (entry?.version && usableVersion(entry.version)) {
        out.push({ name, version: entry.version, ecosystem: 'npm', source });
      }
      if (entry?.dependencies) walk(entry.dependencies);
    }
  };
  walk(lock.dependencies);
  return out;
}

// --- pnpm ---

/**
 * pnpm-lock.yaml, v5 through v9.
 *
 * Only the top-level keys of the `packages:` block are needed, and in every
 * version they encode the name and version directly — `/lodash/4.17.15` in v5,
 * `/lodash@4.17.15` in v6, `lodash@4.17.15` in v9. That makes a line scanner
 * sufficient and saves pulling in a YAML parser for four lines of structure.
 */
export function parsePnpmLock(text: string, source: string): LockPackage[] {
  const out: LockPackage[] = [];
  const seen = new Set<string>();
  let inPackages = false;

  for (const line of text.split('\n')) {
    if (/^packages:\s*$/.test(line)) {
      inPackages = true;
      continue;
    }
    // Any other column-0 key ends the block (`snapshots:`, `settings:`, …).
    if (/^\S/.test(line)) {
      if (inPackages) break;
      continue;
    }
    if (!inPackages) continue;

    const match = /^ {2}(\S.*):\s*$/.exec(line);
    if (!match?.[1]) continue;

    let key = match[1].trim().replace(/^['"]|['"]$/g, '');
    // v5 wrote `/name/version`, v6 `/name@version`; v9 dropped the prefix.
    if (key.startsWith('/')) key = key.slice(1);
    const slash = key.lastIndexOf('/');
    if (slash > 0 && !key.slice(slash + 1).includes('@')) {
      key = `${key.slice(0, slash)}@${key.slice(slash + 1)}`;
    }

    const split = splitNameVersion(key);
    if (!split || !usableVersion(split.version)) continue;
    const id = `${split.name}@${split.version}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push({ ...split, ecosystem: 'npm', source });
  }

  return out;
}

// --- yarn ---

/**
 * yarn.lock, both the v1 custom format and Berry's YAML.
 *
 * The shapes differ but the shape we need does not: a block introduced by one
 * or more requirement specs, containing a `version` field. The package name is
 * the part of the first spec before its version range, and Berry additionally
 * tags the protocol (`lodash@npm:^4.17.15`), which we strip.
 */
export function parseYarnLock(text: string, source: string): LockPackage[] {
  const out: LockPackage[] = [];
  const seen = new Set<string>();
  let pendingName: string | null = null;

  for (const line of text.split('\n')) {
    if (!line.trim() || line.startsWith('#')) continue;

    if (/^\S/.test(line)) {
      pendingName = specName(line.replace(/:\s*$/, ''));
      continue;
    }

    const version = /^\s{2}"?version"?:?\s*"?([^"\s]+)"?\s*$/.exec(line)?.[1];
    if (!version || !pendingName) continue;
    if (!usableVersion(version)) continue;

    const id = `${pendingName}@${version}`;
    if (!seen.has(id)) {
      seen.add(id);
      out.push({ name: pendingName, version, ecosystem: 'npm', source });
    }
    pendingName = null;
  }

  return out;
}

/**
 * Protocols that point at local code rather than a published release.
 *
 * Berry records a workspace package as `my-app@workspace:.` with the version
 * `0.0.0-use.local`, which looks like an ordinary release to any check based on
 * the version string alone. Reading the protocol is what tells them apart.
 */
const LOCAL_PROTOCOLS = ['workspace:', 'file:', 'link:', 'portal:', 'patch:', 'exec:'];

/** `"lodash@npm:^4.17.15, lodash@^4.0.0"` -> `lodash`; local protocols -> null. */
function specName(header: string): string | null {
  const first = header.split(',')[0]?.trim().replace(/^['"]|['"]$/g, '');
  if (!first) return null;
  const at = first.lastIndexOf('@');
  if (at <= 0) return null;
  const name = first.slice(0, at);
  const range = first.slice(at + 1);
  if (LOCAL_PROTOCOLS.some((protocol) => range.startsWith(protocol))) return null;
  return name || null;
}

// --- bun ---

/**
 * bun.lock — JSON with comments and trailing commas, which `JSON.parse`
 * rejects. Each `packages` entry is an array whose first element is the
 * familiar `name@version` key.
 */
export function parseBunLock(text: string, source: string): LockPackage[] {
  let lock: { packages?: Record<string, unknown> };
  try {
    lock = JSON.parse(stripJsonc(text)) as { packages?: Record<string, unknown> };
  } catch {
    return [];
  }

  const out: LockPackage[] = [];
  for (const [key, raw] of Object.entries(lock.packages ?? {})) {
    const descriptor = Array.isArray(raw) && typeof raw[0] === 'string' ? raw[0] : key;
    const split = splitNameVersion(descriptor);
    if (!split || !usableVersion(split.version)) continue;
    out.push({ ...split, ecosystem: 'npm', source });
  }
  return out;
}

/** Remove `//` and block comments outside strings, then trailing commas. */
function stripJsonc(text: string): string {
  let out = '';
  let inString = false;
  let escaped = false;

  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i] as string;
    if (inString) {
      out += ch;
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') {
      inString = true;
      out += ch;
      continue;
    }
    if (ch === '/' && text[i + 1] === '/') {
      while (i < text.length && text[i] !== '\n') i += 1;
      out += '\n';
      continue;
    }
    if (ch === '/' && text[i + 1] === '*') {
      i += 2;
      while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) i += 1;
      i += 1;
      continue;
    }
    out += ch;
  }

  return out.replace(/,(\s*[}\]])/g, '$1');
}

// --- dispatch ---

const PARSERS: Record<string, (text: string, source: string) => LockPackage[]> = {
  'package-lock.json': parseNpmLock,
  'npm-shrinkwrap.json': parseNpmLock,
  'pnpm-lock.yaml': parsePnpmLock,
  'yarn.lock': parseYarnLock,
  'bun.lock': parseBunLock,
};

/**
 * Lockfiles osv-scanner reads that the built-in engine does not, mapped to the
 * ecosystem they belong to. Finding one is not an error — it means a fallback
 * to the binary would see more than we can, which the user deserves to be told.
 */
const FOREIGN_MANIFESTS: Record<string, string> = {
  'requirements.txt': 'PyPI',
  'poetry.lock': 'PyPI',
  'Pipfile.lock': 'PyPI',
  'uv.lock': 'PyPI',
  'pdm.lock': 'PyPI',
  'go.mod': 'Go',
  'go.sum': 'Go',
  'Cargo.lock': 'crates.io',
  'Gemfile.lock': 'RubyGems',
  'composer.lock': 'Packagist',
  'pom.xml': 'Maven',
  'build.gradle': 'Maven',
  'build.gradle.kts': 'Maven',
  'gradle.lockfile': 'Maven',
  'pubspec.lock': 'Pub',
  'mix.lock': 'Hex',
  'packages.lock.json': 'NuGet',
  'conan.lock': 'ConanCenter',
  'renv.lock': 'CRAN',
};

const SKIP_DIRS = new Set(['node_modules', '.git']);
const MAX_DEPTH = 8;

/**
 * Non-Node manifests anywhere under `dir`, as paths relative to it.
 *
 * Used only to warn. The built-in engine reports npm findings correctly whether
 * or not a Go module sits beside them; what it must not do is let that silence
 * read as "nothing found here".
 */
export function findForeignManifests(dir: string): { file: string; ecosystem: string }[] {
  const found: { file: string; ecosystem: string }[] = [];

  const walk = (current: string, depth: number): void => {
    if (depth > MAX_DEPTH || found.length >= 100) return;
    let entries;
    try {
      entries = readdirSync(current, { withFileTypes: true });
    } catch {
      return;
    }
    const subdirs: string[] = [];
    for (const entry of entries) {
      const ecosystem = FOREIGN_MANIFESTS[entry.name];
      if (entry.isFile() && ecosystem) {
        found.push({
          file: path.relative(dir, path.join(current, entry.name)).split(path.sep).join('/'),
          ecosystem,
        });
      } else if (entry.isDirectory() && !SKIP_DIRS.has(entry.name) && !entry.name.startsWith('.')) {
        subdirs.push(path.join(current, entry.name));
      }
    }
    for (const subdir of subdirs) walk(subdir, depth + 1);
  };

  walk(dir, 0);
  return found.sort((a, b) => a.file.localeCompare(b.file));
}

/**
 * Read every lockfile in `lockfiles` (paths relative to `dir`) and return the
 * union of what they declare.
 *
 * Duplicates across lockfiles are kept apart by source, because a monorepo that
 * pins a vulnerable package in two workspaces has two things to fix, and the
 * report says so per package. Within one lockfile they are collapsed.
 */
export function readLockfiles(dir: string, lockfiles: string[]): LockfileScan {
  const packages: LockPackage[] = [];
  const parsed: string[] = [];
  const unsupported: UnsupportedLockfile[] = [];

  for (const rel of lockfiles) {
    const base = path.basename(rel);
    const full = path.join(dir, rel);

    if (base === 'bun.lockb') {
      unsupported.push({
        file: rel,
        ecosystem: 'npm',
        reason: 'binary lockfile — run `bun install --save-text-lockfile` to emit bun.lock',
      });
      continue;
    }

    const parser = PARSERS[base];
    if (!parser) {
      unsupported.push({ file: rel, ecosystem: null, reason: 'unrecognized lockfile format' });
      continue;
    }

    let text: string;
    try {
      text = readFileSync(full, 'utf8');
    } catch {
      unsupported.push({ file: rel, ecosystem: null, reason: 'could not be read' });
      continue;
    }

    const found = parser(text, rel);
    if (found.length === 0) {
      unsupported.push({ file: rel, ecosystem: 'npm', reason: 'no packages could be read from it' });
      continue;
    }
    parsed.push(rel);
    packages.push(...found);
  }

  return { packages: dedupe(packages), parsed, unsupported };
}

function dedupe(packages: LockPackage[]): LockPackage[] {
  const seen = new Set<string>();
  const out: LockPackage[] = [];
  for (const pkg of packages) {
    const id = `${pkg.source}\u0000${pkg.name}\u0000${pkg.version}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(pkg);
  }
  return out;
}

/** True when `dir` looks like a Node project at all. */
export function hasPackageJson(dir: string): boolean {
  return existsSync(path.join(dir, 'package.json'));
}
