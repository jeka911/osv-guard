import { readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { BANDS, type Band } from './types.js';

export type Format = 'pretty' | 'json' | 'summary';

/**
 * Which engine resolves the lockfile and queries OSV.
 *
 * `builtin` needs nothing but Node; `osv-scanner` shells out to the binary,
 * which covers far more ecosystems and can work offline; `auto` prefers the
 * binary when it is installed and falls back to the built-in engine.
 */
export type ScanEngine = 'builtin' | 'osv-scanner' | 'auto';

export interface Options {
  failOn: Band;
  failOnUnknown: boolean;
  max: Partial<Record<Band, number>>;
  ignore: string[];
  ignoreUnfixed: boolean;
  dir: string | undefined;
  format: Format;
  cache: boolean;
  cacheTtlMs: number;
  offline: boolean;
  allVulns: boolean;
  scanner: ScanEngine;
  scannerBin: string;
  packageManager: string | undefined;
  /** Block installs of versions published less than this long ago. 0 disables. */
  minReleaseAgeMs: number;
  /** Packages exempt from the age check: "name" or "name@version". */
  allowNewPackages: string[];
  allowNoLockfile: boolean;
  quiet: boolean;
  verbose: boolean;
  color: boolean | undefined;
}

export interface ParsedArgv {
  command: 'run' | 'report' | 'hook' | 'help' | 'version';
  /** `exec` was used: treat the target as a command, never a script. */
  forceCommand: boolean;
  /** npm script name for `run`. */
  script: string | undefined;
  /** Arguments forwarded verbatim to the npm script. */
  scriptArgs: string[];
  /** Only the options explicitly given on the command line. */
  cliOptions: Partial<Options>;
}

export const DEFAULTS: Options = {
  failOn: 'high',
  failOnUnknown: false,
  max: {},
  ignore: [],
  ignoreUnfixed: false,
  dir: undefined,
  format: 'pretty',
  cache: false,
  cacheTtlMs: 60 * 60 * 1000,
  offline: false,
  allVulns: false,
  scanner: 'builtin',
  scannerBin: 'osv-scanner',
  packageManager: undefined,
  // Seven days clears the window in which most malicious releases are caught
  // and pulled, while rarely catching a package anyone urgently needs.
  minReleaseAgeMs: 7 * 24 * 60 * 60 * 1000,
  allowNewPackages: [],
  allowNoLockfile: false,
  quiet: false,
  verbose: false,
  color: undefined,
};

export class UsageError extends Error {}

const BAND_SET = new Set<string>(BANDS);
const FORMATS = new Set<Format>(['pretty', 'json', 'summary']);
const ENGINES = new Set<ScanEngine>(['builtin', 'osv-scanner', 'auto']);

function asEngine(value: string, label: string): ScanEngine {
  const v = value.trim().toLowerCase();
  // `scanner` and `binary` read naturally for "use the real thing".
  const normalized = v === 'scanner' || v === 'binary' ? 'osv-scanner' : v;
  if (!ENGINES.has(normalized as ScanEngine)) {
    throw new UsageError(`${label} must be builtin, osv-scanner or auto (got "${value}")`);
  }
  return normalized as ScanEngine;
}

/** Accepts `1h`, `30m`, `45s`, `500ms`; a bare number is seconds. */
export function parseDuration(input: string): number {
  const m = /^(\d+(?:\.\d+)?)(ms|s|m|h|d)?$/.exec(input.trim());
  if (!m) throw new UsageError(`invalid duration: ${input} (try 30s, 15m, 1h)`);
  const value = Number(m[1]);
  switch (m[2]) {
    case 'ms':
      return value;
    case 'm':
      return value * 60_000;
    case 'h':
      return value * 3_600_000;
    case 'd':
      return value * 86_400_000;
    default:
      return value * 1000;
  }
}

function asBand(value: string, flag: string): Band {
  const v = value.trim().toLowerCase();
  const normalized = v === 'medium' ? 'moderate' : v;
  if (!BAND_SET.has(normalized)) {
    throw new UsageError(`${flag} must be one of ${BANDS.join(', ')} (got "${value}")`);
  }
  return normalized as Band;
}

function asCount(value: string, flag: string): number {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 0) {
    throw new UsageError(`${flag} must be a non-negative integer (got "${value}")`);
  }
  return n;
}

/**
 * Split argv into osv-guard's own flags and the script invocation.
 *
 * Everything up to the first bare word is ours; that word is the script name
 * and every token after it belongs to the script. `--` also ends our flags,
 * which is the escape hatch for a script literally named like a flag.
 */
export function parseArgv(argv: string[]): ParsedArgv {
  const cli: Partial<Options> = {};
  const ignore: string[] = [];
  const allowNew: string[] = [];
  const max: Partial<Record<Band, number>> = {};
  let command: ParsedArgv['command'] | null = null;
  let script: string | undefined;
  let forceCommand = false;
  const scriptArgs: string[] = [];

  let i = 0;
  const next = (flag: string): string => {
    const value = argv[++i];
    if (value === undefined) throw new UsageError(`${flag} requires a value`);
    return value;
  };

  for (; i < argv.length; i++) {
    const token = argv[i]!;

    if (token === '--') {
      // Remaining tokens: first is the script, rest are its args.
      const rest = argv.slice(i + 1);
      if (rest.length > 0) {
        script = rest[0];
        scriptArgs.push(...rest.slice(1));
      }
      break;
    }

    if (!token.startsWith('-')) {
      if (token === 'report' || token === 'scan') {
        command = 'report';
        continue;
      }
      if (token === 'hook') {
        command = 'hook';
        continue;
      }
      if (token === 'run') {
        // `osv-guard run dev` — tolerate the explicit verb.
        continue;
      }
      if (token === 'exec') {
        // Everything after `exec` is a command line, flags included.
        forceCommand = true;
        const rest = argv.slice(i + 1);
        if (rest.length > 0) {
          script = rest[0];
          scriptArgs.push(...rest.slice(1));
        }
        break;
      }
      script = token;
      scriptArgs.push(...argv.slice(i + 1));
      break;
    }

    const eq = token.indexOf('=');
    const name = eq === -1 ? token : token.slice(0, eq);
    const inlineValue = eq === -1 ? undefined : token.slice(eq + 1);
    const value = (): string => inlineValue ?? next(name);

    switch (name) {
      case '-h':
      case '--help':
        command = 'help';
        break;
      case '-v':
      case '--version':
        command = 'version';
        break;
      case '--fail-on':
        cli.failOn = asBand(value(), '--fail-on');
        break;
      case '--fail-on-unknown':
        cli.failOnUnknown = true;
        break;
      case '--no-fail-on-unknown':
        cli.failOnUnknown = false;
        break;
      case '--max-critical':
        max.critical = asCount(value(), '--max-critical');
        break;
      case '--max-high':
        max.high = asCount(value(), '--max-high');
        break;
      case '--max-moderate':
      case '--max-medium':
        max.moderate = asCount(value(), name);
        break;
      case '--max-low':
        max.low = asCount(value(), '--max-low');
        break;
      case '--ignore':
        ignore.push(
          ...value()
            .split(',')
            .map((s) => s.trim())
            .filter(Boolean),
        );
        break;
      case '--ignore-unfixed':
        cli.ignoreUnfixed = true;
        break;
      case '--dir':
      case '-C':
        cli.dir = value();
        break;
      case '--format':
      case '-f': {
        const f = value().trim().toLowerCase();
        if (!FORMATS.has(f as Format)) {
          throw new UsageError(`--format must be pretty, json or summary (got "${f}")`);
        }
        cli.format = f as Format;
        break;
      }
      case '--json':
        cli.format = 'json';
        break;
      case '--cache':
        cli.cache = true;
        break;
      case '--no-cache':
        cli.cache = false;
        break;
      case '--cache-ttl':
        cli.cacheTtlMs = parseDuration(value());
        // A TTL is a clear statement of intent to cache.
        cli.cache ??= true;
        break;
      case '--offline':
        cli.offline = true;
        break;
      case '--all-vulns':
        cli.allVulns = true;
        break;
      case '--scanner':
      case '--engine':
        cli.scanner = asEngine(value(), name);
        break;
      case '--scanner-bin':
        cli.scannerBin = value();
        // Naming a binary is a clear statement that it should be used.
        cli.scanner ??= 'osv-scanner';
        break;
      case '--package-manager':
      case '--pm':
        cli.packageManager = value();
        break;
      case '--min-release-age':
        cli.minReleaseAgeMs = parseDuration(value());
        break;
      case '--no-min-release-age':
        cli.minReleaseAgeMs = 0;
        break;
      case '--allow-new':
        allowNew.push(
          ...value()
            .split(',')
            .map((s) => s.trim())
            .filter(Boolean),
        );
        break;
      case '--allow-no-lockfile':
        cli.allowNoLockfile = true;
        break;
      case '-q':
      case '--quiet':
        cli.quiet = true;
        break;
      case '--verbose':
        cli.verbose = true;
        break;
      case '--color':
        cli.color = true;
        break;
      case '--no-color':
        cli.color = false;
        break;
      default:
        throw new UsageError(`unknown option: ${name}`);
    }
  }

  if (ignore.length > 0) cli.ignore = ignore;
  if (allowNew.length > 0) cli.allowNewPackages = allowNew;
  if (Object.keys(max).length > 0) cli.max = max;

  return {
    command: command ?? (script ? 'run' : 'help'),
    forceCommand,
    script,
    scriptArgs,
    cliOptions: cli,
  };
}

const CONFIG_FILES = ['osv-guard.json', '.osv-guardrc.json', '.osv-guardrc'];

/** Reads `osv-guard.json`, `.osv-guardrc[.json]`, or a `osv-guard` key in package.json. */
export function loadConfigFile(dir: string): { config: Partial<Options>; path: string | null } {
  for (const name of CONFIG_FILES) {
    const file = path.join(dir, name);
    if (existsSync(file)) return { config: coerceConfig(readJson(file), name), path: file };
  }

  const pkgPath = path.join(dir, 'package.json');
  if (existsSync(pkgPath)) {
    const pkg = readJson(pkgPath) as Record<string, unknown>;
    const embedded = pkg?.['osv-guard'];
    if (embedded && typeof embedded === 'object') {
      return { config: coerceConfig(embedded, "package.json#osv-guard"), path: pkgPath };
    }
  }

  return { config: {}, path: null };
}

function readJson(file: string): unknown {
  try {
    return JSON.parse(readFileSync(file, 'utf8'));
  } catch (err) {
    throw new UsageError(`could not read ${file}: ${(err as Error).message}`);
  }
}

/** Validate the config file with the same strictness as the flags. */
function coerceConfig(raw: unknown, label: string): Partial<Options> {
  if (!raw || typeof raw !== 'object') return {};
  const input = raw as Record<string, unknown>;
  const out: Partial<Options> = {};

  const str = (key: string): string | undefined => {
    const v = input[key];
    if (v === undefined) return undefined;
    if (typeof v !== 'string') throw new UsageError(`${label}: "${key}" must be a string`);
    return v;
  };
  const bool = (key: string): boolean | undefined => {
    const v = input[key];
    if (v === undefined) return undefined;
    if (typeof v !== 'boolean') throw new UsageError(`${label}: "${key}" must be a boolean`);
    return v;
  };

  const failOn = str('failOn');
  if (failOn !== undefined) out.failOn = asBand(failOn, `${label}: failOn`);

  const format = str('format');
  if (format !== undefined) {
    if (!FORMATS.has(format as Format)) {
      throw new UsageError(`${label}: "format" must be pretty, json or summary`);
    }
    out.format = format as Format;
  }

  const failOnUnknown = bool('failOnUnknown');
  if (failOnUnknown !== undefined) out.failOnUnknown = failOnUnknown;
  const ignoreUnfixed = bool('ignoreUnfixed');
  if (ignoreUnfixed !== undefined) out.ignoreUnfixed = ignoreUnfixed;
  const cache = bool('cache');
  if (cache !== undefined) out.cache = cache;
  const offline = bool('offline');
  if (offline !== undefined) out.offline = offline;
  const allVulns = bool('allVulns');
  if (allVulns !== undefined) out.allVulns = allVulns;
  const allowNoLockfile = bool('allowNoLockfile');
  if (allowNoLockfile !== undefined) out.allowNoLockfile = allowNoLockfile;

  const scanner = str('scanner');
  if (scanner !== undefined) out.scanner = asEngine(scanner, `${label}: scanner`);
  const scannerBin = str('scannerBin');
  if (scannerBin !== undefined) out.scannerBin = scannerBin;
  const packageManager = str('packageManager');
  if (packageManager !== undefined) out.packageManager = packageManager;

  const minReleaseAge = input.minReleaseAge;
  if (minReleaseAge !== undefined) {
    out.minReleaseAgeMs =
      typeof minReleaseAge === 'number' ? minReleaseAge : parseDuration(String(minReleaseAge));
  }

  if (input.allowNewPackages !== undefined) {
    if (
      !Array.isArray(input.allowNewPackages) ||
      input.allowNewPackages.some((v) => typeof v !== 'string')
    ) {
      throw new UsageError(`${label}: "allowNewPackages" must be an array of package names`);
    }
    out.allowNewPackages = input.allowNewPackages as string[];
  }
  const dir = str('dir');
  if (dir !== undefined) out.dir = dir;
  const cacheTtl = input.cacheTtl;
  if (cacheTtl !== undefined) {
    out.cacheTtlMs =
      typeof cacheTtl === 'number' ? cacheTtl : parseDuration(String(cacheTtl));
  }

  if (input.ignore !== undefined) {
    if (!Array.isArray(input.ignore) || input.ignore.some((v) => typeof v !== 'string')) {
      throw new UsageError(`${label}: "ignore" must be an array of advisory ids`);
    }
    out.ignore = input.ignore as string[];
  }

  if (input.max !== undefined) {
    if (!input.max || typeof input.max !== 'object') {
      throw new UsageError(`${label}: "max" must be an object`);
    }
    const max: Partial<Record<Band, number>> = {};
    for (const [key, value] of Object.entries(input.max as Record<string, unknown>)) {
      const band = asBand(key, `${label}: max`);
      max[band] = asCount(String(value), `${label}: max.${key}`);
    }
    out.max = max;
  }

  return out;
}

/** CLI flags beat the config file, which beats the built-in defaults. */
export function mergeOptions(fileConfig: Partial<Options>, cli: Partial<Options>): Options {
  return {
    ...DEFAULTS,
    ...stripUndefined(fileConfig),
    ...stripUndefined(cli),
    max: { ...(fileConfig.max ?? {}), ...(cli.max ?? {}) },
    ignore: [...(fileConfig.ignore ?? []), ...(cli.ignore ?? [])],
    allowNewPackages: [
      ...(fileConfig.allowNewPackages ?? []),
      ...(cli.allowNewPackages ?? []),
    ],
  };
}

function stripUndefined<T extends object>(obj: T): Partial<T> {
  return Object.fromEntries(
    Object.entries(obj).filter(([, v]) => v !== undefined),
  ) as Partial<T>;
}
