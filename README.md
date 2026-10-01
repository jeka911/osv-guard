# osv-guard

Two guards against known-bad dependencies, both backed by the [OSV](https://osv.dev) database.

| | What it stops | Needs |
| --- | --- | --- |
| [**Claude Code plugin**](#claude-code-plugin) | An agent **installing** a malicious or vulnerable package | Nothing but Claude Code |
| [**npm run guard**](#cli) | **Executing** `npm run` commands and scripts against a vulnerable lockfile | Nothing but Node 18+ |

They cover different halves of the same problem. The CLI checks what is already in your lockfile before it lets a script start. The plugin checks a package *before* your agent is allowed to install it — the gap the CLI cannot reach, because once a bad dependency is in the lockfile its install scripts have already run.

---

## Claude Code plugin

Blocks your agent from installing packages OSV knows are malicious.

```bash
claude plugin marketplace add jeka-kiselyov/osv-guard
claude plugin install osv-guard@osv-guard
```

Inside a session, use `/plugin marketplace add …` and `/plugin install …` instead, then `/reload-plugins`.

That's the whole setup. No API key, no account, and **no `osv-scanner` binary** — packages that aren't installed yet aren't in any lockfile, so the hook queries the OSV API directly.

Ask Claude to install something malicious and the command never runs:

```
MALICIOUS  icomm-mobile@1.0.0 — MAL-2024-2500
           affected versions: 1.0.0
           Malicious code in icomm-mobile (npm)

osv-guard blocked this install: OSV reports the package itself as malicious.
```

Claude isn't asked to verify anything and isn't consulted on the verdict — the hook queries OSV itself and hands back a decision, so an agent can't skip it, forget it, or be argued out of it.

| Situation | Decision |
| --- | --- |
| OSV reports the package as malicious | **deny** — always, and no `ignore` entry can waive it |
| Vulnerability at or above your threshold | **ask** — you decide |
| Version published less than 7 days ago | **ask** — you decide |
| Anything else, or a registry is unreachable | **allow**, silently |

Malware is denied rather than asked because it isn't a severity judgement. That separation is also load-bearing: OSV's malicious-package advisories carry **no severity data at all**, so a threshold on its own would band every one of them `unknown` and wave them through.

### Brand-new releases

A version published minutes ago is the riskiest thing you can install: when a package is compromised, the malicious release is usually caught and pulled within hours to a few days. osv-guard holds anything younger than **7 days** and asks:

```
TOO NEW    left-pad@1.3.1 — published 4 hours ago

osv-guard holds releases younger than 7 days: that is the window in which a
compromised release is usually caught and pulled. Approve to install anyway, or
pin an older version. To stop asking: add "allowNewPackages": ["left-pad"]
to osv-guard.json, or set "minReleaseAge": 0 to turn the check off.
```

Approving the prompt installs it — this is a speed bump, not a wall. An install with no version pinned is measured against whatever `latest` currently resolves to, since that's what you'd actually get.

Tune it in [config](#config-file) with `minReleaseAge` (`"0"` disables, `"24h"`, `"30d"`) and `allowNewPackages` for packages you always want fresh — your own, typically.

If a registry is slow or a package predates its publish-time data, the age is unknown and the install is **allowed**. Failing closed would block everything during an outage, and that guard gets switched off.

The hook reads the same [config file](#config-file) as the CLI, so `failOn` and `ignore` apply to both.

---

## CLI

Guards what you **run** — any npm script. For example, change `"dev": "vite"` to `"dev": "osv-guard vite"` in your `package.json`. Now `npm run dev` (or `pnpm dev`) first scans the package the script lives in, and the dev server starts only if nothing at or above your threshold turns up.

```
osv-guard · scanned . (package-lock.json) 1.2s

  CRITICAL 1   MODERATE 1

  ✖ CRITICAL  9.8  minimist@0.0.8  GHSA-xvch-5gv4-984h
                 Prototype Pollution in minimist
                 → fixed in 0.2.4  https://github.com/advisories/GHSA-xvch-5gv4-984h
  · MODERATE  5.6  minimist@0.0.8  GHSA-vh95-rmgr-6w4m
                 Prototype Pollution in minimist
                 → fixed in 0.2.1  https://github.com/advisories/GHSA-vh95-rmgr-6w4m

  ✖ blocked: 1 critical at or above the `high` threshold

  `npm run dev` was not started.
```

### Requirements

Node 18+. Nothing else — no binary to install, no account, no API key.

osv-guard reads your lockfile itself and asks [OSV](https://osv.dev) about the exact versions it finds, in one batched request. What leaves your machine is a list of package names and versions, never your code.

### Using the osv-scanner binary instead

The built-in scanner reads **Node lockfiles only** — `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock` and `bun.lock`. For anything else, or to scan without a network, install [osv-scanner](https://github.com/google/osv-scanner) — Google's free, open-source scanner, which covers twenty-odd ecosystems:

```bash
brew install osv-scanner
```

Or `go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest`, or grab a [release binary](https://github.com/google/osv-scanner/releases). Then:

```bash
osv-guard --scanner osv-scanner report      # always use the binary
osv-guard --scanner auto report             # use it when installed, else built-in
```

Point at a non-`PATH` install with `--scanner-bin`, which selects the binary on its own.

Findings are identical either way: both read the same OSV data, and both collapse a flaw's GHSA and CVE ids into one finding. Scores can differ by a decimal on advisories that publish only a CVSS **v4** vector, which the built-in scanner reports by band rather than approximating.

If osv-guard finds a Go, Python, Rust or other non-Node manifest while the built-in scanner is running, it says so rather than letting the silence read as *clean*:

```
osv-guard: the built-in scanner reads Node lockfiles only — 1 Go, 1 PyPI manifests not checked
osv-guard:   api/requirements.txt, go.mod
osv-guard:   install osv-scanner and pass --scanner osv-scanner to cover Go, PyPI
```

And when there is **no** Node lockfile at all but osv-scanner is installed, osv-guard uses it automatically — a pure Go or Rust repo still gets scanned rather than being told it has no lockfile.

### Install

```bash
npm install --save-dev osv-guard
```

Then put the guard in front of whatever you want to protect:

```json
{
  "scripts": {
    "dev": "osv-guard vite",
    "build": "osv-guard hardhat build"
  }
}
```

`npm run dev` / `pnpm dev` now scan first and start the tool only if the scan passes.

### Usage

```bash
osv-guard <target> [args...]        # scan, then run <target>
osv-guard exec <command> [args]     # scan, then run a command directly
osv-guard report                    # scan and print, run nothing
```

`<target>` is a **package.json script** when one matches, otherwise a **command** from `node_modules/.bin` or `PATH`. So both of these work:

```bash
osv-guard dev              # -> pnpm run dev
osv-guard hardhat build    # -> hardhat build
```

A script always wins over a same-named binary; use `exec` to force the command. An unknown name is an error listing your actual scripts, not an opaque "command not found".

The two kinds differ in working directory, matching what each would do unguarded: a **script** runs from the package root, as `npm run` and `pnpm run` always do, while a **command** keeps your current directory, so relative paths like `osv-guard jest src/x.test.js` still mean what they say.

Options go **before** the target; everything after it is forwarded verbatim.

```bash
osv-guard --fail-on critical dev --port 3000
```

Note that `"build": "osv-guard build"` would make osv-guard run `build`, which re-invokes osv-guard, forever. osv-guard detects that and refuses with the fix rather than hanging.

### Package managers

Scripts run through the package manager your project actually uses — detected from the `packageManager` field, then the lockfile, then the invoking user agent — or forced with `--package-manager`.

### Thresholds

| Flag | Default | Meaning |
| --- | --- | --- |
| `--fail-on <band>` | `high` | Block at this band and above (`low`, `moderate`, `high`, `critical`) |
| `--fail-on-unknown` | off | Also block findings with no usable severity |
| `--max-critical <n>` | — | Allow at most n critical findings |
| `--max-high <n>` | — | Allow at most n high findings |
| `--max-moderate <n>` | — | Allow at most n moderate findings |
| `--max-low <n>` | — | Allow at most n low findings |

A `--max-<band>` budget replaces the threshold **for that band only**, so `--fail-on high --max-high 2` tolerates two highs while still blocking on any critical.

### Suppression

| Flag | Meaning |
| --- | --- |
| `--ignore <id,...>` | Skip advisories by GHSA, CVE or OSV id (repeatable; matches aliases) |
| `--ignore-unfixed` | Skip findings with no published fix |

Ignore entries that match nothing are reported, so stale suppressions don't quietly rot.

For long-lived, per-advisory suppressions prefer osv-scanner's own `osv-scanner.toml`, which osv-guard picks up automatically.

### Scanning

| Flag | Meaning |
| --- | --- |
| `--dir`, `-C <path>` | Directory to scan (default: the package npm runs from) |
| `--scanner <engine>` | `builtin` (default), `osv-scanner`, or `auto` |
| `--scanner-bin <path>` | osv-scanner binary (default: `osv-scanner`); implies `--scanner osv-scanner` |
| `--package-manager <pm>` | Force `npm`, `pnpm`, `yarn` or `bun` instead of detecting |
| `--offline` | Use osv-scanner's local database, no network (implies `--scanner osv-scanner`) |
| `--all-vulns` | Include findings osv-scanner considers unimportant or uncalled |
| `--allow-no-lockfile` | Don't fail when no lockfile is present |
| `--cache` | Reuse a recent scan for the same lockfile (**off by default**) |
| `--cache-ttl <duration>` | Cache lifetime — `30s`, `15m`, `1h` (default `1h`; implies `--cache`) |

#### About the cache

Off by default: a guard that can return a stale answer isn't much of a guard. When you do enable it, the key is the **hash of your lockfile contents**, so any dependency change busts it immediately — the TTL only bounds how long an *unchanged* tree is trusted.

Policy flags are applied *after* the cache, so tightening `--fail-on` or adding an `--ignore` takes effect without a rescan.

Cached results live in `node_modules/.cache/osv-guard/`.

#### Monorepos

Scanning is recursive, so a monorepo root is a valid target even when only the sub-packages carry lockfiles:

```
osv-guard · scanned . (3 lockfiles) 1.1s

  ✖ CRITICAL  9.8  minimist@0.0.8  in packages/app  GHSA-xvch-5gv4-984h
  ✖ CRITICAL  9.8  minimist@0.0.8  in tools/cli     GHSA-xvch-5gv4-984h
```

An advisory affecting two packages is reported once per package — each needs its own fix — and every finding is labelled with the package it came from. Thresholds and budgets apply across the whole tree, and one `--ignore` entry covers every package.

Run osv-guard *inside* a package instead and it scans only that package, since the walk-up stops at the nearest `package.json`.

`--cache` keys on the contents of every lockfile found, sub-packages included, so a dependency change anywhere in the monorepo invalidates it.

#### About lockfiles

If there's no lockfile anywhere in the tree, osv-guard stops rather than scanning. There would be nothing to resolve, and an empty result is indistinguishable from a clean one — a false green is worse than an error. Run `npm install`, or pass `--allow-no-lockfile` to accept an unchecked run.

`bun.lockb` is binary and can't be read; run `bun install --save-text-lockfile` to emit a `bun.lock` beside it, or use the osv-scanner binary.

### Output

| Flag | Meaning |
| --- | --- |
| `--format`, `-f <fmt>` | `pretty` (default), `json`, `summary` |
| `--json` | Shorthand for `--format json` |
| `--quiet`, `-q` | Only print when the run is blocked |
| `--verbose` | Show how the scan target and config were resolved |
| `--color` / `--no-color` | Force or disable ANSI color |

Reports go to **stderr** and `--format=json` goes to stdout, so `osv-guard report --json | jq` works while a guarded script keeps its own stdout clean.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Passed (and the script exited 0) |
| `1` | Blocked by policy — the script was not run |
| `2` | Usage or configuration error |
| `3` | The scan could not run — OSV unreachable, or osv-scanner missing/failed |
| * | Otherwise, the script's own exit code |

### CI

```yaml
- run: npm ci
- run: npx osv-guard report --format json > osv.json
```

Exit code `1` fails the job on a policy violation; `3` distinguishes a scan that couldn't run from a real finding.

---

## Config file

Shared by the CLI and the plugin. Settings can live in `osv-guard.json`, `.osv-guardrc.json`, or an `osv-guard` key in `package.json`. Command-line flags win.

```json
{
  "failOn": "high",
  "scanner": "builtin",
  "max": { "critical": 0 },
  "ignore": ["GHSA-xxxx-xxxx-xxxx"],
  "ignoreUnfixed": true,
  "minReleaseAge": "7d",
  "allowNewPackages": ["my-own-package"]
}
```

## How severity is decided

Findings are grouped the way osv-scanner groups them, so a flaw with both a GHSA and a CVE id counts once, not twice.

Each group's band comes from the first available of:

1. the group's `max_severity` (a CVSS base score osv-scanner computes, when the binary is in use),
2. GitHub's `database_specific.severity` (`CRITICAL`/`HIGH`/`MODERATE`/`LOW`),
3. the highest CVSS v3.x vector in the group, scored locally.

Anything left is reported as `unknown` rather than assumed benign. Unknowns don't block by default — `--fail-on-unknown` changes that. CVSS v4-only vectors are not scored, so an advisory with nothing else to go on lands in `unknown`; in practice GitHub's rating covers them.

The suggested fix version is taken from the affected range that actually contains your installed version, so `axios@0.21.0` is told about `0.31.1`, not about a fix on the 1.x line.

## License

MIT
