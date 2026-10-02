# osv-guard

osv-guard has two tools. Each tool stops known bad dependencies. Both tools use the [OSV](https://osv.dev) database.

| | What it stops | What you need |
| --- | --- | --- |
| [**Claude Code plugin**](#claude-code-plugin) | An agent that **installs** a malicious package or a package with a known problem | Claude Code only |
| [**osv-guard CLI**](#cli) | A script or command that **runs** with a lockfile that has a known problem | Node 18 or later only |

The two tools solve different parts of the same problem.

The CLI checks the lockfile before it lets a script start. The plugin checks a package before the agent installs it.

The CLI cannot do the work of the plugin. When a bad dependency is in the lockfile, its install scripts have already run.

---

## Claude Code plugin

The plugin stops your agent when it tries to install a package that OSV lists as malicious.

```bash
claude plugin marketplace add jeka911/osv-guard
claude plugin install osv-guard@osv-guard
```

In a session, use `/plugin marketplace add …` and `/plugin install …`. Then do `/reload-plugins`.

This is all the setup that you need. You do not need an API key or an account. You do not need the `osv-scanner` program.

A package that is not installed is not in a lockfile. Because of this, the hook asks the OSV API directly.

If you tell Claude to install a malicious package, the command does not run:

```
MALICIOUS  icomm-mobile@1.0.0 — MAL-2024-2500
           affected versions: 1.0.0
           Malicious code in icomm-mobile (npm)

osv-guard blocked this install: OSV reports the package itself as malicious.
```

The hook does the check. Claude does not do the check and does not make the decision. The hook asks OSV and returns the decision.

The agent cannot skip the check. The agent cannot forget the check. The agent cannot be persuaded to change the decision.

| Situation | Decision |
| --- | --- |
| OSV reports that the package is malicious | **deny**. This decision never changes. No `ignore` entry can cancel it. |
| The package has a known problem at or above your threshold | **ask**. You make the decision. |
| The version is less than 7 days old | **ask**. You make the decision. |
| Any other case, or a registry does not respond | **allow**. The hook shows no message. |

The hook denies malware. It does not ask. Malware is not a question of severity.

This is also necessary for a technical reason. The OSV advisories for malicious packages have **no severity data**. A threshold alone puts each of them in the band `unknown`, and they all pass.

### New releases

A version that was just published has the highest risk. When a package is compromised, people usually find the malicious release and remove it. This takes from a few hours to a few days.

osv-guard holds each version that is less than **7 days** old, and asks you:

```
TOO NEW    left-pad@1.3.1 — published 4 hours ago

osv-guard holds releases younger than 7 days: that is the window in which a
compromised release is usually caught and pulled. Approve to install anyway, or
pin an older version. To stop asking: add "allowNewPackages": ["left-pad"]
to osv-guard.json, or set "minReleaseAge": 0 to turn the check off.
```

If you approve the prompt, the install continues. The hold is a delay, not a wall.

If you do not pin a version, osv-guard checks the version that `latest` points to now. This is the version that you get.

To change the hold, use `minReleaseAge` in the [config file](#config-file). Use `"0"` to turn it off. You can also use `"24h"` or `"30d"`.

To exempt a package, use `allowNewPackages`. Use it for packages that you always want to be new, for example your own packages.

Sometimes the age is unknown. A registry can be slow, or a package can have no publish-time data. In this case, the hook **allows** the install.

The hook does not fail closed. If it did, it would block all installs when a registry is down. Then people would turn the hook off.

The hook uses the same [config file](#config-file) as the CLI. The settings `failOn` and `ignore` apply to both tools.

---

## CLI

The CLI stops a command that you **run**. It works with each npm script.

For example, in `package.json`, change `"dev": "vite"` to `"dev": "osv-guard vite"`. Then `npm run dev` (or `pnpm dev`) does these steps:

1. It scans the package that contains the script.
2. It starts the dev server only if it finds no problem at or above your threshold.

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

You need Node 18 or later. You do not need anything else. You do not need a program to install, an account, or an API key.

osv-guard reads your lockfile. It sends the exact package versions to [OSV](https://osv.dev) in one batch request.

osv-guard sends only package names and versions from your machine. It never sends your code.

### Use the osv-scanner program

The built-in scanner reads **Node lockfiles only**. These are the files it reads:

- `package-lock.json`
- `npm-shrinkwrap.json`
- `pnpm-lock.yaml`
- `yarn.lock`
- `bun.lock`

For other file types, install [osv-scanner](https://github.com/google/osv-scanner). Also install it if you must scan without a network. Google makes osv-scanner. It is free and open source. It supports about 20 ecosystems.

```bash
brew install osv-scanner
```

You can also use `go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest`. Or download a [release binary](https://github.com/google/osv-scanner/releases). Then use one of these commands:

```bash
osv-guard --scanner osv-scanner report      # always use the binary
osv-guard --scanner auto report             # use it when installed, else built-in
```

If the program is not on your `PATH`, use `--scanner-bin`. This option also selects the program.

Both scanners give the same findings. They use the same OSV data. Both put the GHSA id and the CVE id of one flaw into one finding.

The scores can differ by 0.1 when an advisory also has a CVSS **v4** vector. The built-in scanner does not score v4 vectors. The band does not change.

The built-in scanner can find a manifest from another ecosystem, for example Go, Python, or Rust. If this occurs, osv-guard shows a message. The message tells you that these files are not checked. Without it, no output can look like a clean result.

```
osv-guard: the built-in scanner reads Node lockfiles only — 1 Go, 1 PyPI manifests not checked
osv-guard:   api/requirements.txt, go.mod
osv-guard:   install osv-scanner and pass --scanner osv-scanner to cover Go, PyPI
```

A project can have **no** Node lockfile. If osv-scanner is installed, osv-guard uses it automatically. A project that has only Go or Rust files is also scanned.

### Install

```bash
npm install --save-dev osv-guard
```

Put the guard in front of each command that you want to protect:

```json
{
  "scripts": {
    "dev": "osv-guard vite",
    "build": "osv-guard hardhat build"
  }
}
```

Now `npm run dev` and `pnpm dev` scan first. They start the tool only if the scan passes.

### Usage

```bash
osv-guard <target> [args...]        # scan, then run <target>
osv-guard exec <command> [args]     # scan, then run a command directly
osv-guard report                    # scan and print, run nothing
```

`<target>` is a **package.json script** if one matches. If none matches, `<target>` is a **command** from `node_modules/.bin` or from `PATH`. Both of these commands work:

```bash
osv-guard dev              # -> pnpm run dev
osv-guard hardhat build    # -> hardhat build
```

If a script and a program have the same name, the script is used. To run the program, use `exec`.

If the name is not known, osv-guard shows an error. The error lists the scripts in your project.

The working directory is different for each type of target. It is the same directory that the command uses without osv-guard:

- A **script** runs from the package root. `npm run` and `pnpm run` do the same.
- A **command** runs from your current directory. Relative paths, such as `osv-guard jest src/x.test.js`, keep their meaning.

Put the options **before** the target. osv-guard sends everything after the target to the target without change.

```bash
osv-guard --fail-on critical dev --port 3000
```

Do not use `"build": "osv-guard build"`. osv-guard runs `build`, and `build` starts osv-guard again. This repeats without end.

osv-guard detects this loop. It stops and shows how to correct it.

### Package managers

osv-guard runs scripts with the package manager of your project. It looks for the package manager in this order:

1. The `packageManager` field
2. The lockfile
3. The user agent of the caller

To select a package manager yourself, use `--package-manager`.

### Thresholds

| Option | Default | Meaning |
| --- | --- | --- |
| `--fail-on <band>` | `high` | Block at this band and above (`low`, `moderate`, `high`, `critical`) |
| `--fail-on-unknown` | off | Also block findings that have no usable severity |
| `--max-critical <n>` | none | Allow at most n critical findings |
| `--max-high <n>` | none | Allow at most n high findings |
| `--max-moderate <n>` | none | Allow at most n moderate findings |
| `--max-low <n>` | none | Allow at most n low findings |

A `--max-<band>` limit replaces the threshold for **that band only**.

For example, `--fail-on high --max-high 2` allows two high findings. It still blocks any critical finding.

### Suppression

| Option | Meaning |
| --- | --- |
| `--ignore <id,...>` | Skip advisories by GHSA, CVE, or OSV id. You can repeat the option. It matches aliases. |
| `--ignore-unfixed` | Skip findings that have no published fix |

osv-guard reports each ignore entry that matches nothing. This helps you remove old suppressions.

Only the **osv-scanner program** reads `osv-scanner.toml`. With the built-in scanner (the default), the suppressions in this file do not apply. osv-guard shows a warning when it finds this file.

For long-term suppressions, use `ignore` in the [config file](#config-file). Both scanners use it.

### Scanning

| Option | Meaning |
| --- | --- |
| `--dir`, `-C <path>` | The directory to scan. Default: the package that npm runs from. |
| `--scanner <engine>` | `builtin` (default), `osv-scanner`, or `auto` |
| `--scanner-bin <path>` | The osv-scanner program. Default: `osv-scanner`. It also selects `--scanner osv-scanner`. |
| `--package-manager <pm>` | Use `npm`, `pnpm`, `yarn`, or `bun`. osv-guard does not detect it. |
| `--offline` | Use the local database of osv-scanner. No network is used. It also selects `--scanner osv-scanner`. |
| `--all-vulns` | Include the findings that osv-scanner marks as unimportant or uncalled. Only the osv-scanner program uses this option. The built-in scanner does not filter. |
| `--allow-no-lockfile` | Do not fail when there is no lockfile |
| `--cache` | Use a recent scan of the same lockfile. This is **off by default**. |
| `--cache-ttl <duration>` | The time that the cache is valid: `30s`, `15m`, or `1h`. Default: `1h`. It also selects `--cache`. |

#### The cache

The cache is off by default. A cache can return an old answer. A guard must not do this.

When you turn the cache on, its key is the **hash of the lockfile contents**. If a dependency changes, the key changes, and the old cache is not used.

The time limit applies only to a tree that did not change.

osv-guard applies the policy options after the cache. If you use a lower `--fail-on` value or add an `--ignore`, it takes effect immediately. A new scan is not necessary.

The cached scan results are in `node_modules/.cache/osv-guard/`.

The built-in scanner also keeps the advisory details that it downloads. They are in `~/.cache/osv-guard/advisories/`. If `$XDG_CACHE_HOME` is set, they are under that directory.

Each entry uses the `modified` time from OSV as its key. An entry cannot be old.

This cache does not skip the check of which advisories affect your lockfile. It skips only the new download of the advisory text.

#### Monorepos

The scan is recursive. A monorepo root is a valid target, also when only the sub-packages have lockfiles:

```
osv-guard · scanned . (3 lockfiles) 1.1s

  ✖ CRITICAL  9.8  minimist@0.0.8  in packages/app  GHSA-xvch-5gv4-984h
  ✖ CRITICAL  9.8  minimist@0.0.8  in tools/cli     GHSA-xvch-5gv4-984h
```

If an advisory affects two packages, osv-guard reports it two times, one time for each package. Each package needs its own fix. Each finding shows the name of its package.

Thresholds and limits apply to the whole tree. One `--ignore` entry applies to all packages.

If you run osv-guard **inside** a package, it scans only that package. The search for the package root stops at the nearest `package.json`.

`--cache` uses the contents of all lockfiles as its key, also the lockfiles of sub-packages. A dependency change in any package makes the cache invalid.

#### Lockfiles

If the tree has no lockfile, osv-guard stops and does not scan. There is nothing to resolve. An empty result looks the same as a clean result. A false clean result is worse than an error.

To correct this, run `npm install`. Or use `--allow-no-lockfile` to accept a run that is not checked.

The file `bun.lockb` is binary. osv-guard cannot read it. To make a `bun.lock` file next to it, run `bun install --save-text-lockfile`. Or use the osv-scanner program.

### Output

| Option | Meaning |
| --- | --- |
| `--format`, `-f <fmt>` | `pretty` (default), `json`, or `summary` |
| `--json` | Short form of `--format json` |
| `--quiet`, `-q` | Show output only when the run is blocked |
| `--verbose` | Show how osv-guard found the scan target and the config |
| `--color` / `--no-color` | Turn ANSI color on or off |

Reports go to **stderr**. The output of `--format=json` goes to stdout.

Because of this, `osv-guard report --json | jq` works. A guarded script also keeps its own stdout clean.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | The check passed, and the script exited with 0 |
| `1` | The policy blocked the run. The script did not start. |
| `2` | Usage error or configuration error |
| `3` | The scan could not run. OSV did not respond, or osv-scanner is missing or failed. |
| other | The exit code of the script |

### CI

```yaml
- run: npm ci
- run: npx osv-guard report --format json > osv.json
```

Exit code `1` fails the job when the policy is broken. Exit code `3` shows that the scan could not run. This is different from a real finding.

---

## Config file

The CLI and the plugin use the same config file. Put the settings in one of these places:

- `osv-guard.json`
- `.osv-guardrc.json`
- the `osv-guard` key in `package.json`

Command-line options have priority.

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

## How osv-guard decides the severity

osv-guard puts findings in groups. It uses the same method as osv-scanner. A flaw that has a GHSA id and a CVE id counts one time, not two times.

osv-guard gets the band of a group from the first source that is available:

1. The `max_severity` of the group. This is a CVSS base score that osv-scanner calculates. It is available only when you use the osv-scanner program.
2. The `database_specific.severity` from GitHub (`CRITICAL`, `HIGH`, `MODERATE`, or `LOW`).
3. The highest CVSS v3.x vector in the group. osv-guard calculates the score.

If no source is available, osv-guard reports the band `unknown`. It does not assume that the finding is safe. By default, `unknown` findings do not block. To block them, use `--fail-on-unknown`.

osv-guard does not calculate the score of a CVSS v4 vector. An advisory that has only a v4 vector gets the band `unknown`. In most cases, the GitHub rating gives a band.

osv-guard shows the fix version from the affected range that contains your installed version. For example, for `axios@0.21.0`, it shows `0.31.1`. It does not show a fix from the 1.x line.

## License

MIT
