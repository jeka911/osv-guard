export const HELP = `
osv-guard — guard npm scripts behind a vulnerability check

USAGE
  osv-guard [options] <target> [args...]      scan, then run <target>
  osv-guard exec [options] <command> [args]   scan, then run a command directly
  osv-guard report [options]                  scan and print a report only
  osv-guard [options] -- <target> [args...]   explicit separator

  <target> is a package.json script when one matches, otherwise a command found
  in node_modules/.bin or on PATH — so both of these work:

    osv-guard dev                 ->  <pm> run dev
    osv-guard hardhat build       ->  hardhat build

  Scripts run through the project's package manager, detected from the
  "packageManager" field, then the lockfile, then the invoking user agent.
  Use \`exec\` to force command interpretation when a script shares the name.

  Options must come before the target. Everything after it is forwarded verbatim.

THRESHOLDS
  --fail-on <band>        block at this band and above (default: high)
                          bands: low, moderate, high, critical
  --fail-on-unknown       also block findings with no usable severity
  --max-critical <n>      allow at most n critical findings
  --max-high <n>          allow at most n high findings
  --max-moderate <n>      allow at most n moderate findings
  --max-low <n>           allow at most n low findings

  A --max-<band> budget replaces the threshold for that band only, so
  \`--fail-on high --max-high 2\` still blocks on any critical.

SUPPRESSION
  --ignore <id,...>       skip advisories by GHSA/CVE/OSV id (repeatable)
  --ignore-unfixed        skip findings with no published fix

SCANNING
  --dir, -C <path>        directory to scan (default: the package npm runs from;
                          scanning is recursive, so a monorepo root works)
  --scanner <engine>      builtin | osv-scanner | auto (default: builtin)
                          builtin reads lockfiles itself and queries osv.dev —
                          no binary needed, Node ecosystems only
  --scanner-bin <path>    osv-scanner binary (default: osv-scanner)
  --package-manager <pm>  force npm | pnpm | yarn | bun instead of detecting
  --offline               use osv-scanner's local database, no network
                          (implies --scanner osv-scanner)
  --all-vulns             include findings osv-scanner deems unimportant/uncalled
  --allow-no-lockfile     do not fail when no lockfile is present
  --cache                 reuse a recent scan for the same lockfile (off by default)
  --cache-ttl <duration>  cache lifetime, e.g. 30s, 15m, 1h (default: 1h; implies --cache)

OUTPUT
  --format, -f <fmt>      pretty | json | summary (default: pretty)
  --json                  shorthand for --format json
  --quiet, -q             only print the report when the run is blocked
  --verbose               show how the scan target and config were resolved
  --color / --no-color    force or disable ANSI color
  --help, -h              show this help
  --version, -v           show the osv-guard version

CONFIG
  Settings may live in osv-guard.json, .osv-guardrc.json, or an "osv-guard" key in
  package.json. Command-line flags win over the config file.

    { "failOn": "high", "ignore": ["GHSA-xxxx-xxxx-xxxx"], "ignoreUnfixed": true }

  Long-lived per-advisory suppressions are better kept in osv-scanner's own
  osv-scanner.toml, which osv-guard picks up automatically.

EXIT CODES
  0   scan passed (and the script exited 0)
  1   blocked by policy — the script was not run
  2   usage or configuration error
  3   the scan could not run (OSV unreachable, or osv-scanner missing/failed)
  *   otherwise, the script's own exit code

SETUP
  Guard a command:       "build": "osv-guard hardhat build"

  Guard another script:  "build": "osv-guard build:run",
                         "build:run": "hardhat build"

  A script that invokes osv-guard directly (e.g. "build": "osv-guard build")
  would run itself forever; osv-guard refuses that and says what to do instead.
`.trim();
