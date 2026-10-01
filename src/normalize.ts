import { compareVersions } from './semver.js';
import { resolveSeverity } from './severity.js';
import type {
  Finding,
  OsvRawAffected,
  OsvRawGroup,
  OsvRawOutput,
  OsvRawVulnerability,
} from './types.js';

/**
 * Pick the fixed version that actually applies to `installed`.
 *
 * An advisory's `affected` list usually covers several release lines (e.g.
 * axios 0.x and 1.x separately), so taking the first `fixed` event would
 * routinely tell a 0.21.0 user to upgrade to 1.15.2. We find the range that
 * contains the installed version and report that range's fix; if the version
 * can't be ordered, we fall back to the lowest fix on offer rather than guess.
 */
export function resolveFixedVersion(
  affected: OsvRawAffected[] | undefined,
  packageName: string,
  installed: string,
): string | null {
  const allFixes: string[] = [];
  let matched: string | null = null;

  for (const entry of affected ?? []) {
    if (entry.package?.name && entry.package.name !== packageName) continue;
    for (const range of entry.ranges ?? []) {
      let introduced: string | null = null;
      let fixed: string | null = null;
      for (const event of range.events ?? []) {
        if (event.introduced !== undefined) {
          introduced = event.introduced;
          fixed = null;
        }
        if (event.fixed !== undefined) {
          fixed = event.fixed;
          if (fixed) allFixes.push(fixed);
          if (introduced !== null && inRange(installed, introduced, fixed)) {
            matched = pickLower(matched, fixed);
          }
          introduced = null;
        }
        if (event.last_affected !== undefined) introduced = null;
      }
    }
  }

  if (matched) return matched;
  // No range claimed the installed version (unorderable version strings, or an
  // ecosystem using non-semver events) — offer the lowest known fix instead.
  return allFixes.reduce<string | null>((acc, v) => pickLower(acc, v), null);
}

function inRange(installed: string, introduced: string, fixed: string): boolean {
  // "0" is OSV's canonical "from the beginning of time".
  if (introduced !== '0') {
    const afterIntro = compareVersions(installed, introduced);
    if (afterIntro === null || afterIntro < 0) return false;
  }
  const beforeFix = compareVersions(installed, fixed);
  if (beforeFix === null) return false;
  return beforeFix < 0;
}

function pickLower(current: string | null, candidate: string): string {
  if (current === null) return candidate;
  const cmp = compareVersions(candidate, current);
  return cmp !== null && cmp < 0 ? candidate : current;
}

/** Prefer a GHSA id as the display id; they have the best human summaries. */
function preferredId(ids: string[]): string {
  return ids.find((id) => id.startsWith('GHSA-')) ?? ids[0] ?? 'UNKNOWN';
}

function advisoryUrl(id: string): string {
  if (id.startsWith('GHSA-')) return `https://github.com/advisories/${id}`;
  return `https://osv.dev/vulnerability/${id}`;
}

function firstLine(text: string): string {
  const line = text.split('\n').find((l) => l.trim().length > 0) ?? '';
  return line.trim();
}

/**
 * Flatten osv-scanner's JSON into one `Finding` per group.
 *
 * Groups are the unit because osv-scanner emits a separate `vulnerabilities`
 * entry for each alias of the same flaw — lodash 4.17.15 reports 6
 * vulnerabilities but only 4 distinct issues. Counting raw vulnerabilities
 * would inflate every budget check.
 */
export function normalize(raw: OsvRawOutput): { findings: Finding[]; sources: string[] } {
  const findings: Finding[] = [];
  const sources = new Set<string>();

  for (const result of raw.results ?? []) {
    const source = result.source?.path ?? '';
    if (source) sources.add(source);

    for (const pkg of result.packages ?? []) {
      const packageName = pkg.package?.name ?? 'unknown';
      const packageVersion = pkg.package?.version ?? 'unknown';
      const ecosystem = pkg.package?.ecosystem ?? 'unknown';

      const byId = new Map<string, OsvRawVulnerability>();
      for (const vuln of pkg.vulnerabilities ?? []) byId.set(vuln.id, vuln);

      // A scanner build that omits `groups` still has to produce findings, so
      // synthesize one single-id group per vulnerability in that case.
      const groups: OsvRawGroup[] =
        pkg.groups && pkg.groups.length > 0
          ? pkg.groups
          : (pkg.vulnerabilities ?? []).map((v) => ({ ids: [v.id], aliases: v.aliases ?? [] }));

      for (const group of groups) {
        const ids = group.ids ?? [];
        const id = preferredId(ids);
        const primary = byId.get(id) ?? (ids.map((i) => byId.get(i)).find(Boolean) as
          | OsvRawVulnerability
          | undefined);

        // Withdrawn advisories are noise, not findings.
        if (primary?.withdrawn) continue;

        // Score across the whole group, not just its primary record: the GHSA
        // and the CVE describing one flaw carry separate vectors, and
        // osv-scanner's `max_severity` is the maximum of all of them.
        const groupVectors = ids.flatMap((memberId) => byId.get(memberId)?.severity ?? []);

        const { band, score, source: severitySource } = resolveSeverity(
          group.max_severity,
          primary?.database_specific?.severity,
          groupVectors.length > 0 ? groupVectors : primary?.severity,
        );

        const aliasSet = new Set<string>([...ids, ...(group.aliases ?? [])]);
        aliasSet.delete(id);

        findings.push({
          id,
          aliases: [...aliasSet].sort(),
          band,
          score,
          severitySource,
          packageName,
          packageVersion,
          ecosystem,
          summary: primary?.summary
            ? firstLine(primary.summary)
            : primary?.details
              ? firstLine(primary.details)
              : 'No summary published.',
          fixedVersion: resolveFixedVersion(primary?.affected, packageName, packageVersion),
          url: advisoryUrl(id),
          source,
        });
      }
    }
  }

  return { findings, sources: [...sources] };
}
