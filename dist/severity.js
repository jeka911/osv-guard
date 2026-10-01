/** CVSS v3.x qualitative rating scale, mapped onto our band names. */
export function scoreToBand(score) {
    if (!Number.isFinite(score) || score <= 0)
        return null;
    if (score >= 9.0)
        return 'critical';
    if (score >= 7.0)
        return 'high';
    if (score >= 4.0)
        return 'moderate';
    return 'low';
}
/** GHSA publishes MODERATE where CVSS says MEDIUM; accept both spellings. */
export function normalizeBandName(raw) {
    switch ((raw ?? '').trim().toLowerCase()) {
        case 'critical':
            return 'critical';
        case 'high':
            return 'high';
        case 'moderate':
        case 'medium':
            return 'moderate';
        case 'low':
            return 'low';
        default:
            return null;
    }
}
// --- CVSS v3.0/v3.1 base score ---
const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC = { L: 0.77, H: 0.44 };
const UI = { N: 0.85, R: 0.62 };
const CIA = { H: 0.56, L: 0.22, N: 0 };
const PR_UNCHANGED = { N: 0.85, L: 0.62, H: 0.27 };
const PR_CHANGED = { N: 0.85, L: 0.68, H: 0.5 };
/** Round up to one decimal, per the CVSS v3.1 spec's roundup(). */
function roundUp1(value) {
    const i = Math.round(value * 100000);
    if (i % 10000 === 0)
        return i / 100000;
    return (Math.floor(i / 10000) + 1) / 10;
}
/**
 * Compute a CVSS v3.0/v3.1 base score from a vector string. Returns null if the
 * vector is not v3 or is missing required metrics.
 *
 * CVSS v4.0 vectors are intentionally not scored here: v4 base scoring is a
 * 270-entry MacroVector lookup, and in practice osv-scanner already gives us
 * `max_severity`, with GitHub's `database_specific.severity` behind it. A v4
 * vector as the *only* signal is rare enough to be worth reporting honestly as
 * unknown rather than approximating.
 */
export function cvss3BaseScore(vector) {
    if (!/^CVSS:3\.[01]\//.test(vector))
        return null;
    const m = {};
    for (const part of vector.split('/').slice(1)) {
        const idx = part.indexOf(':');
        if (idx > 0)
            m[part.slice(0, idx)] = part.slice(idx + 1);
    }
    const scopeChanged = m.S === 'C';
    const av = AV[m.AV ?? ''];
    const ac = AC[m.AC ?? ''];
    const ui = UI[m.UI ?? ''];
    const pr = (scopeChanged ? PR_CHANGED : PR_UNCHANGED)[m.PR ?? ''];
    const c = CIA[m.C ?? ''];
    const i = CIA[m.I ?? ''];
    const a = CIA[m.A ?? ''];
    if ([av, ac, ui, pr, c, i, a].some((v) => v === undefined))
        return null;
    const iss = 1 - (1 - c) * (1 - i) * (1 - a);
    const impact = scopeChanged
        ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
        : 6.42 * iss;
    if (impact <= 0)
        return 0;
    const exploitability = 8.22 * av * ac * pr * ui;
    const base = scopeChanged
        ? Math.min(1.08 * (impact + exploitability), 10)
        : Math.min(impact + exploitability, 10);
    return roundUp1(base);
}
/**
 * Resolve a band from every signal available, most trustworthy first:
 *
 *   1. the group's `max_severity` (osv-scanner v2 computes this itself)
 *   2. GitHub's `database_specific.severity` string
 *   3. a CVSS v3 vector we score ourselves
 *
 * Anything left over is `unknown` — never silently treated as benign.
 */
export function resolveSeverity(maxSeverity, databaseSpecific, vectors) {
    if (maxSeverity !== undefined && maxSeverity !== '') {
        const score = Number(maxSeverity);
        const band = scoreToBand(score);
        if (band)
            return { band, score, source: 'max_severity' };
        // An explicit 0 is a real answer: scored, but not severe.
        if (Number.isFinite(score) && score === 0) {
            return { band: 'low', score: 0, source: 'max_severity' };
        }
    }
    const named = normalizeBandName(databaseSpecific);
    if (named) {
        // The named band is authoritative — GitHub's rating can deliberately differ
        // from the raw CVSS arithmetic — but a vector alongside it still carries a
        // number worth showing. Reporting the band without a score would hide it.
        return { band: named, score: maxVectorScore(vectors), source: 'database_specific' };
    }
    const score = maxVectorScore(vectors);
    if (score !== null) {
        const band = scoreToBand(score);
        if (band)
            return { band, score, source: 'cvss_v3' };
    }
    return { band: 'unknown', score: null, source: 'none' };
}
/**
 * The highest scorable CVSS v3 vector on offer.
 *
 * A single flaw is often scored more than once — the GHSA record and the CVE
 * it aliases can disagree, and both end up in the same group. osv-scanner's
 * `max_severity` is, as the name says, the maximum; taking the first vector
 * instead would under-report whenever the lower score happened to come first.
 */
function maxVectorScore(vectors) {
    let best = null;
    for (const entry of vectors ?? []) {
        if (!entry?.score)
            continue;
        const score = cvss3BaseScore(entry.score);
        if (score === null)
            continue;
        if (best === null || score > best)
            best = score;
    }
    return best;
}
