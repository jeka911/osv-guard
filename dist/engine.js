import { UsageError } from './config.js';
export function chooseEngine(input) {
    if (input.requested === 'osv-scanner') {
        return { engine: 'osv-scanner', reason: 'requested', warnings: [] };
    }
    // `--offline` means osv-scanner's local database. The built-in engine has no
    // equivalent: the npm slice of OSV alone is over 200 MB to mirror.
    if (input.offline) {
        if (input.explicit && input.requested === 'builtin') {
            throw new UsageError([
                '--offline needs the osv-scanner binary, which carries a local database.',
                'The built-in scanner queries https://api.osv.dev and cannot run offline.',
                '',
                'Drop --offline, or pass --scanner osv-scanner.',
            ].join('\n'));
        }
        return { engine: 'osv-scanner', reason: '--offline requires the binary', warnings: [] };
    }
    if (input.requested === 'auto') {
        return input.hasBinary()
            ? { engine: 'osv-scanner', reason: 'auto: binary available', warnings: [] }
            : { engine: 'builtin', reason: 'auto: no binary on PATH', warnings: [] };
    }
    // Nothing the built-in engine can read, but something osv-scanner could:
    // fall back rather than report a clean tree we never actually looked at.
    if (input.lockfiles.length === 0 && input.foreign.length > 0 && !input.explicit) {
        if (input.hasBinary()) {
            return {
                engine: 'osv-scanner',
                reason: `no Node lockfile, but ${describe(input.foreign)} present`,
                warnings: [],
            };
        }
    }
    return { engine: 'builtin', reason: 'default', warnings: builtinWarnings(input) };
}
/**
 * What the built-in engine is not looking at.
 *
 * Silence from a guard reads as "clean", so an unexamined Cargo.lock sitting
 * beside a scanned package-lock.json has to be said out loud. The scan itself
 * is still correct for what it did cover, which is why this warns rather than
 * fails.
 */
function builtinWarnings(input) {
    if (input.foreign.length === 0)
        return [];
    const ecosystems = [...new Set(input.foreign.map((m) => m.ecosystem))].sort();
    const sample = input.foreign.slice(0, 3).map((m) => m.file);
    const more = input.foreign.length - sample.length;
    return [
        `the built-in scanner reads Node lockfiles only — ${describe(input.foreign)} not checked`,
        `  ${sample.join(', ')}${more > 0 ? `, and ${more} more` : ''}`,
        `  install osv-scanner and pass --scanner osv-scanner to cover ${ecosystems.join(', ')}`,
    ];
}
/** "2 Go, 1 PyPI manifests" — enough to tell the user what they are missing. */
function describe(foreign) {
    const counts = new Map();
    for (const entry of foreign)
        counts.set(entry.ecosystem, (counts.get(entry.ecosystem) ?? 0) + 1);
    const parts = [...counts]
        .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
        .map(([ecosystem, count]) => `${count} ${ecosystem}`);
    return `${parts.join(', ')} manifest${foreign.length === 1 ? '' : 's'}`;
}
/** Warnings raised by the lockfiles the built-in engine could not read. */
export function unsupportedWarnings(unsupported) {
    return unsupported.map((entry) => `could not read ${entry.file}: ${entry.reason}`);
}
