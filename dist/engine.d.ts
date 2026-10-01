import { type ScanEngine } from './config.js';
import type { UnsupportedLockfile } from './lockfile.js';
/**
 * Pick the scan engine, and say what the choice costs.
 *
 * The built-in engine is the default because it makes osv-guard work with
 * nothing installed but Node — the same property the Claude Code plugin always
 * had, now extended to the CLI. It reads Node lockfiles only, so this is also
 * where a project that osv-scanner would cover better gets told so.
 */
export type ResolvedEngine = 'builtin' | 'osv-scanner';
export interface EngineInput {
    requested: ScanEngine;
    /** The user named an engine explicitly; never override that silently. */
    explicit: boolean;
    offline: boolean;
    /** Node lockfiles found under the scan root. */
    lockfiles: string[];
    foreign: {
        file: string;
        ecosystem: string;
    }[];
    /** An osv-scanner.toml is present: only the binary knows how to read it. */
    scannerToml?: boolean;
    /** Deferred so we only pay for probing the binary when the answer matters. */
    hasBinary: () => boolean;
}
export interface EngineChoice {
    engine: ResolvedEngine;
    /** Why, for `--verbose`. */
    reason: string;
    warnings: string[];
}
export declare function chooseEngine(input: EngineInput): EngineChoice;
/** Warnings raised by the lockfiles the built-in engine could not read. */
export declare function unsupportedWarnings(unsupported: UnsupportedLockfile[]): string[];
