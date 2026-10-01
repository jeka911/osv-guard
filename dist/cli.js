#!/usr/bin/env node
import { existsSync } from 'node:fs';
import { cacheKey, readCache, writeCache } from './cache.js';
import { createColors } from './colors.js';
import { UsageError, loadConfigFile, mergeOptions, parseArgv } from './config.js';
import { HELP } from './help.js';
import { applyPolicy } from './policy.js';
import { chooseEngine, unsupportedWarnings } from './engine.js';
import { findForeignManifests } from './lockfile.js';
import { findLockfiles, resolveProjectDir } from './resolve.js';
import { render } from './report.js';
import { assertNotLooping, planRun, runCwd, runTarget, RecursionError } from './run.js';
import { ScannerError, buildArgs, detectScannerVersion, runScan } from './scanner.js';
import { runLocalScan } from './scanlocal.js';
import { detectPackageManager } from './pm.js';
import { TargetError, resolveTarget } from './target.js';
import { VERSION } from './version.js';
import { evaluateCommand, parseHookInput, toHookOutput } from './hook.js';
const EXIT_BLOCKED = 1;
const EXIT_USAGE = 2;
const EXIT_SCANNER = 3;
async function main(argv) {
    const parsed = parseArgv(argv);
    const invokedFrom = process.cwd();
    if (parsed.command === 'help') {
        process.stdout.write(`${HELP}\n`);
        return argv.length === 0 ? EXIT_USAGE : 0;
    }
    if (parsed.command === 'version') {
        process.stdout.write(`${VERSION}\n`);
        return 0;
    }
    if (parsed.command === 'hook') {
        return runHook(parsed.cliOptions);
    }
    // The config file lives with the package being scanned, so the scan target
    // has to be resolved before the config can be read — and again afterwards in
    // case the config itself sets `dir`.
    const initial = resolveProjectDir(parsed.cliOptions.dir, process.env, process.cwd());
    const { config, path: configPath } = loadConfigFile(initial.dir);
    const options = mergeOptions(config, parsed.cliOptions);
    const resolved = parsed.cliOptions.dir
        ? initial
        : resolveProjectDir(options.dir, process.env, process.cwd());
    const dir = resolved.dir;
    const colors = createColors(options.color);
    if (options.verbose) {
        warn(colors.gray(`osv-guard: scan target ${dir} (via ${resolved.via})`));
        warn(colors.gray(`osv-guard: config ${configPath ?? '(defaults only)'}`));
    }
    if (!existsSync(dir)) {
        throw new UsageError(`directory does not exist: ${dir}`);
    }
    // Resolve what we are guarding before scanning: a typo'd script name or a
    // self-invoking script should fail immediately, not after a slow scan.
    let target = null;
    const pm = detectPackageManager(dir, options.packageManager, process.env);
    if (parsed.command === 'run') {
        if (!parsed.script) {
            throw new UsageError('nothing to run — try `osv-guard <script>` or `osv-guard report`');
        }
        assertNotLooping(process.env);
        target = resolveTarget(dir, parsed.script, { forceCommand: parsed.forceCommand });
        if (options.verbose) {
            const run = { target, args: parsed.scriptArgs, dir, cwd: invokedFrom, pm: pm.pm };
            const plan = planRun(run);
            warn(colors.gray(`osv-guard: package manager ${pm.pm} (via ${pm.via})`));
            warn(colors.gray(`osv-guard: ${target.kind} target -> ${plan.command} ${plan.argv.join(' ')}`));
            warn(colors.gray(`osv-guard: running in ${runCwd(run)}`));
        }
    }
    const lockfiles = findLockfiles(dir);
    const foreign = findForeignManifests(dir);
    // Which engine runs decides what counts as "nothing to scan": osv-scanner
    // would happily resolve a Cargo.lock the built-in engine cannot read.
    const choice = chooseEngine({
        requested: options.scanner,
        explicit: parsed.cliOptions.scanner !== undefined || config.scanner !== undefined,
        offline: options.offline,
        lockfiles,
        foreign,
        hasBinary: () => detectScannerVersion(options.scannerBin) !== null,
    });
    if (options.verbose) {
        warn(colors.gray(`osv-guard: engine ${choice.engine} (${choice.reason})`));
    }
    // In quiet mode a guarded script would otherwise carry three lines of
    // preamble on every run. The headline still goes out — silence from a guard
    // reads as "clean", and an unchecked ecosystem is not that.
    emitWarnings(choice.warnings, options.quiet, colors);
    const nothingToScan = choice.engine === 'builtin' ? lockfiles.length === 0 : lockfiles.length === 0 && foreign.length === 0;
    if (nothingToScan && !options.allowNoLockfile) {
        throw new UsageError([
            `no lockfile found in ${dir}`,
            '',
            'Without a lockfile there is nothing to resolve, and an empty result',
            'would look identical to a clean one. Run `npm install` first, or pass',
            '--allow-no-lockfile if you accept an unchecked run.',
        ].join('\n'));
    }
    const scanOptions = {
        dir,
        scannerBin: options.scannerBin,
        offline: options.offline,
        allVulns: options.allVulns,
    };
    let scan = null;
    const key = options.cache
        ? cacheKey({
            dir,
            lockfiles,
            scannerVersion: null,
            scanFlags: [choice.engine, ...buildArgs(scanOptions).filter((a) => a !== dir)],
        })
        : null;
    if (key)
        scan = readCache(dir, key, options.cacheTtlMs);
    if (!scan) {
        if (choice.engine === 'builtin') {
            const local = await runLocalScan({ dir, lockfiles });
            emitWarnings(unsupportedWarnings(local.lockfileScan.unsupported), false, colors);
            if (options.verbose) {
                warn(colors.gray(`osv-guard: queried OSV for ${local.packagesScanned} packages`));
            }
            scan = local;
        }
        else {
            scan = await runScan(scanOptions);
        }
        if (key)
            writeCache(dir, key, scan);
    }
    const policy = applyPolicy(scan.findings, options);
    const ctx = { scan, policy, options, dir, lockfiles };
    // In quiet mode a passing scan says nothing, so guarding a script does not
    // bury its own output under a report every single run.
    const shouldPrint = !options.quiet || policy.blocked || options.format === 'json';
    if (shouldPrint) {
        const { text, stream } = render(ctx);
        (stream === 'stdout' ? process.stdout : process.stderr).write(`${text}\n`);
    }
    if (policy.blocked) {
        if (target && !options.quiet && options.format !== 'json') {
            const plan = planRun({ target, args: parsed.scriptArgs, dir, cwd: invokedFrom, pm: pm.pm });
            const shown = target.kind === 'script'
                ? `${pm.pm} ${plan.argv.join(' ')}`
                : [target.name, ...parsed.scriptArgs].join(' ');
            warn(colors.gray(`  \`${shown}\` was not started.`));
            warn('');
        }
        return EXIT_BLOCKED;
    }
    if (parsed.command === 'report' || !target)
        return 0;
    const { code } = await runTarget({ target, args: parsed.scriptArgs, dir, cwd: invokedFrom, pm: pm.pm });
    return code;
}
/**
 * Claude Code PreToolUse hook: read the tool call on stdin, decide, print the
 * decision as JSON.
 *
 * It always exits 0 — the verdict travels in the JSON, and a non-zero exit
 * would read as "the hook is broken" rather than "this install is dangerous".
 * Anything unexpected (bad input, no network) allows rather than blocks, so a
 * failure here can never wedge the user's session.
 */
async function runHook(cliOptions) {
    let raw = '';
    for await (const chunk of process.stdin)
        raw += chunk;
    const input = parseHookInput(raw);
    const command = input?.tool_input?.command;
    if (!input || input.tool_name !== 'Bash' || !command)
        return 0;
    const dir = input.cwd ?? process.cwd();
    try {
        const outcome = await evaluateCommand(command, dir, cliOptions);
        if (outcome.decision === 'allow')
            return 0;
        process.stderr.write(`${outcome.reason}\n`);
        process.stdout.write(`${toHookOutput(outcome)}\n`);
    }
    catch {
        // Never let a hook failure block the user.
        return 0;
    }
    return 0;
}
/** Detail lines are dropped in quiet mode; the first line never is. */
function emitWarnings(lines, quiet, colors) {
    for (const line of quiet ? lines.slice(0, 1) : lines) {
        warn(colors.yellow(`osv-guard: ${line}`));
    }
}
function warn(message) {
    process.stderr.write(`${message}\n`);
}
const colors = createColors(undefined);
try {
    process.exitCode = await main(process.argv.slice(2));
}
catch (error) {
    if (error instanceof UsageError) {
        warn(`${colors.red('osv-guard:')} ${error.message}`);
        warn(colors.gray('Run `osv-guard --help` for usage.'));
        process.exitCode = EXIT_USAGE;
    }
    else if (error instanceof TargetError) {
        warn(`${colors.red('osv-guard:')} ${error.message}`);
        if (error.hint)
            warn(`\n${error.hint}`);
        process.exitCode = EXIT_USAGE;
    }
    else if (error instanceof RecursionError) {
        warn(`${colors.red('osv-guard:')} ${error.message}`);
        process.exitCode = EXIT_USAGE;
    }
    else if (error instanceof ScannerError) {
        warn(`${colors.red('osv-guard:')} ${error.message}`);
        if (error.hint)
            warn(`\n${error.hint}`);
        process.exitCode = EXIT_SCANNER;
    }
    else {
        warn(`${colors.red('osv-guard:')} unexpected error`);
        warn(String(error?.stack ?? error));
        process.exitCode = EXIT_SCANNER;
    }
}
