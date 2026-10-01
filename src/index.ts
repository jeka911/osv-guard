export { normalize, resolveFixedVersion } from './normalize.js';
export { applyPolicy, countBands, type PolicyResult } from './policy.js';
export { render, renderJson, renderPretty, renderSummary, sortFindings } from './report.js';
export { runScan, buildArgs, detectScannerVersion, ScannerError } from './scanner.js';
export { findLockfiles, resolveProjectDir } from './resolve.js';
export { runTarget, planRun, runCwd, assertNotLooping, currentDepth, RecursionError, DEPTH_ENV } from './run.js';
export { detectPackageManager, buildRunArgs, pmExecutable, PACKAGE_MANAGERS, type PackageManager } from './pm.js';
export { resolveTarget, readScripts, invokesOsvGuard, binDir, TargetError, type RunTarget } from './target.js';
export { cvss3BaseScore, resolveSeverity, scoreToBand, normalizeBandName } from './severity.js';
export { compareVersions } from './semver.js';
export { cacheKey, readCache, writeCache } from './cache.js';
export {
  DEFAULTS,
  UsageError,
  loadConfigFile,
  mergeOptions,
  parseArgv,
  parseDuration,
  type Options,
  type Format,
  type ScanEngine,
} from './config.js';
export { VERSION } from './version.js';
export { evaluateCommand, parseHookInput, toHookOutput, isAgeExempt, type Decision, type HookOutcome, type TooNew } from './hook.js';
export { resolveReleaseTime, isTooNew, ageMs, formatAge, type ReleaseInfo } from './releaseage.js';
export { parseInstallCommand, parseSpec, isPackageArgument, isExactVersion, segments, type InstallSpec } from './installcmd.js';
export { queryPackage, queryAll, isMalicious, toScanOutput } from './osvapi.js';
export { runLocalScan, groupByAlias, type LocalScanOptions, type LocalScanResult } from './scanlocal.js';
export {
  readLockfiles,
  findForeignManifests,
  splitNameVersion,
  parseNpmLock,
  parsePnpmLock,
  parseYarnLock,
  parseBunLock,
  type LockPackage,
  type LockfileScan,
  type UnsupportedLockfile,
} from './lockfile.js';
export { chooseEngine, unsupportedWarnings, type EngineChoice, type ResolvedEngine } from './engine.js';
export * from './types.js';
