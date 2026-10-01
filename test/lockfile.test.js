/**
 * Lockfile parsing — the one job the osv-scanner binary used to do for us.
 *
 * Every assertion here is about the same question: does the package list we
 * hand to OSV match what is actually installed? An entry missed here is a
 * vulnerability never queried, and a guard that reports clean because it did
 * not look is worse than no guard at all.
 */

import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  findForeignManifests,
  parseBunLock,
  parseNpmLock,
  parsePnpmLock,
  parseYarnLock,
  readLockfiles,
  splitNameVersion,
} from '../dist/lockfile.js';

function tempDir() {
  return mkdtempSync(path.join(tmpdir(), 'osv-guard-lock-'));
}

/** Packages as `name@version`, sorted, for readable assertions. */
function ids(packages) {
  return packages.map((p) => `${p.name}@${p.version}`).sort();
}

// --- name/version splitting -------------------------------------------------

test('a scoped name splits at the last @, not the first', () => {
  assert.deepEqual(splitNameVersion('@scope/pkg@1.2.3'), { name: '@scope/pkg', version: '1.2.3' });
  assert.deepEqual(splitNameVersion('lodash@4.17.15'), { name: 'lodash', version: '4.17.15' });
});

test('pnpm peer-dependency suffixes are not part of the version', () => {
  assert.deepEqual(splitNameVersion('@typescript-eslint/parser@8.0.0(typescript@5.5.4)'), {
    name: '@typescript-eslint/parser',
    version: '8.0.0',
  });
});

test('a bare name with no version is rejected rather than guessed at', () => {
  assert.equal(splitNameVersion('lodash'), null);
  assert.equal(splitNameVersion('@scope/pkg'), null);
});

// --- npm --------------------------------------------------------------------

test('npm lockfile v3: packages are keyed by install path', () => {
  const text = JSON.stringify({
    lockfileVersion: 3,
    packages: {
      '': { name: 'root', version: '1.0.0' },
      'node_modules/lodash': { version: '4.17.15' },
      'node_modules/@scope/pkg': { version: '2.0.0' },
      'node_modules/a/node_modules/lodash': { version: '3.10.1' },
    },
  });
  assert.deepEqual(ids(parseNpmLock(text, 'package-lock.json')), [
    '@scope/pkg@2.0.0',
    'lodash@3.10.1',
    'lodash@4.17.15',
  ]);
});

test('the project itself is not reported as one of its own dependencies', () => {
  const text = JSON.stringify({
    lockfileVersion: 3,
    packages: { '': { name: 'root', version: '1.0.0' }, 'node_modules/x': { version: '1.0.0' } },
  });
  const names = parseNpmLock(text, 'package-lock.json').map((p) => p.name);
  assert.deepEqual(names, ['x']);
});

test('workspace links are skipped: they resolve to local code, not a release', () => {
  const text = JSON.stringify({
    lockfileVersion: 3,
    packages: {
      '': { name: 'root' },
      'node_modules/my-pkg': { resolved: 'packages/my-pkg', link: true },
      'packages/my-pkg': { name: 'my-pkg', version: '0.0.0' },
      'node_modules/lodash': { version: '4.17.15' },
    },
  });
  const found = ids(parseNpmLock(text, 'package-lock.json'));
  // The `link` entry is a symlink into the repo, not an install. Querying OSV
  // for it would be asking about a package that was never published.
  assert.equal(found.filter((id) => id.startsWith('my-pkg@')).length, 1);
  assert.ok(found.includes('lodash@4.17.15'));
});

test('npm lockfile v1: the nested dependency tree is walked to the bottom', () => {
  const text = JSON.stringify({
    lockfileVersion: 1,
    dependencies: {
      a: { version: '1.0.0', dependencies: { b: { version: '2.0.0' } } },
      c: { version: '3.0.0' },
    },
  });
  assert.deepEqual(ids(parseNpmLock(text, 'package-lock.json')), ['a@1.0.0', 'b@2.0.0', 'c@3.0.0']);
});

test('a corrupt lockfile yields nothing rather than throwing mid-scan', () => {
  assert.deepEqual(parseNpmLock('{not json', 'package-lock.json'), []);
});

// --- pnpm -------------------------------------------------------------------

test('pnpm v9: packages block keys are name@version', () => {
  const text = [
    "lockfileVersion: '9.0'",
    '',
    'importers:',
    '',
    '  .:',
    '    dependencies:',
    '      lodash:',
    '        specifier: ^4.17.15',
    '        version: 4.17.15',
    '',
    'packages:',
    '',
    "  '@scope/pkg@2.0.0':",
    '    resolution: {integrity: sha512-aaa}',
    '',
    '  lodash@4.17.15:',
    '    resolution: {integrity: sha512-bbb}',
    '',
    'snapshots:',
    '',
    '  lodash@4.17.15: {}',
  ].join('\n');
  assert.deepEqual(ids(parsePnpmLock(text, 'pnpm-lock.yaml')), ['@scope/pkg@2.0.0', 'lodash@4.17.15']);
});

test('pnpm importers and snapshots are not mistaken for packages', () => {
  // `importers` lists workspace members with their own `version:` lines, and
  // `snapshots` repeats every package with peer suffixes. Reading either would
  // inflate the query list with entries that are not installed releases.
  const text = [
    'importers:',
    '  .:',
    '    dependencies:',
    '      hardhat:',
    '        specifier: ^3.0.0',
    '        version: 3.16.0',
    'packages:',
    '  hardhat@3.16.0:',
    '    resolution: {integrity: sha512-x}',
    'snapshots:',
    '  hardhat@3.16.0(typescript@5.9.3):',
    '    dependencies: {}',
  ].join('\n');
  assert.deepEqual(ids(parsePnpmLock(text, 'pnpm-lock.yaml')), ['hardhat@3.16.0']);
});

test('pnpm v5 and v6 key shapes are both understood', () => {
  const v5 = ['packages:', '  /lodash/4.17.15:', '    resolution: {integrity: sha512-x}'].join('\n');
  const v6 = ['packages:', '  /lodash@4.17.15:', '    resolution: {integrity: sha512-x}'].join('\n');
  assert.deepEqual(ids(parsePnpmLock(v5, 'pnpm-lock.yaml')), ['lodash@4.17.15']);
  assert.deepEqual(ids(parsePnpmLock(v6, 'pnpm-lock.yaml')), ['lodash@4.17.15']);
});

// --- yarn -------------------------------------------------------------------

test('yarn v1: the name comes from the spec, the version from the block', () => {
  const text = [
    '# yarn lockfile v1',
    '',
    'lodash@^4.17.15, lodash@^4.0.0:',
    '  version "4.17.15"',
    '  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.15.tgz"',
    '',
    '"@scope/pkg@^2.0.0":',
    '  version "2.0.0"',
  ].join('\n');
  assert.deepEqual(ids(parseYarnLock(text, 'yarn.lock')), ['@scope/pkg@2.0.0', 'lodash@4.17.15']);
});

test('yarn berry: the npm: protocol tag is not part of the name', () => {
  const text = [
    '__metadata:',
    '  version: 6',
    '',
    '"lodash@npm:^4.17.15":',
    '  version: 4.17.15',
    '  resolution: "lodash@npm:4.17.15"',
  ].join('\n');
  const parsed = parseYarnLock(text, 'yarn.lock');
  assert.deepEqual(ids(parsed), ['lodash@4.17.15']);
  assert.equal(parsed[0].name, 'lodash');
});

test('yarn workspace entries pointing at local code are skipped', () => {
  const text = ['"my-app@workspace:."', '  version: 0.0.0-use.local', '', '"lodash@npm:^4.0.0":', '  version: 4.17.15'].join('\n');
  assert.deepEqual(ids(parseYarnLock(text, 'yarn.lock')), ['lodash@4.17.15']);
});

// --- bun --------------------------------------------------------------------

test('bun.lock parses despite comments and trailing commas', () => {
  const text = [
    '{',
    '  // bun writes JSONC, which JSON.parse rejects outright',
    '  "lockfileVersion": 1,',
    '  "packages": {',
    '    "lodash": ["lodash@4.17.15", "", {}, "sha512-aaa"],',
    '    "@scope/pkg": ["@scope/pkg@2.0.0", "", {}, "sha512-bbb"],',
    '  },',
    '}',
  ].join('\n');
  assert.deepEqual(ids(parseBunLock(text, 'bun.lock')), ['@scope/pkg@2.0.0', 'lodash@4.17.15']);
});

test('a // inside a string is not treated as a comment', () => {
  const text = '{"packages":{"x":["x@1.0.0","https://example.com/x",{},"sha512-a"]}}';
  assert.deepEqual(ids(parseBunLock(text, 'bun.lock')), ['x@1.0.0']);
});

// --- whole-tree reads -------------------------------------------------------

test('a binary bun.lockb is reported as unsupported, not silently skipped', () => {
  const dir = tempDir();
  writeFileSync(path.join(dir, 'bun.lockb'), Buffer.from([0, 1, 2, 3]));
  const scan = readLockfiles(dir, ['bun.lockb']);
  assert.equal(scan.packages.length, 0);
  assert.equal(scan.unsupported.length, 1);
  assert.match(scan.unsupported[0].reason, /save-text-lockfile/);
});

test('a monorepo keeps the same package distinct per lockfile', () => {
  // Two workspaces pinning the same vulnerable version are two things to fix,
  // and the report labels each with its own source.
  const dir = tempDir();
  for (const pkg of ['app', 'cli']) {
    mkdirSync(path.join(dir, 'packages', pkg), { recursive: true });
    writeFileSync(
      path.join(dir, 'packages', pkg, 'package-lock.json'),
      JSON.stringify({
        lockfileVersion: 3,
        packages: { '': { name: pkg }, 'node_modules/lodash': { version: '4.17.15' } },
      }),
    );
  }
  const scan = readLockfiles(dir, ['packages/app/package-lock.json', 'packages/cli/package-lock.json']);
  assert.equal(scan.packages.length, 2);
  assert.deepEqual(
    scan.packages.map((p) => p.source).sort(),
    ['packages/app/package-lock.json', 'packages/cli/package-lock.json'],
  );
  assert.deepEqual(scan.parsed.length, 2);
});

test('the same package twice in one lockfile is queried once', () => {
  const dir = tempDir();
  writeFileSync(
    path.join(dir, 'package-lock.json'),
    JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 'root' },
        'node_modules/lodash': { version: '4.17.15' },
        'node_modules/a/node_modules/lodash': { version: '4.17.15' },
      },
    }),
  );
  assert.equal(readLockfiles(dir, ['package-lock.json']).packages.length, 1);
});

// --- foreign manifests ------------------------------------------------------

test('non-Node manifests are found and named by ecosystem', () => {
  const dir = tempDir();
  writeFileSync(path.join(dir, 'go.mod'), 'module example.com/x\n');
  mkdirSync(path.join(dir, 'api'), { recursive: true });
  writeFileSync(path.join(dir, 'api', 'requirements.txt'), 'flask==2.0.0\n');
  const found = findForeignManifests(dir);
  assert.deepEqual(found.map((f) => f.ecosystem).sort(), ['Go', 'PyPI']);
});

test('node_modules is never descended into when looking for manifests', () => {
  const dir = tempDir();
  mkdirSync(path.join(dir, 'node_modules', 'dep'), { recursive: true });
  writeFileSync(path.join(dir, 'node_modules', 'dep', 'Cargo.lock'), '');
  assert.deepEqual(findForeignManifests(dir), []);
});
