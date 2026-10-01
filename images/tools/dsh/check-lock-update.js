#!/usr/bin/env node
'use strict';

// Build-mode location freeze for the combined dsh + pnpm lock.
//
// Usage:
//   check-lock-update.js OLD_MANIFEST OLD_LOCK NEW_MANIFEST NEW_LOCK \
//                        DSH_VERSION PNPM_VERSION
//
// `OLD_*` are the committed files; `NEW_*` are what an explicit-slot
// preparation produced. DSH_VERSION/PNPM_VERSION are the requested slots
// (empty means "keep the committed pin"). The script exits 0 only when the
// update is exactly the one the ticket allows, and 1 (with the offending
// paths) otherwise.
//
// The rule is a *location* freeze, not inferred dependency ownership:
//
//   * a slot counts as changed only when its requested value is nonempty AND
//     differs from the committed manifest pin;
//   * for each changed root (node_modules/@deepseek-ai/dsh, node_modules/pnpm)
//     the allowed set A is that exact location plus any key beginning with
//     <location>/node_modules/;
//   * every key outside A (except "") must exist on BOTH sides with a
//     recursively canonical-JSON-identical record -- additions, deletions and
//     relocations outside A all fail, including shared/hoisted records;
//   * the top-level lock fields and the "" root record may differ only in the
//     changed slots' exact `dependencies` values;
//   * the manifest may differ only in the changed slots' exact `dependencies`
//     values;
//   * with no changed slot the manifest and lock must be byte-identical.
//
// Because A is a location rule, a compatible explicit pair is what must be
// found; if an override needs to move a frozen record, the build is rejected
// rather than silently refreshing the empty slot or a transitive tree.
//
// Plain Node built-ins only; no npm, no network. Invariants (lockfileVersion 3,
// exactly the two expected root dependencies, an integrity hash on every
// non-root record, safe location keys, the dsh-sandbox-local layout) are
// re-checked here as well, so the checker cannot be fooled by a lock that is
// internally inconsistent but freezes correctly.

const fs = require('fs');

const DSH = '@deepseek-ai/dsh';
const PNPM = 'pnpm';
const EXPECTED_DEPENDENCIES = [DSH, PNPM];
const DSH_LOCATION = 'node_modules/' + DSH;
const PNPM_LOCATION = 'node_modules/' + PNPM;
const SANDBOX_SUFFIX = '/@deepseek-ai/dsh-sandbox-local';
const SANDBOX_LOCATION = DSH_LOCATION + SANDBOX_SUFFIX;
const SANDBOX_ALLOWED = new RegExp(
  '^node_modules/(@deepseek-ai/dsh/node_modules/)?@deepseek-ai/dsh-sandbox-local$'
);

function fail(message) {
  process.stderr.write('check-lock-update: ' + message + '\n');
  process.exit(1);
}

function readFile(path, what) {
  try {
    return fs.readFileSync(path);
  } catch (error) {
    fail('cannot read ' + what + ' ' + path + ': ' + error.message);
  }
}

function readJson(path, what) {
  const text = readFile(path, what).toString('utf8');
  try {
    return JSON.parse(text);
  } catch (error) {
    fail(what + ' ' + path + ' is not valid JSON: ' + error.message);
  }
}

function hasOwn(object, key) {
  return Object.prototype.hasOwnProperty.call(object, key);
}

// Recursively canonical JSON: object keys sorted, array order preserved, and an
// absent key distinct from a present null (it simply does not appear).
function canon(value) {
  if (Array.isArray(value)) {
    return '[' + value.map(canon).join(',') + ']';
  }
  if (value !== null && typeof value === 'object') {
    return (
      '{' +
      Object.keys(value)
        .sort()
        .map((key) => JSON.stringify(key) + ':' + canon(value[key]))
        .join(',') +
      '}'
    );
  }
  return JSON.stringify(value);
}

function isSafeLocationKey(key) {
  if (key === '') {
    return true;
  }
  if (key.startsWith('/') || key.includes('..') || key.includes('\0')) {
    return false;
  }
  return key === 'node_modules' || key.startsWith('node_modules/');
}

function sortedKeys(object) {
  return Object.keys(object).sort();
}

function requireExactDependencies(manifest, what) {
  const names = sortedKeys(manifest.dependencies || {}).join(',');
  if (names !== EXPECTED_DEPENDENCIES.slice().sort().join(',')) {
    fail(
      what +
        ' must depend on exactly ' +
        EXPECTED_DEPENDENCIES.join(' and ') +
        ', not [' +
        names +
        ']'
    );
  }
}

function validateLock(manifest, lock, expectedDsh, expectedPnpm, what) {
  if (lock.lockfileVersion !== 3) {
    fail(what + ' lockfileVersion is ' + lock.lockfileVersion + ', expected 3');
  }
  const packages = lock.packages;
  if (!packages || typeof packages !== 'object' || Array.isArray(packages)) {
    fail(what + ' has no `packages` object');
  }
  if (!hasOwn(packages, '')) {
    fail(what + ' has no root (packages[""]) record');
  }
  requireExactDependencies(manifest, what + ' manifest');

  const root = packages[''];
  const rootDeps = root.dependencies || {};
  for (const name of EXPECTED_DEPENDENCIES) {
    if (rootDeps[name] !== manifest.dependencies[name]) {
      fail(
        what +
          ' root record dependency ' +
          name +
          ' is ' +
          JSON.stringify(rootDeps[name]) +
          ', manifest pins ' +
          JSON.stringify(manifest.dependencies[name])
      );
    }
  }

  for (const key of Object.keys(packages)) {
    if (!isSafeLocationKey(key)) {
      fail(what + ' has an unsafe location key ' + JSON.stringify(key));
    }
    const record = packages[key];
    if (!record || typeof record !== 'object' || Array.isArray(record)) {
      fail(what + ' location ' + JSON.stringify(key) + ' is not an object');
    }
    if (record.link !== undefined) {
      fail(what + ' location ' + JSON.stringify(key) + ' is a link record');
    }
    if (key !== '' && (typeof record.integrity !== 'string' || record.integrity === '')) {
      fail(what + ' location ' + JSON.stringify(key) + ' carries no integrity hash');
    }
  }
  if (manifest.workspaces !== undefined) {
    fail(what + ' manifest declares workspaces; a workspace lock is unsupported');
  }

  const dshRecord = packages[DSH_LOCATION];
  if (!dshRecord || dshRecord.version !== expectedDsh) {
    fail(
      what +
        ' installs dsh ' +
        JSON.stringify(dshRecord && dshRecord.version) +
        ', expected ' +
        JSON.stringify(expectedDsh)
    );
  }
  const pnpmRecord = packages[PNPM_LOCATION];
  if (!pnpmRecord || pnpmRecord.version !== expectedPnpm) {
    fail(
      what +
        ' installs pnpm ' +
        JSON.stringify(pnpmRecord && pnpmRecord.version) +
        ', expected ' +
      JSON.stringify(expectedPnpm)
    );
  }

  const sandbox = Object.keys(packages).filter(
    (key) => key === SANDBOX_LOCATION || key.endsWith(SANDBOX_SUFFIX)
  );
  if (sandbox.length === 0) {
    fail(what + ' has no dsh-sandbox-local location; dsh web would fail to resolve it');
  }
  for (const key of sandbox) {
    if (!SANDBOX_ALLOWED.test(key)) {
      fail(
        what +
          ' installs dsh-sandbox-local at ' +
          JSON.stringify(key) +
          ', which dsh\'s plugin loader cannot resolve'
      );
    }
  }
}

// Compare two records ignoring only the listed dependency names in their
// `dependencies` map -- the one field a changed slot is allowed to move.
function compareIgnoringSlots(label, oldManifest, newManifest, changedNames) {
  const left = JSON.parse(JSON.stringify(oldManifest));
  const right = JSON.parse(JSON.stringify(newManifest));
  const leftDeps = left.dependencies || {};
  const rightDeps = right.dependencies || {};
  for (const name of changedNames) {
    delete leftDeps[name];
    delete rightDeps[name];
  }
  left.dependencies = leftDeps;
  right.dependencies = rightDeps;
  if (canon(left) !== canon(right)) {
    fail(label + ' changed fields other than the selected slots\' dependencies');
  }
}

function main(argv) {
  if (argv.length !== 6) {
    fail(
      'usage: check-lock-update.js OLD_MANIFEST OLD_LOCK NEW_MANIFEST NEW_LOCK ' +
        'DSH_VERSION PNPM_VERSION'
    );
  }
  const [oldManifestPath, oldLockPath, newManifestPath, newLockPath, dshVersionArg, pnpmVersionArg] =
    argv;

  const oldManifest = readJson(oldManifestPath, 'old manifest');
  const oldLock = readJson(oldLockPath, 'old lock');
  const newManifest = readJson(newManifestPath, 'new manifest');
  const newLock = readJson(newLockPath, 'new lock');

  const committedDsh = oldManifest.dependencies[DSH];
  const committedPnpm = oldManifest.dependencies[PNPM];
  if (typeof committedDsh !== 'string' || typeof committedPnpm !== 'string') {
    fail('the committed manifest does not pin both dsh and pnpm exactly');
  }

  const effectiveDsh = dshVersionArg === '' ? committedDsh : dshVersionArg;
  const effectivePnpm = pnpmVersionArg === '' ? committedPnpm : pnpmVersionArg;

  const changedNames = [];
  if (dshVersionArg !== '' && dshVersionArg !== committedDsh) {
    changedNames.push(DSH);
  }
  if (pnpmVersionArg !== '' && pnpmVersionArg !== committedPnpm) {
    changedNames.push(PNPM);
  }

  validateLock(newManifest, newLock, effectiveDsh, effectivePnpm, 'new');

  if (changedNames.length === 0) {
    // Empty or explicitly-equal slots must reuse the committed bytes untouched.
    if (!readFile(oldManifestPath, 'old manifest').equals(readFile(newManifestPath, 'new manifest'))) {
      fail('no slot changed, but the manifest bytes are not identical to the committed ones');
    }
    if (!readFile(oldLockPath, 'old lock').equals(readFile(newLockPath, 'new lock'))) {
      fail('no slot changed, but the lock bytes are not identical to the committed ones');
    }
    process.stdout.write(
      'check-lock-update: dsh/pnpm unchanged; committed manifest and lock bytes preserved\n'
    );
    return 0;
  }

  // Top-level lock fields other than `packages` must be canonical-JSON-equal.
  for (const key of new Set([...Object.keys(oldLock), ...Object.keys(newLock)])) {
    if (key === 'packages') {
      continue;
    }
    if (!hasOwn(oldLock, key) || !hasOwn(newLock, key)) {
      fail('top-level lock field ' + JSON.stringify(key) + ' was added or removed');
    }
    if (canon(oldLock[key]) !== canon(newLock[key])) {
      fail('top-level lock field ' + JSON.stringify(key) + ' changed');
    }
  }

  const allowedLocations = changedNames.map((name) => 'node_modules/' + name);
  const inAllowed = (key) =>
    allowedLocations.some(
      (location) => key === location || key.startsWith(location + '/node_modules/')
    );

  const oldPackages = oldLock.packages;
  const newPackages = newLock.packages;
  const violations = [];
  for (const key of new Set([...Object.keys(oldPackages), ...Object.keys(newPackages)])) {
    if (key === '' || inAllowed(key)) {
      continue;
    }
    const inOld = hasOwn(oldPackages, key);
    const inNew = hasOwn(newPackages, key);
    if (!inOld || !inNew) {
      violations.push(key + (inOld ? ' (removed)' : ' (added)'));
      continue;
    }
    if (canon(oldPackages[key]) !== canon(newPackages[key])) {
      violations.push(key + ' (changed)');
    }
  }
  if (violations.length > 0) {
    fail(
      'changes outside the selected root prefixes ' +
        allowedLocations.map((l) => JSON.stringify(l)).join(', ') +
        ':\n  ' +
        violations.join('\n  ')
    );
  }

  compareIgnoringSlots('the lock root record (packages[""])', oldPackages[''], newPackages[''], changedNames);
  compareIgnoringSlots('the manifest', oldManifest, newManifest, changedNames);

  process.stdout.write(
    'check-lock-update: changed only ' +
      changedNames.map((n) => JSON.stringify(n)).join(', ') +
      ' and its permitted locations\n'
  );
  return 0;
}

if (require.main === module) {
  process.exit(main(process.argv.slice(2)));
}

module.exports = { canon, isSafeLocationKey };
