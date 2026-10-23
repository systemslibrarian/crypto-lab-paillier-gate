// Run only from a committed, clean source baseline. Every mutation is built,
// killed by its exact assertion owner, restored byte-for-byte, rebuilt, and
// tested green before the next mutation begins.
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
process.chdir(root);

const build = ['npm', ['run', 'build']];
const unit = (file, title) => ['npx', ['vitest', 'run', file, '-t', title]];
const browser = (title) => [
  'npx',
  [
    'playwright',
    'test',
    'e2e/exhibits.spec.ts',
    '--project=chromium',
    '--grep',
    title,
    '--workers=1',
    '--retries=0',
  ],
];

function run([command, args]) {
  return spawnSync(command, args, {
    cwd: root,
    encoding: 'utf8',
    env: { ...process.env, CI: '1' },
  });
}

function pass(command, label) {
  const result = run(command);
  if (result.status !== 0) {
    throw new Error(`${label}\n${result.stdout}\n${result.stderr}`);
  }
  return result;
}

function distHash() {
  const hash = createHash('sha256');
  const walk = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })
      .sort((a, b) => a.name.localeCompare(b.name))) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) walk(path);
      else {
        hash.update(path);
        hash.update(readFileSync(path));
      }
    }
  };
  walk('dist');
  return hash.digest('hex');
}

const cases = [
  [
    'aggregation result leaks learner private count',
    'src/aggregation.ts',
    '      id: `Hospital ${String.fromCharCode(65 + index)}`,\n      encryptedCount: ciphertext,',
    '      id: `Hospital ${String.fromCharCode(65 + index)}`,\n      privateCount,\n      encryptedCount: ciphertext,',
    unit('tests/aggregation.test.ts', 'produces an encrypted total that decrypts to the sum'),
  ],
  [
    'optional weights no longer default to one',
    'src/input.ts',
    "  if (value.trim() === '') {",
    "  if (value.trim() === '__never_blank__') {",
    unit('tests/input.test.ts', 'defaults every omitted weight to one'),
  ],
  [
    'decimal workload limit is bypassed',
    'src/input.ts',
    '  if (trimmed.length > maxDigits) {',
    '  if (false && trimmed.length > maxDigits) {',
    unit('tests/input.test.ts', 'rejects signs, non-decimal text, and oversized integers'),
  ],
  [
    'ballot MAC omits the voter identity',
    'src/ballots.ts',
    '  return encoder.encode(`${BALLOT_DOMAIN}\\0${voterId}\\0${ciphertext.toString()}`);',
    '  return encoder.encode(`${BALLOT_DOMAIN}\\0${ciphertext.toString()}`);',
    unit('tests/ballots.test.ts', 'binds the voter identity as well as the ciphertext'),
  ],
  [
    'ballot verification accepts any well-formed tag',
    'src/ballots.ts',
    '    return await crypto.subtle.verify(',
    '    return signature.length === 32 || await crypto.subtle.verify(',
    unit('tests/ballots.test.ts', 'treats malformed tags as invalid instead of comparing strings'),
  ],
  [
    'ballot MAC key becomes extractable',
    'src/ballots.ts',
    "  return crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);",
    "  return crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, true, ['sign', 'verify']);",
    unit('tests/ballots.test.ts', 'keeps the ballot-box MAC key non-extractable'),
  ],
  [
    'authenticated ballot box accepts a duplicate voter',
    'src/ballots.ts',
    '    const replayed = acceptedVoters.has(ballot.voterId);',
    '    const replayed = false && acceptedVoters.has(ballot.voterId);',
    unit('tests/ballots.test.ts', 'rejects a replayed voter identity under authentication'),
  ],
  [
    'stale key epoch regains authority',
    'src/session.ts',
    '  return expectedEpoch === currentEpoch && expectedN === currentN;',
    '  return (expectedEpoch === currentEpoch || true) && expectedN === currentN;',
    unit('tests/session.test.ts', 'accepts only the epoch and modulus that launched the operation'),
  ],
  [
    'modular wrap is labeled as the unreduced total',
    'src/main.ts',
    " The raw sum reached N, so this result wrapped and is not the unreduced total.",
    " The raw sum reached N, so this result is a match to the unreduced total.",
    browser('aggregation distinguishes a modular match from the unreduced total'),
  ],
  [
    'random ciphertext samples are called proof of semantic security',
    'src/main.ts',
    'it is not a proof of the\n            underlying decisional composite residuosity assumption.',
    'it is proof of the\n            underlying decisional composite residuosity assumption.',
    browser('the randomness exhibit does not claim that samples prove semantic security'),
  ],
];

const sourceFiles = [...new Set(cases.map((entry) => entry[1]))];
const dirty = spawnSync('git', ['diff', '--exit-code', '--', ...sourceFiles], {
  cwd: root,
  encoding: 'utf8',
});
if (dirty.status !== 0) {
  throw new Error('Commit the source baseline before mutation checks.');
}

pass(build, 'baseline build');
const baseline = distHash();
const evidence = [];
console.log('baseline: unmutated copy PASSES');
mkdirSync('mutation-logs', { recursive: true });

for (const [name, file, before, after, owner] of cases) {
  pass(owner, `${name}: baseline owner`);
  const original = readFileSync(file, 'utf8');
  if (original.split(before).length !== 2) {
    throw new Error(`${name}: expected exactly one mutation site`);
  }

  try {
    writeFileSync(file, original.replace(before, after));
    const sourceDiff = spawnSync('git', ['diff', '--', file], {
      cwd: root,
      encoding: 'utf8',
    }).stdout;
    if (!sourceDiff.trim()) throw new Error(`${name}: source diff is empty`);

    pass(build, `${name}: mutant build`);
    const mutant = distHash();
    if (mutant === baseline) throw new Error(`${name}: production artifact did not move`);

    const result = run(owner);
    writeFileSync(
      `mutation-logs/${name.replaceAll(' ', '-')}.log`,
      result.stdout + result.stderr,
    );
    const output = result.stdout + result.stderr;
    if (
      result.status === 0
      || !/AssertionError|ERR_ASSERTION|Error: expect|Expected values|expected/i.test(output)
    ) {
      throw new Error(`${name}: no assertion kill\n${output}`);
    }

    evidence.push({
      name,
      sourceDiff,
      baseline,
      mutant,
      namedTest: owner[1].includes('--grep')
        ? owner[1][owner[1].indexOf('--grep') + 1]
        : owner[1][owner[1].indexOf('-t') + 1],
      assertionFailure: true,
      retries: 0,
    });
  } finally {
    writeFileSync(file, original);
    pass(build, `${name}: restore build`);
    if (distHash() !== baseline) throw new Error(`${name}: restored artifact hash differs`);
    pass(owner, `${name}: restored owner`);
  }

  evidence.at(-1).restoredGreen = true;
  console.log(`${name}: killed; exact artifact restored; owning test green`);
}

writeFileSync('mutation-evidence.json', `${JSON.stringify(evidence, null, 2)}\n`);
console.log(`all ${cases.length} mutation(s) caught`);
