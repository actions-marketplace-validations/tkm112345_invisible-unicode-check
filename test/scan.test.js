'use strict';

const test = require('node:test');
const assert = require('node:assert');

const { scanLine, scanText, scanPath, parseDiff, globToRegExp, escapeInvisible } = require('../index.js');

// Payloads are built from code points so this file contains no invisible characters itself.
const RLO = String.fromCodePoint(0x202E);
const PDF = String.fromCodePoint(0x202C);
const ZWSP = String.fromCodePoint(0x200B);
const BOM = String.fromCodePoint(0xFEFF);
const TAG_A = String.fromCodePoint(0xE0061);
const VS = String.fromCodePoint(0xFE0F);
const PUA = String.fromCodePoint(0xE000);

const ids = (findings) => findings.map((f) => f.ruleId);

test('bidi override is critical and reported on unchanged lines', () => {
  // Both the override and its terminator are reported.
  const line = `if (isAdmin${RLO} ${PDF}) { grant(); }`;
  assert.deepStrictEqual(ids(scanLine('a.js', line, 3, false)), ['IUC001', 'IUC001']);
  assert.deepStrictEqual(ids(scanLine('a.js', line, 3, true)), ['IUC001', 'IUC001']);
});

test('tag characters are critical', () => {
  assert.deepStrictEqual(ids(scanLine('a.js', `const x = 1;${TAG_A}`, 1, false)), ['IUC002']);
});

test('private use area is critical', () => {
  assert.deepStrictEqual(ids(scanLine('a.js', `const icon = '${PUA}';`, 1, false)), ['IUC004']);
});

test('three variation selectors trigger the run rule, two do not', () => {
  assert.deepStrictEqual(ids(scanLine('a.js', `x${VS}${VS}${VS}`, 1, false)), ['IUC003']);
  assert.deepStrictEqual(ids(scanLine('a.js', `x${VS}${VS}`, 1, false)), []);
});

test('a lone emoji variation selector is not a finding', () => {
  assert.deepStrictEqual(ids(scanLine('a.js', `// warning ⚠${VS} here`, 1, true)), []);
});

test('zero-width space warns only on changed lines', () => {
  assert.deepStrictEqual(ids(scanLine('a.js', `const a${ZWSP} = 1;`, 1, true)), ['IUC005']);
  assert.deepStrictEqual(ids(scanLine('a.js', `const a${ZWSP} = 1;`, 1, false)), []);
});

test('a leading BOM is allowed, a BOM anywhere else is not', () => {
  assert.deepStrictEqual(ids(scanLine('a.js', `${BOM}const a = 1;`, 1, true)), []);
  assert.deepStrictEqual(ids(scanLine('a.js', `const a = ${BOM}1;`, 2, true)), ['IUC006']);
});

test('clean source produces no findings', () => {
  const text = ['const a = 1;', '// 日本語のコメントは問題ない', 'console.log("ok");'].join('\n');
  assert.deepStrictEqual(scanText('a.js', text, null), []);
});

test('scanText honours the changed-line set', () => {
  const text = [`const a${ZWSP} = 1;`, `const b${RLO} = 2;`].join('\n');
  // Only line 2 was touched: the warning on line 1 is suppressed, the critical is not.
  assert.deepStrictEqual(ids(scanText('a.js', text, new Set([2]))), ['IUC001']);
  assert.deepStrictEqual(ids(scanText('a.js', text, new Set([1, 2]))), ['IUC005', 'IUC001']);
});

test('a payload in the file path is caught', () => {
  assert.deepStrictEqual(ids(scanPath(`src/${RLO}gnp.js`)), ['IUC001']);
  assert.deepStrictEqual(ids(scanPath('src/index.js')), []);
});

test('findings carry a readable snippet', () => {
  const [finding] = scanLine('a.js', `x = "${RLO}"`, 1, true);
  assert.match(finding.snippet, /\\u\{202E\}/);
  assert.strictEqual(finding.message.startsWith('U+202E'), true);
});

test('escapeInvisible leaves ordinary text alone', () => {
  assert.strictEqual(escapeInvisible('const a = 1; // メモ'), 'const a = 1; // メモ');
});

test('parseDiff maps hunk headers to added line numbers', () => {
  const diff = [
    'diff --git a/foo.txt b/foo.txt',
    '--- a/foo.txt',
    '+++ b/foo.txt',
    '@@ -1,3 +1,4 @@ context',
    '+added',
    '@@ -10,2 +11,3 @@',
    '+another',
  ].join('\n');
  const result = parseDiff(diff);
  assert.deepStrictEqual([...result.get('foo.txt')].sort((a, b) => a - b), [1, 2, 3, 4, 11, 12, 13]);
});

test('parseDiff treats a missing count as one line', () => {
  const diff = ['--- a/bar.txt', '+++ b/bar.txt', '@@ -5 +5 @@'].join('\n');
  assert.deepStrictEqual([...parseDiff(diff).get('bar.txt')], [5]);
});

test('parseDiff ignores deletions', () => {
  const diff = ['--- a/gone.txt', '+++ /dev/null', '@@ -1,2 +0,0 @@'].join('\n');
  assert.strictEqual(parseDiff(diff).size, 0);
});

test('glob matching', () => {
  assert.strictEqual(globToRegExp('locales/**').test('locales/ar/app.json'), true);
  assert.strictEqual(globToRegExp('*.po').test('messages.po'), true);
  assert.strictEqual(globToRegExp('*.po').test('a/messages.po'), false);
  assert.strictEqual(globToRegExp('**/*.po').test('a/b/messages.po'), true);
});
