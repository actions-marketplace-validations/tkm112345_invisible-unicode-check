'use strict';

const test = require('node:test');
const assert = require('node:assert');

const { scanLine, escapeInvisible, classify } = require('../index.js');

const cp = (n) => String.fromCodePoint(n);
const ids = (findings) => findings.map((f) => f.ruleId);

test('line and paragraph separators are critical', () => {
  // U+2028 terminates a line in JavaScript, so it can escape a string or comment.
  assert.deepStrictEqual(ids(scanLine('a.js', `const s = "x${cp(0x2028)}";`, 1, false)), ['IUC007']);
  assert.deepStrictEqual(ids(scanLine('a.js', `const s = "x${cp(0x2029)}";`, 1, false)), ['IUC007']);
});

test('control characters are critical, ordinary whitespace is not', () => {
  assert.deepStrictEqual(ids(scanLine('a.js', `log("${cp(0x1b)}[31mred");`, 1, false)), ['IUC008']); // ANSI escape
  assert.deepStrictEqual(ids(scanLine('a.js', `const a = 1;${cp(0x7f)}`, 1, false)), ['IUC008']); // DEL
  assert.deepStrictEqual(ids(scanLine('a.js', `const a = 1;${cp(0x85)}`, 1, false)), ['IUC008']); // NEL
  assert.deepStrictEqual(ids(scanLine('a.js', `\tconst a = 1;${cp(0x0c)}`, 1, true)), []); // tab, form feed
});

test('noncharacters are critical', () => {
  assert.deepStrictEqual(ids(scanLine('a.js', `x${cp(0xfdd0)}`, 1, false)), ['IUC009']);
  assert.deepStrictEqual(ids(scanLine('a.js', `x${cp(0xfffe)}`, 1, false)), ['IUC009']);
  assert.deepStrictEqual(ids(scanLine('a.js', `x${cp(0x1ffff)}`, 1, false)), ['IUC009']);
});

test('blank-looking characters warn on changed lines', () => {
  assert.deepStrictEqual(ids(scanLine('a.js', `const a =${cp(0xa0)}1;`, 1, true)), ['IUC010']); // NBSP
  assert.deepStrictEqual(ids(scanLine('a.js', `const a =${cp(0x3000)}1;`, 1, true)), ['IUC010']); // ideographic
  assert.deepStrictEqual(ids(scanLine('a.js', `const a =${cp(0x2800)}1;`, 1, true)), ['IUC010']); // braille blank
  assert.deepStrictEqual(ids(scanLine('a.js', `const a =${cp(0xa0)}1;`, 1, false)), []);
});

test('a long run of combining marks warns once', () => {
  const zalgo = 'a' + cp(0x0301).repeat(6);
  assert.deepStrictEqual(ids(scanLine('a.js', zalgo, 1, true)), ['IUC011']);
  // Accented text with one or two marks is left alone.
  assert.deepStrictEqual(ids(scanLine('a.js', `const cafe${cp(0x0301)} = 1;`, 1, true)), []);
});

test('a word mixing Latin with Cyrillic is reported', () => {
  const cyrillicA = cp(0x0430);
  assert.deepStrictEqual(ids(scanLine('a.js', `const p${cyrillicA}yload = 1;`, 1, true)), ['IUC012']);
  // A comment written entirely in Russian mixes nothing and is fine.
  assert.deepStrictEqual(ids(scanLine('a.js', '// проверка', 1, true)), []);
  assert.deepStrictEqual(ids(scanLine('a.js', 'const payload = 1;', 1, true)), []);
});

test('classify leaves ordinary text alone', () => {
  for (const ch of 'const a = 1; // 日本語 メモ ✅') {
    assert.strictEqual(classify(ch.codePointAt(0), ch), null, `unexpected finding for ${ch}`);
  }
});

test('escapeInvisible reveals the newly covered characters', () => {
  assert.strictEqual(escapeInvisible(`a${cp(0xa0)}b`), 'a\\u{A0}b');
  assert.strictEqual(escapeInvisible(`a${cp(0x2028)}b`), 'a\\u{2028}b');
  assert.strictEqual(escapeInvisible(`a${cp(0x1b)}b`), 'a\\u{1B}b');
});
