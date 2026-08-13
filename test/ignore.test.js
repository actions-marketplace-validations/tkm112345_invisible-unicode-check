'use strict';

const test = require('node:test');
const assert = require('node:assert');

const { parseIgnoreRules, isIgnored } = require('../index.js');

test('a single path and rule is parsed', () => {
  const { entries, problems } = parseIgnoreRules('locales/**:IUC012');
  assert.deepStrictEqual(problems, []);
  assert.strictEqual(entries.length, 1);
  assert.strictEqual(entries[0].glob, 'locales/**');
  assert.deepStrictEqual([...entries[0].ids], ['IUC012']);
});

test('several rules on one line, blank lines and comments', () => {
  const { entries, problems } = parseIgnoreRules(
    ['# i18n text legitimately uses these', 'locales/**:IUC012,IUC010', '', 'src/legacy.js:iuc005'].join('\n')
  );
  assert.deepStrictEqual(problems, []);
  assert.strictEqual(entries.length, 2);
  assert.deepStrictEqual([...entries[0].ids].sort(), ['IUC010', 'IUC012']);
  // Rule ids are case insensitive.
  assert.deepStrictEqual([...entries[1].ids], ['IUC005']);
});

test('an unknown rule id is reported rather than silently accepted', () => {
  const { entries, problems } = parseIgnoreRules('locales/**:IUC0012');
  assert.deepStrictEqual(entries, []);
  assert.strictEqual(problems.length, 1);
  assert.match(problems[0], /IUC0012.*not a known rule id/);
});

test('a line without a rule id is reported', () => {
  const { problems } = parseIgnoreRules('locales/**');
  assert.match(problems[0], /not '<glob>:<RULE_ID>'/);
});

test('a valid rule survives alongside an invalid one on the same line', () => {
  const { entries, problems } = parseIgnoreRules('locales/**:IUC012,NOPE');
  assert.deepStrictEqual([...entries[0].ids], ['IUC012']);
  assert.strictEqual(problems.length, 1);
});

test('suppression applies to the matching path only', () => {
  const { entries } = parseIgnoreRules('locales/**:IUC012');
  assert.strictEqual(isIgnored(entries, 'locales/ar/app.json', 'IUC012'), true);
  assert.strictEqual(isIgnored(entries, 'src/app.js', 'IUC012'), false);
});

test('suppression applies to the matching rule only', () => {
  const { entries } = parseIgnoreRules('locales/**:IUC012');
  assert.strictEqual(isIgnored(entries, 'locales/ar/app.json', 'IUC001'), false);
});

test('an exact file path works without wildcards', () => {
  const { entries } = parseIgnoreRules('src/vendor/thing.js:IUC005');
  assert.strictEqual(isIgnored(entries, 'src/vendor/thing.js', 'IUC005'), true);
  assert.strictEqual(isIgnored(entries, 'src/vendor/other.js', 'IUC005'), false);
});

test('no configuration suppresses nothing', () => {
  const { entries } = parseIgnoreRules('');
  assert.deepStrictEqual(entries, []);
  assert.strictEqual(isIgnored(entries, 'a.js', 'IUC001'), false);
});
