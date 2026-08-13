# Contributing

Thanks for taking a look. This is a small tool with a few hard rules, listed first because they are the ones that get pull requests rejected.

## Non-negotiable

**No npm dependencies. Ever.** This action detects supply chain attacks; it must not have a supply chain of its own. There is deliberately no `package.json` in this repository, so `npm install` has nothing to install. A pull request that adds `package.json`, a lockfile, a `node_modules` directory, or any `require()` of a package outside Node's standard library will be closed. This includes build tooling, bundlers, linters and test frameworks — `node --test` and `node:assert` cover the testing need.

**No literal invisible characters in this repository.** The scanner runs against its own source in CI (`self-check`), and it must stay clean. Test payloads are built with `String.fromCodePoint()`:

```js
const RLO = String.fromCodePoint(0x202E);
assert.deepStrictEqual(ids(scanLine('a.js', `if (isAdmin${RLO})`, 1, true)), ['IUC001']);
```

**Pull request #1 is never merged.** It plants real payloads on purpose and is kept open as a live demonstration that the action blocks a merge.

## Running the tests

```sh
node --test test/*.test.js
```

No install step, no build step. To run the scanner itself against a checkout:

```sh
node index.js                                     # scans every tracked file
env 'INPUT_BASE-SHA=<sha>' node index.js          # scans the diff against <sha>
env 'INPUT_IGNORE-RULES=locales/**:IUC010' node index.js
```

Action inputs arrive as `INPUT_<NAME>` environment variables with hyphens preserved, which is why `env 'NAME=value'` is needed rather than `NAME=value`.

## Adding or changing a rule

1. Add an entry to `RULES` in `index.js` with a stable id, a kebab-case name, a severity and a one-line description.
2. Single code points go in `classify()`. **Order matters** — the specific ranges are checked before the `Default_Ignorable_Code_Point` catch-all, so a new rule for characters already covered by IUC005 must be placed above it.
3. Anything that needs to look at a sequence rather than one code point goes in `scanSequences()` (see IUC003's variation selector run and IUC011's combining run).
4. Add tests to `test/rules.test.js`, including at least one case that must **not** fire.
5. Document it in the README rules table.

### Choosing a severity

This is the decision that matters most, and it is not about how bad the character is.

- **critical** blocks the merge and runs on **every line of every file the pull request touches**, including lines the author did not write. Reserve it for characters that have no legitimate reason to appear in source code. If a rule at this level fires on real-world code even occasionally, the team it protects will disable the whole check, and then it protects nothing.
- **warning** never blocks and runs **only on lines the pull request added or changed**. This is the right home for anything that appears legitimately in i18n resources, emoji, or non-Latin prose.

When in doubt, ship it as a warning. A warning that gets promoted later costs nothing; a critical rule that produces false positives costs the whole tool.

### Changing a threshold

Thresholds such as `VS_RUN_THRESHOLD` and `COMBINING_RUN_THRESHOLD` exist to separate an attack from legitimate text, and they were chosen against real examples — a single emoji uses one variation selector, a GlassWorm payload chains dozens. A pull request that moves one should say what real code it was checked against and what the false positive count was before and after.

## Pull requests

`main` is protected. Every change goes through a pull request, requires review from the code owner, and requires both CI jobs (`test` and `self-check`) to pass.

Keep the diff to the change being made. Please do not reformat surrounding code, and do not add abstractions for a single call site — this file is meant to stay readable end to end by one person in one sitting.

## Reporting a bypass

If you have found a way to smuggle invisible Unicode past this action, please do not open a public issue. Use **Security → Report a vulnerability** on this repository, which opens a private advisory visible only to the maintainer.

A payload split into runs of two variation selectors across many lines is a known limitation, not a new finding — it is documented in the README under Design decisions.
