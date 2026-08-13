# Invisible Unicode Check

[![ci](https://github.com/tkm112345/invisible-unicode-check/actions/workflows/ci.yml/badge.svg)](https://github.com/tkm112345/invisible-unicode-check/actions/workflows/ci.yml)

A GitHub Action that detects invisible Unicode used to smuggle malicious code into source files — [GlassWorm](https://xtech.nikkei.com/atcl/nxt/column/18/00989/040100204/)-style payload encoding and [Trojan Source](https://trojansource.codes/) — and blocks the pull request from being merged.

**No npm packages.** It runs on the Node.js standard library alone, and this repository ships no `package.json`, so `npm install` has nothing to install. A tool that detects supply chain attacks should not have a supply chain of its own.

## Usage

```yaml
name: invisible-unicode

on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0        # required to diff against the base commit
      - uses: tkm112345/invisible-unicode-check@v1
```

### Making it actually block a merge

The action only fails the job. Blocking the merge button is a repository setting.

Go to **Settings → Rules → Rulesets → New branch ruleset**, target your default branch, and add `scan` (the job name) under **Require status checks to pass**.

> Do not add a `paths:` filter to `on.pull_request`. If the filter skips the job, the required status check stays pending forever and the pull request can never be merged.

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `base-sha` | resolved from the event | Commit to diff against. `pull_request.base.sha` for pull requests, `before` for pushes. |
| `exclude` | none | Glob patterns to skip, separated by newlines or commas. Supports `**`, `*` and `?`. |

```yaml
      - uses: tkm112345/invisible-unicode-check@v1
        with:
          exclude: |
            locales/**
            *.po
```

## Rules

### Critical — blocks the merge

| ID | Name | Detects |
| --- | --- | --- |
| IUC001 | bidi-control | U+202A–202E, U+2066–2069 — control characters that reorder rendered source |
| IUC002 | tag-character | U+E0000–E007F — used to carry invisible payloads |
| IUC003 | variation-selector-run | 3 or more variation selectors on one line — GlassWorm-style data encoding |
| IUC004 | private-use | U+E000–F8FF and the supplementary private use planes |
| IUC007 | line-separator | U+2028 / U+2029 — line terminators in JavaScript, so they can escape a string or a comment |
| IUC008 | control-char | Any Cc character other than tab, LF, FF and CR — including U+001B, which enables ANSI escape injection |
| IUC009 | noncharacter | U+FDD0–FDEF and every U+xFFFE / U+xFFFF — never valid in interchange |

### Warning — does not block

| ID | Name | Detects |
| --- | --- | --- |
| IUC005 | invisible-format | ZWSP, ZWNJ, ZWJ, soft hyphen, LRM/RLM and other invisible format characters |
| IUC006 | misplaced-bom | A byte-order mark anywhere other than the start of the file |
| IUC010 | deceptive-space | Blank-looking characters that are not U+0020: NBSP, U+2000–200A, U+3000, and U+2800 braille blank |
| IUC011 | combining-run | 5 or more combining marks in a row, which obscure the text underneath |
| IUC012 | mixed-script-word | A single word mixing Latin with Cyrillic or Greek, e.g. `payload` whose `a` is U+0430 CYRILLIC SMALL LETTER A |

## What gets scanned

Only files the pull request touches. Within those files:

- **critical rules run on every line**
- warning rules run **only on lines the pull request added or changed**

This catches a payload already sitting in a file the pull request touches, without drowning the author in findings from pre-existing emoji or i18n text.

If the base commit cannot be determined, or `git diff` fails, the action prints a warning and falls back to scanning **every tracked file, every line**. It never skips the check silently.

File paths are scanned too, since a bidi override can be planted in a filename.

## Design decisions

**Variation selectors are judged by density: 3 or more on one line.** A legitimate emoji uses exactly one (`⚠️` is U+26A0 U+FE0F), so one or two are ignored. A GlassWorm-style payload chains dozens on a single line, which this threshold separates cleanly. The tradeoff: **a payload split into runs of two across many lines will not be caught.** That is the inherent limit of a threshold.

**LRM/RLM (U+200E/200F) are not critical.** They appear legitimately in i18n text and are weak at rewriting how code looks on their own. Only the embedding, override and isolate controls block a merge.

**Warnings never block.** Zero-width spaces and stray BOMs produce false positives, and a check that blocks on those gets disabled by the team it was meant to protect.

**Mixed-script detection is word-level, not identifier-level.** Full [UTS #39](https://www.unicode.org/reports/tr39/) confusable analysis needs a tokenizer per language and a confusables table. Splitting a line into words and asking whether one word mixes Latin with Cyrillic or Greek catches the same homoglyph attack with a regex, at the cost of not distinguishing an identifier from a comment. It is therefore a warning, not a block.

## Limits

This action protects **pull requests coming into your repository**. It does not protect you from a compromised upstream dependency.

The real-world GlassWorm damage arrived through npm packages and VS Code extensions on Open VSX, and the same is true of the [keyv/cacheable compromise](https://socket.dev/blog/popular-npm-packages-in-the-keyv-and-cacheable-namespaces-compromised-in-active-supply-chain) — malicious files land in `node_modules` at install time, never passing through a pull request. Those payloads are also plain obfuscated JavaScript rather than invisible Unicode, so none of the rules above would fire even if `node_modules` were scanned. Defending against that requires separate controls: `npm ci --ignore-scripts`, pinned lockfiles, and review of dependency diffs.

## Development

```sh
node --test test/scan.test.js
```

The tests build their payloads with `String.fromCodePoint()`, so this repository contains no invisible characters of its own and passes its own scan.

[Pull request #1](https://github.com/tkm112345/invisible-unicode-check/pull/1) is kept open on purpose: it plants real payloads and demonstrates the action blocking the merge. It is never merged.

## License

MIT
