#!/usr/bin/env node
'use strict';

// Detect invisible / adversarial Unicode in a pull request and fail the check.
// No npm dependencies: Node standard library only.

const { execFileSync } = require('node:child_process');
const fs = require('node:fs');

const MAX_FILE_BYTES = 5 * 1024 * 1024;
const MAX_DIFF_BYTES = 50 * 1024 * 1024;
const VS_RUN_THRESHOLD = 3;
const COMBINING_RUN_THRESHOLD = 5;

const RULES = {
  IUC001: { name: 'bidi-control', severity: 'critical', desc: 'Bidirectional control character (Trojan Source)' },
  IUC002: { name: 'tag-character', severity: 'critical', desc: 'Tag character used to encode a hidden payload' },
  IUC003: { name: 'variation-selector-run', severity: 'critical', desc: 'Variation selector run (GlassWorm-style payload)' },
  IUC004: { name: 'private-use', severity: 'critical', desc: 'Private Use Area character' },
  IUC005: { name: 'invisible-format', severity: 'warning', desc: 'Invisible or zero-width format character' },
  IUC006: { name: 'misplaced-bom', severity: 'warning', desc: 'Byte-order mark outside the start of the file' },
  IUC007: { name: 'line-separator', severity: 'critical', desc: 'Line/paragraph separator (terminates a line in JavaScript)' },
  IUC008: { name: 'control-char', severity: 'critical', desc: 'Control character (ANSI escape injection, truncation)' },
  IUC009: { name: 'noncharacter', severity: 'critical', desc: 'Unicode noncharacter, never valid in interchange' },
  IUC010: { name: 'deceptive-space', severity: 'warning', desc: 'Blank-looking character that is not an ASCII space' },
  IUC011: { name: 'combining-run', severity: 'warning', desc: 'Long run of combining marks (obscures the text beneath)' },
  IUC012: { name: 'mixed-script-word', severity: 'warning', desc: 'One word mixes Latin with Cyrillic or Greek (homoglyph)' },
};

// Default_Ignorable_Code_Point covers ZWSP/ZWNJ/ZWJ/word joiner/soft hyphen and
// friends. It also covers the ranges handled by the rules above, so it is only
// consulted after those have been ruled out.
const IGNORABLE = /\p{Default_Ignorable_Code_Point}/u;
const COMBINING = /\p{Mn}|\p{Me}/u;
const LATIN = /[A-Za-z]/;
const CYRILLIC_OR_GREEK = /\p{Script=Cyrillic}|\p{Script=Greek}/u;
const WORD = /[\p{L}\p{N}_$]+/gu;

// Blank-looking characters that are not U+0020. Zero-width ones are already
// Default_Ignorable; these render as a space, or as nothing at all (U+2800).
const DECEPTIVE_SPACES = new Set([0x00a0, 0x1680, 0x202f, 0x205f, 0x3000, 0x2800]);

// U+202A-202E and U+2066-2069 can reorder rendered source. U+200E/200F/061C are
// weaker directional markers and fall through to IUC005 as warnings.
const isBidiControl = (cp) => (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069);
const isTag = (cp) => cp >= 0xe0000 && cp <= 0xe007f;
const isVariationSelector = (cp) => (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef);
const isPrivateUse = (cp) =>
  (cp >= 0xe000 && cp <= 0xf8ff) || (cp >= 0xf0000 && cp <= 0xffffd) || (cp >= 0x100000 && cp <= 0x10fffd);
const isNoncharacter = (cp) => (cp >= 0xfdd0 && cp <= 0xfdef) || (cp & 0xfffe) === 0xfffe;
// Tab, newline, form feed and carriage return are ordinary whitespace in source.
const isControl = (cp) =>
  (cp < 0x20 && cp !== 0x09 && cp !== 0x0a && cp !== 0x0c && cp !== 0x0d) || cp === 0x7f || (cp >= 0x80 && cp <= 0x9f);
const isDeceptiveSpace = (cp) => DECEPTIVE_SPACES.has(cp) || (cp >= 0x2000 && cp <= 0x200a);

/** Return the rule id for a single code point, or null if it is unremarkable. */
function classify(cp, ch) {
  if (isBidiControl(cp)) return 'IUC001';
  if (isTag(cp)) return 'IUC002';
  if (isPrivateUse(cp)) return 'IUC004';
  if (isVariationSelector(cp)) return null; // counted per line by IUC003
  if (cp === 0x2028 || cp === 0x2029) return 'IUC007';
  if (isControl(cp)) return 'IUC008';
  if (isNoncharacter(cp)) return 'IUC009';
  if (cp === 0xfeff) return 'IUC006';
  if (IGNORABLE.test(ch)) return 'IUC005';
  if (isDeceptiveSpace(cp)) return 'IUC010';
  return null;
}

const hex = (cp) => 'U+' + cp.toString(16).toUpperCase().padStart(4, '0');

/** Render text with every invisible code point spelled out, so it is readable in logs. */
function escapeInvisible(text) {
  let out = '';
  for (const ch of text) {
    const cp = ch.codePointAt(0);
    const hidden = isVariationSelector(cp) || classify(cp, ch) !== null;
    out += hidden ? `\\u{${cp.toString(16).toUpperCase()}}` : ch;
  }
  return out;
}

function snippet(line) {
  const s = escapeInvisible(line.trim());
  return s.length > 120 ? s.slice(0, 120) + '...' : s;
}

const finding = (ruleId, file, line, col, message, near) => ({
  ruleId,
  file,
  line,
  col,
  message,
  snippet: near,
});

/** Per-line checks that need to look at a sequence rather than a single code point. */
function scanSequences(file, line, lineNo) {
  const findings = [];
  let col = 0;
  let vsCount = 0;
  let vsCol = 0;
  let combining = 0;
  let combiningCol = 0;
  let reportedCombining = false;

  for (const ch of line) {
    col += 1;
    const cp = ch.codePointAt(0);

    if (isVariationSelector(cp)) {
      vsCount += 1;
      if (vsCount === 1) vsCol = col;
      combining = 0;
      continue;
    }
    if (COMBINING.test(ch)) {
      combining += 1;
      if (combining === 1) combiningCol = col;
      if (combining >= COMBINING_RUN_THRESHOLD && !reportedCombining) {
        reportedCombining = true;
        findings.push(
          finding('IUC011', file, lineNo, combiningCol, `${RULES.IUC011.desc}`, snippet(line))
        );
      }
    } else {
      combining = 0;
    }
  }

  if (vsCount >= VS_RUN_THRESHOLD) {
    findings.push(
      finding(
        'IUC003',
        file,
        lineNo,
        vsCol,
        `${vsCount} variation selectors on one line — ${RULES.IUC003.desc}`,
        snippet(line)
      )
    );
  }

  for (const m of line.matchAll(WORD)) {
    const word = m[0];
    if (LATIN.test(word) && CYRILLIC_OR_GREEK.test(word)) {
      findings.push(
        finding('IUC012', file, lineNo, m.index + 1, `'${word}' — ${RULES.IUC012.desc}`, snippet(line))
      );
    }
  }
  return findings;
}

/**
 * Scan one line. `changed` selects the depth of the check: critical rules run on
 * every line of every touched file, the rest only on lines the PR actually added.
 */
function scanLine(file, line, lineNo, changed) {
  const findings = [];
  let col = 0;

  for (const ch of line) {
    col += 1;
    const cp = ch.codePointAt(0);
    const ruleId = classify(cp, ch);
    if (!ruleId) continue;
    if (ruleId === 'IUC006' && lineNo === 1 && col === 1) continue; // legitimate leading BOM
    if (!changed && RULES[ruleId].severity !== 'critical') continue;
    findings.push(finding(ruleId, file, lineNo, col, `${hex(cp)} ${RULES[ruleId].desc}`, snippet(line)));
  }

  for (const f of scanSequences(file, line, lineNo)) {
    if (!changed && RULES[f.ruleId].severity !== 'critical') continue;
    findings.push(f);
  }
  return findings.sort((a, b) => a.col - b.col);
}

function scanText(file, text, changedLines) {
  const findings = [];
  const lines = text.split(/\r\n|\r|\n/);
  for (let i = 0; i < lines.length; i += 1) {
    const changed = changedLines === null || changedLines.has(i + 1);
    findings.push(...scanLine(file, lines[i], i + 1, changed));
  }
  return findings;
}

/** A path can itself carry a bidi override or a hidden payload. */
function scanPath(file) {
  return scanLine(file, file, 1, false).map((f) => ({
    ...f,
    message: `${f.message} (in the file path)`,
  }));
}

/** Parse `git diff -U0` output into { path -> Set(added line numbers) }. */
function parseDiff(text) {
  const result = new Map();
  let current = null;
  for (const line of text.split('\n')) {
    if (line.startsWith('+++ b/')) {
      current = line.slice(6);
      if (!result.has(current)) result.set(current, new Set());
    } else if (line.startsWith('+++ /dev/null')) {
      current = null;
    } else if (line.startsWith('@@') && current) {
      const m = /^@@ -\S+ \+(\d+)(?:,(\d+))?/.exec(line);
      if (!m) continue;
      const start = Number(m[1]);
      const count = m[2] === undefined ? 1 : Number(m[2]);
      const set = result.get(current);
      for (let n = start; n < start + count; n += 1) set.add(n);
    }
  }
  return result;
}

/** Minimal glob matcher: supports `**`, `*` and `?`. */
function globToRegExp(glob) {
  let re = '';
  for (let i = 0; i < glob.length; i += 1) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') {
        re += '.*';
        i += 1;
        if (glob[i + 1] === '/') i += 1;
      } else {
        re += '[^/]*';
      }
    } else if (c === '?') {
      re += '[^/]';
    } else {
      re += c.replace(/[.+^${}()|[\]\\]/, '\\$&');
    }
  }
  return new RegExp(`^${re}$`);
}

const matchesAny = (file, patterns) => patterns.some((p) => p.test(file));

/**
 * Parse the `ignore-rules` input: one `<glob>:<RULE_ID>[,<RULE_ID>...]` per line.
 * Returns the usable entries plus anything that could not be understood, so the
 * caller can report typos instead of silently ignoring them.
 */
function parseIgnoreRules(text) {
  const entries = [];
  const problems = [];
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;

    // Split on the last colon so a path may contain one.
    const sep = line.lastIndexOf(':');
    if (sep === -1) {
      problems.push(`'${line}' is not '<glob>:<RULE_ID>'`);
      continue;
    }
    const glob = line.slice(0, sep).trim();
    const ids = line
      .slice(sep + 1)
      .split(',')
      .map((s) => s.trim().toUpperCase())
      .filter(Boolean);

    if (!glob) {
      problems.push(`'${line}' has no path pattern`);
      continue;
    }
    const known = ids.filter((id) => {
      if (RULES[id]) return true;
      problems.push(`'${id}' is not a known rule id`);
      return false;
    });
    if (known.length > 0) entries.push({ glob, re: globToRegExp(glob), ids: new Set(known) });
  }
  return { entries, problems };
}

const isIgnored = (entries, file, ruleId) =>
  entries.some((entry) => entry.ids.has(ruleId) && entry.re.test(file));

// --- GitHub Actions plumbing ------------------------------------------------

const getInput = (name) => (process.env[`INPUT_${name.replace(/ /g, '_').toUpperCase()}`] || '').trim();

const escData = (s) => s.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
const escProp = (s) => escData(s).replace(/:/g, '%3A').replace(/,/g, '%2C');

function annotate(f) {
  const level = RULES[f.ruleId].severity === 'critical' ? 'error' : 'warning';
  const title = `${f.ruleId} ${RULES[f.ruleId].name}`;
  const props = `file=${escProp(f.file)},line=${f.line},col=${f.col},title=${escProp(title)}`;
  console.log(`::${level} ${props}::${escData(f.message)}`);
}

function git(args) {
  return execFileSync('git', args, { encoding: 'utf8', maxBuffer: MAX_DIFF_BYTES });
}

/** Resolve the commit to diff against. Returns '' when it cannot be determined. */
function resolveBaseSha() {
  const explicit = getInput('base-sha');
  if (explicit) return explicit;
  const eventPath = process.env.GITHUB_EVENT_PATH;
  if (!eventPath || !fs.existsSync(eventPath)) return '';
  let event;
  try {
    event = JSON.parse(fs.readFileSync(eventPath, 'utf8'));
  } catch {
    return '';
  }
  if (event.pull_request && event.pull_request.base && event.pull_request.base.sha) {
    return event.pull_request.base.sha;
  }
  if (typeof event.before === 'string' && !/^0+$/.test(event.before)) return event.before;
  return '';
}

function collectTargets(baseSha) {
  // Reject anything that is not a plain SHA so it cannot be read as a git flag.
  if (baseSha && !/^[0-9a-fA-F]+$/.test(baseSha)) {
    console.log(`::warning::ignoring malformed base SHA '${baseSha}'`);
    baseSha = '';
  }
  if (baseSha) {
    try {
      const diff = git(['-c', 'core.quotepath=false', 'diff', '-U0', '--diff-filter=AMR', baseSha, 'HEAD']);
      return { targets: parseDiff(diff), diffed: true };
    } catch (err) {
      console.log(`::warning::git diff failed (${err.message.split('\n')[0]}); scanning all tracked files`);
    }
  } else {
    console.log('::warning::no base commit available; scanning all tracked files');
  }
  // Fall back loudly rather than silently checking nothing.
  let files;
  try {
    files = git(['-c', 'core.quotepath=false', 'ls-files']).split('\n').filter(Boolean);
  } catch (err) {
    // Never pass by accident: if we cannot even list files, fail the check.
    console.log(`::error::cannot list files (${err.message.split('\n')[0]})`);
    process.exit(1);
  }
  return { targets: new Map(files.map((f) => [f, null])), diffed: false };
}

function writeSummary(findings) {
  const file = process.env.GITHUB_STEP_SUMMARY;
  if (!file) return;
  const lines = ['# Invisible Unicode Check', ''];
  if (findings.length === 0) {
    lines.push('No adversarial Unicode found.');
  } else {
    lines.push('| Severity | Rule | Location | Detail |', '| --- | --- | --- | --- |');
    for (const f of findings) {
      const rule = RULES[f.ruleId];
      lines.push(
        `| ${rule.severity} | ${f.ruleId} ${rule.name} | \`${f.file}:${f.line}:${f.col}\` | ${f.message} |`
      );
    }
  }
  fs.appendFileSync(file, lines.join('\n') + '\n');
}

function main() {
  const excludes = getInput('exclude')
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter(Boolean)
    .map(globToRegExp);

  const { entries: ignoreRules, problems } = parseIgnoreRules(getInput('ignore-rules'));
  for (const problem of problems) console.log(`::warning::ignore-rules: ${problem}`);
  for (const entry of ignoreRules) {
    // Suppressing a blocking rule is allowed, but it must never be silent.
    const suppressed = [...entry.ids].filter((id) => RULES[id].severity === 'critical');
    if (suppressed.length > 0) {
      console.log(`::warning::ignore-rules disables blocking rule(s) ${suppressed.join(', ')} for '${entry.glob}'`);
    }
  }

  const { targets } = collectTargets(resolveBaseSha());
  const collected = [];

  for (const [file, changedLines] of targets) {
    if (matchesAny(file, excludes)) continue;
    collected.push(...scanPath(file));

    let buf;
    try {
      buf = fs.readFileSync(file);
    } catch {
      continue; // deleted or unreadable in this checkout
    }
    if (buf.length > MAX_FILE_BYTES) {
      console.log(`::warning file=${escProp(file)}::skipped, larger than ${MAX_FILE_BYTES} bytes`);
      continue;
    }
    if (buf.includes(0)) continue; // binary

    collected.push(...scanText(file, buf.toString('utf8'), changedLines));
  }

  const findings = collected.filter((f) => !isIgnored(ignoreRules, f.file, f.ruleId));
  const suppressed = collected.length - findings.length;

  findings.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.col - b.col);
  for (const f of findings) annotate(f);

  const critical = findings.filter((f) => RULES[f.ruleId].severity === 'critical');
  for (const f of critical) {
    console.log(`  ${f.file}:${f.line}:${f.col}  ${f.ruleId}  ${f.message}`);
    console.log(`    near: ${f.snippet}`);
  }
  writeSummary(findings);

  const note = suppressed > 0 ? `, ${suppressed} suppressed by ignore-rules` : '';
  console.log(
    `\nScanned ${targets.size} file(s): ${critical.length} critical, ${findings.length - critical.length} warning(s)${note}.`
  );
  if (critical.length > 0) {
    console.log('::error::Invisible Unicode detected. This pull request must not be merged as-is.');
    process.exitCode = 1;
  }
}

module.exports = {
  scanLine,
  scanText,
  scanPath,
  parseDiff,
  globToRegExp,
  parseIgnoreRules,
  isIgnored,
  escapeInvisible,
  classify,
  RULES,
};

if (require.main === module) main();
