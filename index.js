#!/usr/bin/env node
'use strict';

// Detect invisible / adversarial Unicode in a pull request and fail the check.
// No npm dependencies: Node standard library only.

const { execFileSync } = require('node:child_process');
const fs = require('node:fs');

const MAX_FILE_BYTES = 5 * 1024 * 1024;
const MAX_DIFF_BYTES = 50 * 1024 * 1024;
const VS_RUN_THRESHOLD = 3;

const RULES = {
  IUC001: { name: 'bidi-control', severity: 'critical', desc: 'Bidirectional control character (Trojan Source)' },
  IUC002: { name: 'tag-character', severity: 'critical', desc: 'Tag character used to encode a hidden payload' },
  IUC003: { name: 'variation-selector-run', severity: 'critical', desc: 'Variation selector run (GlassWorm-style payload)' },
  IUC004: { name: 'private-use', severity: 'critical', desc: 'Private Use Area character' },
  IUC005: { name: 'invisible-format', severity: 'warning', desc: 'Invisible or zero-width format character' },
  IUC006: { name: 'misplaced-bom', severity: 'warning', desc: 'Byte-order mark outside the start of the file' },
};

// Default_Ignorable_Code_Point covers ZWSP/ZWNJ/ZWJ/word joiner/soft hyphen and
// friends. It also covers the ranges handled by the rules above, so it is only
// consulted after those have been ruled out.
const IGNORABLE = /\p{Default_Ignorable_Code_Point}/u;

// U+202A-202E and U+2066-2069 can reorder rendered source. U+200E/200F/061C are
// weaker directional markers and fall through to IUC005 as warnings.
const isBidiControl = (cp) => (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069);
const isTag = (cp) => cp >= 0xe0000 && cp <= 0xe007f;
const isVariationSelector = (cp) => (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef);
const isPrivateUse = (cp) =>
  (cp >= 0xe000 && cp <= 0xf8ff) || (cp >= 0xf0000 && cp <= 0xffffd) || (cp >= 0x100000 && cp <= 0x10fffd);

/** Return the rule id for a single code point, or null if it is unremarkable. */
function classify(cp, ch) {
  if (isBidiControl(cp)) return 'IUC001';
  if (isTag(cp)) return 'IUC002';
  if (isPrivateUse(cp)) return 'IUC004';
  if (isVariationSelector(cp)) return null; // counted per line by IUC003
  if (cp === 0xfeff) return 'IUC006';
  if (IGNORABLE.test(ch)) return 'IUC005';
  return null;
}

const hex = (cp) => 'U+' + cp.toString(16).toUpperCase().padStart(4, '0');

/** Render text with every invisible code point spelled out, so it is readable in logs. */
function escapeInvisible(text) {
  let out = '';
  for (const ch of text) {
    const cp = ch.codePointAt(0);
    const hidden =
      isBidiControl(cp) || isTag(cp) || isPrivateUse(cp) || isVariationSelector(cp) || IGNORABLE.test(ch);
    out += hidden || (cp < 0x20 && cp !== 0x09) ? `\\u{${cp.toString(16).toUpperCase()}}` : ch;
  }
  return out;
}

function snippet(line) {
  const s = escapeInvisible(line.trim());
  return s.length > 120 ? s.slice(0, 120) + '...' : s;
}

/**
 * Scan one line. `changed` selects the depth of the check: critical rules run on
 * every line of every touched file, the rest only on lines the PR actually added.
 */
function scanLine(file, line, lineNo, changed) {
  const findings = [];
  let col = 0;
  let vsCount = 0;
  let vsCol = 0;

  for (const ch of line) {
    col += 1;
    const cp = ch.codePointAt(0);

    if (isVariationSelector(cp)) {
      vsCount += 1;
      if (vsCount === 1) vsCol = col;
      continue;
    }
    const ruleId = classify(cp, ch);
    if (!ruleId) continue;
    if (ruleId === 'IUC006' && lineNo === 1 && col === 1) continue; // legitimate leading BOM
    if (!changed && RULES[ruleId].severity !== 'critical') continue;

    findings.push({
      ruleId,
      file,
      line: lineNo,
      col,
      message: `${hex(cp)} ${RULES[ruleId].desc}`,
      snippet: snippet(line),
    });
  }

  if (vsCount >= VS_RUN_THRESHOLD) {
    findings.push({
      ruleId: 'IUC003',
      file,
      line: lineNo,
      col: vsCol,
      message: `${vsCount} variation selectors on one line — ${RULES.IUC003.desc}`,
      snippet: snippet(line),
    });
  }
  return findings;
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
  const findings = [];
  let col = 0;
  for (const ch of file) {
    col += 1;
    const cp = ch.codePointAt(0);
    const ruleId = isVariationSelector(cp) ? 'IUC003' : classify(cp, ch);
    if (!ruleId || RULES[ruleId].severity !== 'critical') continue;
    findings.push({
      ruleId,
      file,
      line: 1,
      col,
      message: `${hex(cp)} in the file path — ${RULES[ruleId].desc}`,
      snippet: escapeInvisible(file),
    });
  }
  return findings;
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
  const files = git(['-c', 'core.quotepath=false', 'ls-files']).split('\n').filter(Boolean);
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

  const { targets } = collectTargets(resolveBaseSha());
  const findings = [];

  for (const [file, changedLines] of targets) {
    if (matchesAny(file, excludes)) continue;
    findings.push(...scanPath(file));

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

    findings.push(...scanText(file, buf.toString('utf8'), changedLines));
  }

  findings.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.col - b.col);
  for (const f of findings) annotate(f);

  const critical = findings.filter((f) => RULES[f.ruleId].severity === 'critical');
  for (const f of critical) {
    console.log(`  ${f.file}:${f.line}:${f.col}  ${f.ruleId}  ${f.message}`);
    console.log(`    near: ${f.snippet}`);
  }
  writeSummary(findings);

  console.log(
    `\nScanned ${targets.size} file(s): ${critical.length} critical, ${findings.length - critical.length} warning(s).`
  );
  if (critical.length > 0) {
    console.log('::error::Invisible Unicode detected. This pull request must not be merged as-is.');
    process.exitCode = 1;
  }
}

module.exports = { scanLine, scanText, scanPath, parseDiff, globToRegExp, escapeInvisible, classify, RULES };

if (require.main === module) main();
