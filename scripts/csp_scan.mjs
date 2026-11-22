#!/usr/bin/env node
// What blocks a strict CSP (script-src without 'unsafe-inline', script-src-attr 'none') on a static site.
// No dependencies. Usage: node csp_scan.mjs <site directory> [--json]
// Exit code 1 if there are blocking findings (inline scripts, on* attributes, javascript:, eval).
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, extname } from 'node:path';

const root = process.argv[2] || '.';
const asJson = process.argv.includes('--json');
const SKIP = new Set(['node_modules', '.git', '.vercel', 'dist', 'build', 'graphify-out', 'test-results', 'playwright-report']);

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (SKIP.has(name) || name.startsWith('.')) continue;
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) walk(p, out);
    else if (['.html', '.htm', '.js', '.mjs'].includes(extname(name))) out.push(p);
  }
  return out;
}

const findings = [];
const add = (file, line, kind, severity, text) =>
  findings.push({ file: relative(root, file), line, kind, severity, text: text.trim().slice(0, 140) });
const lineAt = (src, idx) => src.slice(0, idx).split('\n').length;

for (const file of walk(root)) {
  const src = readFileSync(file, 'utf8');
  const isHtml = /\.html?$/.test(file);
  const isTest = /(^|\/)(tests?|__tests__|e2e)\//.test(relative(root, file)) || /\.(spec|test)\.m?js$/.test(file);
  if (isTest) continue;

  if (isHtml) {
    // <script> without src that has a body (except JSON data blocks — they don't execute)
    for (const m of src.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
      const attrs = m[1];
      const body = m[2].trim();
      const type = (attrs.match(/\btype\s*=\s*["']?([^"'\s>]+)/i) || [])[1] || '';
      if (/\bsrc\s*=/.test(attrs)) {
        const src_ = (attrs.match(/\bsrc\s*=\s*["']([^"']+)/i) || [])[1] || '';
        if (/^https?:\/\//i.test(src_)) {
          if (!/\bintegrity\s*=/.test(attrs)) add(file, lineAt(src, m.index), 'cdn-no-sri', 'warn', `no integrity: ${src_}`);
          if (!/\bcrossorigin\b/i.test(attrs)) add(file, lineAt(src, m.index), 'cdn-no-crossorigin', 'warn', `no crossorigin: ${src_}`);
          if (!/@\d+\.\d+\.\d+/.test(src_) && /(jsdelivr|unpkg|cdnjs|esm\.sh)/.test(src_))
            add(file, lineAt(src, m.index), 'cdn-floating-version', 'warn', `version not pinned: ${src_}`);
        }
        continue;
      }
      if (!body) continue;
      if (/json|importmap|template|text\/x-/i.test(type)) continue;
      add(file, lineAt(src, m.index), 'inline-script', 'block', body.split('\n')[0]);
    }
    for (const m of src.matchAll(/<link\b[^>]*rel\s*=\s*["']?stylesheet[^>]*>/gi)) {
      const href = (m[0].match(/\bhref\s*=\s*["']([^"']+)/i) || [])[1] || '';
      if (/^https?:\/\//.test(href) && !/fonts\.googleapis\.com/.test(href) && !/\bintegrity\s*=/.test(m[0]))
        add(file, lineAt(src, m.index), 'cdn-no-sri', 'warn', `stylesheet has no integrity: ${href}`);
    }
    for (const m of src.matchAll(/<[a-z][^>]*?\s(on[a-z]+)\s*=\s*["'][^"']*["'][^>]*>/gi))
      add(file, lineAt(src, m.index), 'inline-handler', 'block', m[0]);
    for (const m of src.matchAll(/<style\b[^>]*>/gi))
      add(file, lineAt(src, m.index), 'inline-style-block', 'info', '<style> block — needs style-src \'unsafe-inline\' or moving it into a .css file');
  }

  // In JS and HTML: handlers in template strings, javascript: URLs, eval
  const patterns = [
    [/["'`][^"'`]*\son[a-z]+\s*=\s*\\?["'][^"'`]*/g, 'handler-in-template', 'block', 'on* attribute in an HTML string (innerHTML) — replace with addEventListener/delegation'],
    [/(?:href|src|action)\s*=\s*\\?["']\s*javascript:/gi, 'javascript-url', 'block', 'javascript: URL'],
    [/\beval\s*\(|\bnew\s+Function\s*\(|setTimeout\s*\(\s*["'`]|setInterval\s*\(\s*["'`]/g, 'eval', 'block', 'eval/new Function/string timer — needs unsafe-eval'],
    [/\.setAttribute\(\s*["']on[a-z]+["']/g, 'set-handler-attr', 'block', 'setAttribute("on…") — blocked by script-src-attr'],
  ];
  for (const [re, kind, sev, note] of patterns) {
    for (const m of src.matchAll(re)) {
      if (isHtml && kind === 'handler-in-template') continue; // in HTML this is already covered by inline-handler
      add(file, lineAt(src, m.index), kind, sev, `${note}: ${m[0]}`);
    }
  }
}

const blocking = findings.filter((f) => f.severity === 'block');
if (asJson) {
  console.log(JSON.stringify({ blocking: blocking.length, findings }, null, 2));
} else {
  const order = { block: 0, warn: 1, info: 2 };
  findings.sort((a, b) => order[a.severity] - order[b.severity] || a.file.localeCompare(b.file) || a.line - b.line);
  const icon = { block: '✗', warn: '⚠', info: 'ℹ' };
  for (const f of findings) console.log(`${icon[f.severity]} ${f.file}:${f.line} [${f.kind}] ${f.text}`);
  console.log(`\nBlocking: ${blocking.length}, warnings: ${findings.filter((f) => f.severity === 'warn').length}, info: ${findings.filter((f) => f.severity === 'info').length}`);
  if (!blocking.length) console.log('The site is ready for script-src without \'unsafe-inline\' and script-src-attr \'none\'.');
}
process.exitCode = blocking.length ? 1 : 0;
