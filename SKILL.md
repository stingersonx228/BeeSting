---
name: beesting
license: MIT
description: BeeSting — security playbook for sites built as "static frontend (vanilla JS/HTML) + Supabase + Vercel/Netlify". Audits RLS, grants and SECURITY DEFINER RPCs; fixes them with a migration verified on a local Supabase-like Postgres (embedded, no access to production); strict CSP without unsafe-inline plus SRI; anti-spam with Cloudflare Turnstile behind an Edge Function gate; staff 2FA (aal2). Use it whenever the project has supabase*.sql / supabase/migrations / supabase-js and the user asks to check security, "how protected are we", find holes, fix RLS or permissions, write or review a SQL migration, lock an RPC away from anon, add a captcha or anti-spam to orders/forms, enable 2FA for the admin panel, remove inline scripts, or set up CSP/security headers — even if the word "security" never comes up.
---

# BeeSting: securing a Supabase-backed site

The threat model behind every decision: the project URL and the anon key are public. Anyone
can call, straight from the browser console, whatever the `anon` and `authenticated` roles are
allowed to do (the latter comes free with sign-up), bypassing the site entirely. So protection
lives in the database — RLS, grants and checks inside functions — and JavaScript checks exist
only for user convenience. The site is just a storefront.

The second fact that shapes the process: SQL is usually applied by the database owner by hand
in the SQL Editor. A broken migration breaks production, and rolling back depends on a person.
Hence the rule: every migration runs on the local harness together with all previous ones
before it is handed over.

## Where things are

| Task | Read |
|---|---|
| Database audit, fix-migration template | `references/supabase-audit.md` |
| Verifying SQL on local Postgres, scenarios | `references/sql-verification.md`, `scripts/pg-harness/` |
| CSP without unsafe-inline, SRI, headers | `references/csp-sri.md`, `scripts/csp_scan.mjs`, `scripts/sri.sh` |
| Anti-spam for orders and forms | `references/turnstile-gate.md`, `assets/turnstile-gate.ts` |
| 2FA for admins and operators | `references/staff-mfa.md`, `assets/staff-mfa.js` |

Read a reference when you reach its topic, not all of them up front.

## Process

### 0. Map the project (5 minutes that save hours)
- Migrations and their **apply order**. Usually a numbered list in DEPLOY.md/README, otherwise
  `supabase/migrations/` sorted by name. Without the order the harness can't be built — ask the user.
- What the client calls: `grep -n "\.rpc(\|\.from(\|functions/v1\|channel(" *.js`. This is the
  real attack surface.
- Who applies SQL and who deploys. If you have no production access, the deliverable is files,
  SQL text and a PR — not changes in production.

### 1. Audit
1. Start the harness and take the automatic report:
   ```bash
   cp -r <skill>/scripts/pg-harness "$TMP/pgh" && sh "$TMP/pgh/setup.sh"
   node "$TMP/pgh/harness.mjs" --repo <project>
   ```
   The report lists tables without RLS, `true` policies, definer functions without
   `search_path`, every function callable by anon/authenticated (flagged "via PUBLIC" and
   "no identity check"), views that bypass RLS, direct anon writes and realtime tables.
2. Review every function in the "callable via rpc" list by hand against the checklist in
   `references/supabase-audit.md`: who can call it, what it checks, what it returns, whether a
   caller can forge a price, a status, someone else's id, or bypass a limit.
3. Client: `service_role` in the code, direct inserts/updates into tables, `.rpc()` without
   `await` (supabase-js is lazy — such a request is never sent), `innerHTML` with user data,
   personal data in URLs.
4. Frontend: `node <skill>/scripts/csp_scan.mjs <project>` and the headers in `vercel.json`.

Write the report so the owner understands it without you:

```
## [Critical|High|Medium|Low] Short title
Where: file:line / function
Attack: what exactly the attacker does (a concrete request) and what they get
Fix: what changes; whether it requires site changes and a rollout order
```

First come findings an anonymous visitor can exploit right now (personal data leaks, free
orders, other people's promo codes), then those that require sign-in, then hygiene.

### 2. Fixes
- **A new migration file**, applied last. Do not edit migrations that were already applied:
  the owner has run them, and editing them changes nothing in the database.
- The file is **idempotent** (`create or replace`, `if not exists`, `drop policy if exists`),
  wrapped in `begin/commit`, with a header: which file it goes after, what changes for the site,
  how to roll back.
- **Compatibility with the live site.** The site and the SQL ship at different times. Either the
  new SQL works with the old client (new parameters have defaults, old signatures keep working),
  or state the order explicitly: "merge the PR first, then the SQL" or the other way round. Best
  of all, make either order safe.
- If the file rewrites a function that later migrations changed, start from the latest version
  of that function. Otherwise you will silently drop someone else's check — in a real project a
  branch validation in `place_order` was lost exactly this way.
- Risky switches (locking an RPC behind a gate, mandatory 2FA) go into a separate final step
  that runs after a production check, and every step gets a rollback.

### 3. Verification
- Harness: all migrations in order + the new file + the new file again (`--twice`) + a scenario
  (`--scenario`) with a pair of checks for every fix: "a stranger/anonymous user can't" and "the
  rightful user can". Otherwise a fix may break the legitimate path and you won't notice.
- `csp_scan.mjs` reports 0 blocking findings, and the page served with the `vercel.json`
  headers opens without CSP errors in the console.
- If the project has e2e tests (Playwright etc.), run them.
- Be honest about what was verified on the harness and what only production can show (the
  harness does not emulate PostgREST's HTTP layer, Storage, Realtime or Edge Functions).

### 4. Handoff
- Give SQL for the SQL Editor **as one block of text** in your answer: the owner copies it whole.
  After any edit to the file, give the text again — the old one is stale.
- Update the migration list in DEPLOY.md (order, which files are idempotent, preconditions).
- Deploying on Vercel Hobby: commits not authored by the project owner are blocked. Work on a
  branch and open a PR; the owner merges it with **Create a merge commit** (not squash/rebase,
  otherwise the contributor stays the author and the deploy is blocked again).
- Do not apply SQL to production or change production settings yourself unless the user
  explicitly asks, even if an MCP server gives you access.

## Principles
- Close what works against an anonymous visitor today first; polish later.
- Every rollout step leaves the site working and has a rollback.
- Database errors are short and machine-readable (`too many orders`); the client turns them
  into human-friendly text.
- Don't grant permissions "just in case": `revoke ... from public, anon, authenticated`, then a
  targeted `grant`.
- Suggest but don't impose business decisions: personal-data retention, processing consent,
  data residency. Those are the owner's call.
