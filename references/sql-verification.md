# Verifying SQL migrations before handing them to the owner

The owner applies SQL by hand in the Supabase SQL Editor. A mistake in file order, an RPC
signature or grants can stop writes from the site or leave data readable by the wrong role.
Run the whole chain on a fresh temporary database, and separately check that the new file is
safe to apply again after a failure or a repeated run from the SQL Editor.

## What the harness covers

`scripts/pg-harness/harness.mjs` starts an embedded Postgres 17. Each run creates a new database,
applies SQL as `postgres`, prints an audit and runs a scenario if one is given.

- Roles `anon`, `authenticated`, `service_role` without login. `service_role` has `BYPASSRLS` but
  still needs grants.
- `auth.uid()`, `auth.role()`, `auth.jwt()` and `auth.email()` read the session settings
  `request.jwt.claims`, `request.jwt.claim.sub` and `request.jwt.claim.role`. The `auth.users` and
  `auth.mfa_factors` tables have a minimal set of columns for fixtures and FKs.
- Default privileges follow Supabase's model for objects created by `postgres` in `public`: the
  three roles get rights on new tables and sequences and `EXECUTE` on functions. A real project's
  ACLs may differ, especially if the owner or default privileges were changed.
- There is an empty `supabase_realtime` publication. The harness tries to install `pgcrypto`,
  `uuid-ossp`, `citext` and `pg_trgm` into the `extensions` schema; extensions missing from the
  build are skipped. The `extensions` schema is in the initial `search_path`.

The model stops at SQL. Substituting claims does not test JWT signatures, token issuance or
TOTP. PostgREST HTTP routing, RPC overload resolution, the schema cache, Storage, Realtime event
delivery and Edge Function calls must be tested separately on a staging Supabase project. A
successful local run also leaves open compatibility with data already accumulated in production
and the actual permissions of the owner's role in the SQL Editor.

### If a migration depends on pg_net, pg_cron or Vault

In a temporary copy of the migrations, prepare a first file `bootstrap-local.sql`. Create only the
schemas, columns and signatures the SQL uses, including argument names for calls with `:=`. If the
chain has a `CREATE EXTENSION` for a missing extension, replace that line with a stub in the test
copy only and note the difference in your report. A stub does not register the extension in
`pg_extension`. Example for calls to `net.http_post`, `cron.schedule` and reads from Vault.
[Example calls in Supabase Docs](https://supabase.com/docs/guides/functions/schedule-functions)

```sql
-- bootstrap-local.sql, temporary harness only
create schema net;
create schema cron;
create schema vault;

create function net.http_post(
  url text,
  body jsonb default '{}'::jsonb,
  params jsonb default '{}'::jsonb,
  headers jsonb default '{"Content-Type":"application/json"}'::jsonb,
  timeout_milliseconds integer default 2000
) returns bigint language sql as $$ select 1::bigint $$;

create function cron.schedule(job_name text, schedule text, command text)
returns bigint language sql as $$ select 1::bigint $$;

create view vault.decrypted_secrets as
select 'api_key'::text as name, 'local-test-only'::text as decrypted_secret;
```

Put `bootstrap-local.sql` first in `--migrations`. For tests that call these from an application
role, reproduce the needed grants explicitly. A dummy ID proves the SQL wires together. To check
call parameters, write them into a local table and compare from the scenario. Actual HTTP sending,
scheduled job execution and secret management must be tested separately.

## How to run it

1. From the skill root, copy the harness into a temporary directory. Installation needs Node.js
   and npm; `node_modules` stays in the temporary copy.

   ```sh
   work=$(mktemp -d)
   cp -R scripts/pg-harness "$work/pg-harness"
   cd "$work/pg-harness"
   sh setup.sh
   ```

2. Apply the previous migrations in rollout order, then the new file. In the second command,
   substitute your file names and put `checks.mjs` into the temporary harness copy.

   ```sh
   repo=/path/to/my-site
   node harness.mjs --repo "$repo" --twice supabase_bugfixes.sql
   node harness.mjs --repo "$repo" \
     --migrations supabase.sql,supabase_hardening.sql,supabase_bugfixes.sql \
     --twice supabase_bugfixes.sql --scenario ./checks.mjs --json ./report.json
   ```

   Compare the `✓ applied` lines with the instructions for the owner. For a multi-stage rollout,
   also run the intermediate states with the matching file lists. If the migration changes the
   data format, test it against rows in the old format too. Setup SQL with fixtures can be placed
   in the local list right before the new file. The scenario runs after the migrations.

3. Review the audit and the scenario result. Exit code `0` means the migrations and the given
   scenario passed. Audit warnings don't change the exit code. If a migration fails, the harness
   stops with code `1` and prints the file and, if the server reported a position, the line.
   Abridged output of a run with a re-apply and a scenario:

   ```text
   ✓ applied supabase_bugfixes.sql
   ✓ applied supabase_staff_mfa.sql
   ✓ re-applied supabase_bugfixes.sql
   ✓ Tables in public without RLS: none
   ⚠ "true" policies for public/anon/authenticated: 1
      - menu_items.menu_public_read [SELECT {anon,authenticated}] using=true check=-
   ✓ SECURITY DEFINER without set search_path: none
   ⚠ Functions callable via /rest/v1/rpc (review each one): 25
   ── Scenario ./checks.mjs
   ✓ anon has no EXECUTE on place_order
   ✓ a retry with the same key left one order
   ✓ is_staff requires membership and aal2
   SCENARIO PASSED
   ```

### Flags

| Flag | Effect |
| --- | --- |
| `--repo DIR` | Project root. Defaults to the current directory. |
| `--migrations a.sql,b.sql` | Explicit order. Paths are relative to `--repo`. Without the flag the order comes from the first matching document among `DEPLOY.md`, `README.md`, `MIGRATIONS.md`, `docs/*.md`. The parser looks for lines like `1. a.sql` or `2) b.sql`, including names in backticks. It does not act on conditions written in the text. |
| `--twice x.sql,y.sql` | Runs the listed files again after the main chain. For a real re-apply, include them in the main chain too. |
| `--scenario ./checks.mjs` | Loads a module from a path relative to the current directory and calls its `default` or `run` export. |
| `--no-audit` | Skips the audit. Handy while debugging a scenario. |
| `--json ./report.json` | Writes the results of migrations, audit and scenario. The file is created after connecting to the database and running the checks; a startup failure may leave no report. |
| `--port 54330` | Local Postgres port. Defaults to `54329`. |

### Reading the audit

| Report line | What to check |
| --- | --- |
| Tables in `public` without RLS | Client grants on private data must be fixed. For an internal table with revoked rights, confirm the rejection for both `anon` and `authenticated`. |
| `true` policies | An open `SELECT` on a public catalog is fine. An unconditional write needs a justification and a check together with the effective grants. The search matches a literal `true`, so test complex conditions with scenarios. |
| `SECURITY DEFINER` without `search_path` | Pin the path, e.g. `set search_path = public, pg_temp`, provided calling roles can't create objects in `public`. The audit only sees whether the setting exists; check its contents by hand. |
| Callable RPCs | Compare each signature's `EXECUTE` with the contract. The "via PUBLIC" label calls for an ACL check. "No identity check" is detected by searching the function body. A public token-based RPC can be legitimate if it verifies the token and returns only the necessary data. |
| Readable views without `security_invoker` | A plain view uses the owner's rights to read base tables. Set `security_invoker = true` or revoke client `SELECT`. For a materialized view, check access to the stored rows and its grants. |
| Direct `anon` writes | Candidates based on the combination of ACLs and policies. Test the specific operation and the expected row state afterwards. Writing through an RPC does not by itself close direct writes. |
| `supabase_realtime` | Tables in the publication. Compare with intent and check the SELECT policies. |

See `references/supabase-audit.md` for details on permissions and RLS.

## Writing scenarios

Start from `scripts/pg-harness/example-scenario.mjs`. Run queries sequentially with `await`: a
single session switches role and claims. Use `h.q` to prepare fixtures and inspect the actual
database state as `postgres`, and test access with `h.asAnon`, `h.asUser` or `h.asService`.

**RLS and grants.** For a table with `SELECT` granted and an owner policy, first confirm that the
owner sees a specific row, then check that another user gets `rowCount === 0` on the same query.
An empty table makes a negative check pass falsely. If a grant should be revoked, expect SQLSTATE
`42501` via `h.rejects`. For a business rejection, check the specific error, e.g. `/not staff/`, or
an explicit `false` / empty set according to the function's contract.

**2FA.** Create the user with `h.createUser` before inserting related rows. The same staff member
must be rejected at `aal1` and allowed at `aal2`. Also test an outsider at `aal2`. Example for a
schema with `staff(id, name, role)` and `is_staff(uuid)`:

```js
export default async function (h) {
  const uid = await h.createUser({ email: 'staff@example.test' });
  const other = await h.createUser();
  await h.q(
    'insert into public.staff (id, name, role) values ($1, $2, $3)',
    [uid, 'Test', 'admin'],
  );

  const sql = 'select public.is_staff($1::uuid) as ok';
  await h.rejects(h.asAnon(sql, [uid]), { code: '42501' });
  h.assert.equal((await h.asUser(uid, sql, [uid])).rows[0].ok, false);
  h.assert.equal((await h.asUser(uid, sql, [uid], { aal: 'aal2' })).rows[0].ok, true);
  h.assert.equal((await h.asUser(other, sql, [other], { aal: 'aal2' })).rows[0].ok, false);
  h.log('is_staff requires membership and aal2');
}
```

**RPC idempotency.** Apart from `--twice`, call the RPC twice with the same key and a valid
payload. In the example, `payload` holds test order data and `clientKey` is a UUID. If writes go
through an Edge gate, use `h.asService` for the SQL call and test the `anon` rejection separately.

```js
const sql = 'select * from public.place_order($1::jsonb)';
const args = [JSON.stringify({ ...payload, client_key: clientKey })];
await h.rejects(h.asAnon(sql, args), { code: '42501' });
const first = (await h.asService(sql, args)).rows[0];
const repeat = (await h.asService(sql, args)).rows[0];
h.assert.ok(first.order_no);
h.assert.equal(repeat.order_no, first.order_no);
const { rows: [count] } = await h.q(
  'select count(*)::int n from public.orders where client_key = $1',
  [clientKey],
);
h.assert.equal(count.n, 1);
```

**Rate-limit windows.** So that earlier fixtures don't exhaust the limit for the next test, age
them as `postgres`, restricting the UPDATE to the ids of the rows you created. In a dedicated
limit test, keep a fresh `created_at`, check the rejection, then age the rows and check that a new
request passes.

```js
await h.q(
  "update public.orders set created_at = now() - interval '1 hour' where id = any($1::bigint[])",
  [fixtureOrderIds],
);
```

**Time zones.** Compare hours and minutes in the business rule's zone, then check the interval
between two absolute moments. Pick a time later than the default ETA so you test the scheduled
delivery specifically. Add a case that crosses local midnight. Here `tz` is the project's IANA
zone, `expectedHm` is the local time passed to the RPC, and `order` is the call's result.

```js
const { rows: [eta] } = await h.q(
  `select to_char($1::timestamptz at time zone $3, 'HH24:MI') as hm,
          extract(epoch from ($1::timestamptz - $2::timestamptz)) / 60 as minutes`,
  [order.eta_delivery_at, order.eta_ready_at, tz],
);
h.assert.equal(eta.hm, expectedHm);
h.assert.equal(Number(eta.minutes), 20);
```

## Pitfalls

- **macOS and symlinks.** If Postgres fails to start while loading a library, run `sh setup.sh`
  again. It runs `scripts/hydrate-symlinks.js` from the installed `@embedded-postgres` package and
  hides its output. To diagnose, run that JS by hand from the package directory inside
  `node_modules/@embedded-postgres/`.
- **Port in use.** Rerun with `--port 54330` or another free port.
- **Staff FK.** A random UUID in `staff.id` fails the FK if the user doesn't exist in `auth.users`
  yet. Call `h.createUser()` first, then INSERT with its UUID.
- **New RPC result type.** `CREATE OR REPLACE FUNCTION` with the same input types does not change
  the result type, including the shape of `RETURNS TABLE`. Drop the old signature and recreate the
  function. Check dependencies and restore `REVOKE` / targeted `GRANT EXECUTE` in the same
  transaction. The new object gets default privileges, so re-running alone doesn't guarantee the
  previous ACL.
- **Gate rules changed.** An old scenario called `place_order` as `anon`. After switching to the
  Edge gate, the successful-order test must go through `service_role`, and an `anon` call must get
  `42501`. Re-running the SQL must not restore public `EXECUTE`.

## Before handing it to the owner

1. Run the whole chain in the order given to the owner, including the new file. Reconcile the order
   with what has already shipped and with the conditions for enabling the gate or 2FA.
2. Re-apply the new file with `--twice`. When updating an existing database, also check that old
   rows survive and new columns get filled.
3. Test the owner, a stranger and an anonymous user. Add `service_role` for internal RPCs and an
   `aal1` vs `aal2` comparison for staff.
4. After every `DROP FUNCTION`, verify the effective `EXECUTE` for the exact signature, including
   access via `PUBLIC`. Test both the rejection and a successful call after re-applying the file.
5. Give the owner the SQL Editor execution order, rollout conditions and short site checks to run
   afterwards. If stubs were used, list the integrations that need testing on a staging project.
