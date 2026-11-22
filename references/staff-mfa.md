# Staff 2FA with Supabase MFA

After a password sign-in the JWT has level `aal1`. After TOTP verification Supabase issues
session JWTs with `aal2`. The code screen only gates entry to the panel. Data access is enforced
by RLS and RPCs based on the signed JWT, because the browser can call the API directly and skip
the UI. `aal2` proves the sign-in level; the staff role still comes from the `staff` table.
[Supabase MFA](https://supabase.com/docs/guides/auth/auth-mfa)

## The check in the database

Route all staff checks through `public.is_staff(auth.uid())` and `public.is_admin(auth.uid())`.
Review policies with alternative access conditions, `SECURITY DEFINER` RPCs, analytics views and
data access via Realtime. Direct membership checks left in individual RPCs or policies can let
`aal1` through. Use `references/supabase-audit.md` for the inventory.

Example of a new migration for an existing `public.staff(id, role)` table. Keep the project's
parameter names, function owners and role rules. `uid = auth.uid()` means a caller can only
check themselves. `coalesce` rejects a JWT without `aal`.

```sql
begin;

create or replace function public.is_staff(uid uuid)
returns boolean
language sql stable security definer
set search_path = public, pg_temp
as $$
  select uid is not null and uid = auth.uid()
     and coalesce(auth.jwt() ->> 'aal', '') = 'aal2'
     and exists (select 1 from public.staff where id = uid);
$$;

create or replace function public.is_admin(uid uuid)
returns boolean
language sql stable security definer
set search_path = public, pg_temp
as $$
  select uid is not null and uid = auth.uid()
     and coalesce(auth.jwt() ->> 'aal', '') = 'aal2'
     and exists (
       select 1 from public.staff where id = uid and role in ('admin', 'owner')
     );
$$;

revoke execute on function public.is_staff(uuid) from public, anon;
grant execute on function public.is_staff(uuid) to authenticated;
revoke execute on function public.is_admin(uuid) from public, anon, authenticated;

commit;
```

In this variant RLS calls `is_staff` as `authenticated`, while `is_admin` is called inside a
privileged RPC or view whose owner has the right permissions. If you need `is_admin` directly in
RLS or in a `security_invoker` view, the calling role needs `EXECUTE`. In PL/pgSQL use
`if public.is_admin(auth.uid()) is not true then raise exception 'not admin'; end if;` so that a
null result also denies access.

## Vanilla JS panel

Copy `assets/staff-mfa.js` into the site and load it before the panel script. Use the same
Supabase JS v2 instance for sign-in, MFA, data queries and subscriptions. Set `issuer` to a
constant string from the app config.

```html
<section id="mfa" class="hide"><div class="card"></div></section>
<script defer src="/staff-mfa.js"></script>
<script defer src="/admin.js"></script>
```

By this point Supabase JS must be loaded and a `.hide` class defined. In `boot()`, after the
session check and before any data queries, insert:

```js
async function confirmStaffSession(sb, signOutStaff) {
  const { data: { session }, error } = await sb.auth.getSession();
  if (error || !session) return false;
  return window.StaffMFA.ensure(sb, document.querySelector("#mfa"), {
    onSignOut: signOutStaff,
    issuer: "Staff panel",
  });
}

// In the panel's async boot():
// if (!(await confirmStaffSession(sb, signOutStaff)) || signingOut) return;
```

Keep the working panel hidden until `ensure` resolves. If you need an early staff lookup by
`session.user.id`, keep reading the user's own minimal row under a separate self-only policy. If
the lookup relies on `is_staff`, move it after MFA: at `aal1` the check denies access and the
code screen would never be reached. After `ensure`, load the role, data and subscriptions. On
sign-out, stop timers, remove subscriptions, clear panel data and call `sb.auth.signOut()`.

What the template does:

1. `getAuthenticatorAssuranceLevel()` returns `currentLevel` and `nextLevel`. If the current level
   is already `aal2`, continue. `nextLevel === 'aal2'` means the level can be raised.
2. At `aal1`, call `listFactors()`. For a verified TOTP in `factors.totp`, show the six-digit code
   input.
3. If there is no verified TOTP, take the unfinished TOTP factors from `factors.all` and remove them
   with `unenroll({ factorId })`. When adapting the template, handle an unenroll error before
   `enroll`. Then call `enroll({ factorType: 'totp', issuer, friendlyName })` and show
   `data.totp.qr_code` or the manual secret. Don't log the QR or secret, and clear them from the UI
   on completion or sign-out.
4. `challengeAndVerify({ factorId, code })` creates a challenge and verifies the code. After success
   the SDK uses the refreshed session. If you call the API with your own `fetch`, take the new
   access token. For a wrong or expired code, allow a retry without re-enrolling; on a rate limit,
   tell the user to wait.

## Rollout

1. **Check Auth settings.** Enable TOTP enrollment and verification. Require at least 12 characters
   for staff passwords and review existing accounts. Keep sign-in and MFA verification rate limits
   on. If neither the storefront nor other clients need self-sign-up, disable
   `Allow new users to sign up` and create staff accounts administratively.
   [Auth settings](https://supabase.com/docs/guides/auth/general-configuration)
2. **Deploy the site.** Update every staff panel. Test enrollment, re-sign-in and sign-out, and
   recovery after a wrong code. The old database rules still apply at this stage.
3. **Wait for every staff member.** Each admin and operator enrolls a factor and signs in with a code
   in a new session. Before switching, confirm that everyone has a verified factor. Do initial
   enrollment and re-enrollment after a reset only after verifying the person's identity: on an
   account without a factor, the password alone is enough to start enrollment.
4. **Apply the migration.** Run it on the harness and apply it last. Check that at `aal1` protected
   data and operations are unavailable, at `aal2` an operator sees their sections and an admin can
   perform admin operations. The site's public flows must keep working.

## Resetting a factor

Verify the staff member's identity and find the exact UUID in Authentication → Users. Delete the
factor through the Auth Admin API from a trusted server environment. Here `adminClient` is a client
instance with the server key, and `userId` and `factorId` are verified UUIDs.

```js
const { error } = await adminClient.auth.admin.mfa.deleteFactor({
  userId,
  id: factorId,
});
if (error) throw error;
```

Supabase ends active sessions when a verified factor is deleted. An already issued access token may
stay valid until it expires if the app only checks the JWT. Ask the person to sign in again; with no
verified factors they'll be offered enrollment. Deleting rows directly from `auth.mfa_factors`
appears in older guides; use the Auth Admin API for a proper reset that ends sessions.
[Supabase deleteFactor](https://supabase.com/docs/reference/javascript/auth-admin-deletefactor)

## Rollback

Prepare a new SQL file with the previous definitions of `is_staff` and `is_admin` and the previous
grants. Restore them in one transaction, keeping the own-UID restriction and the role check. Test
the panels. If the frontend also needs rolling back, do it after the SQL — otherwise the old client
stops at `aal1`. Enrolled factors are kept. After the SQL rollback a password is again enough to
query staff data, even if the panel still asks for a code.

## Pitfalls

- An abandoned enrollment left an unverified TOTP factor that blocked the next attempt. Clean up only
  unfinished TOTP factors. Prevent re-running `boot()` and double code submission while a check is in
  progress.
- If the SQL is switched on before the panels are updated and factors enrolled, old sessions stay at
  `aal1`. RLS on reads can return an empty list without an error, so test access against a row you
  created beforehand.
- Reusing a JWT captured before MFA keeps requests at `aal1` even after a correct code. Start data
  loading and Realtime after MFA and recreate old subscriptions.
- A strict CSP can hide the QR code: the asset receives `data:image/svg+xml`. Check `img-src` and the
  manual key enrollment. If the active policy blocks inline styles, move the template's styles into
  external CSS.
- In the template, leaving the form calls `onSignOut`. If your integration doesn't reload the page,
  resolve the pending `ensure` with `false` when adapting it, so the next sign-in starts a new cycle.

## How to verify

The `scripts/pg-harness/` scenario below uses `public.staff(id, name, role)` and RLS on
`public.orders`. Prepare one order row the operator should see. If there is a public read policy,
pick an order or operation protected specifically by the staff check.

```js
export default async function (h) {
  const operator = await h.createUser({ email: "operator@example.com" });
  const outsider = await h.createUser({ email: "outsider@example.com" });
  await h.q(
    "insert into public.staff (id, name, role) values ($1, 'Operator', 'operator')",
    [operator],
  );
  const sql = "select count(*)::int as n from public.orders";
  const aal1 = await h.asUser(operator, sql, [], { aal: "aal1" });
  const aal2 = await h.asUser(operator, sql, [], { aal: "aal2" });
  const nonStaff = await h.asUser(outsider, sql, [], { aal: "aal2" });
  h.assert.equal(aal1.rows[0].n, 0);
  h.assert.ok(aal2.rows[0].n > 0);
  h.assert.equal(nonStaff.rows[0].n, 0);
}
```

Add project checks for an admin RPC: an operator at `aal2` and an admin at `aal1` are rejected, an
admin at `aal2` succeeds. Check the actual result through the public entry point.

```bash
node "$HARNESS/harness.mjs" --repo "$PROJECT" --scenario "$CHECKS" --twice staff_mfa.sql
```

`HARNESS` is a copy of `scripts/pg-harness/` after `sh setup.sh`, `PROJECT` is the project
directory, `CHECKS` is the scenario with data setup and checks. Substitute your migration name.
The harness imitates PostgREST claims. Separately, test in a browser: first sign-in with the QR,
re-sign-in with a code, rejection of a wrong code, sign-out, factor reset and re-enrollment.
