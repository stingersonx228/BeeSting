# Supabase audit: what to look for and how to fix it

Threat model: the anon key and project URL are public — anyone can see them in DevTools.
Everything granted to `anon` (and to `authenticated`, after a free sign-up) can be called
directly through `/rest/v1/...` and `/rest/v1/rpc/...`, bypassing the site. So all protection
lives in the database: RLS, grants and checks inside functions. Client-side checks are UX only.

## Contents
1. Table permissions and RLS
2. Functions (RPC) and SECURITY DEFINER
3. Views and realtime
4. Business logic: money, limits, idempotency
5. Client code
6. Staff: roles and 2FA
7. Fix-migration template

## 1. Table permissions and RLS

In Supabase, everything created in `public` is granted to `anon`, `authenticated` and
`service_role` by default (default privileges). Therefore:

- A table without `enable row level security` is fully open for reading and writing.
- RLS enabled but no policies: everything is closed (fine for internal tables).
- With RLS, other people's rows return "0 rows", not an error. "permission denied" only appears after a `revoke`.
- A `using (true)` policy on SELECT is fine for a public catalog (a menu). On
  INSERT/UPDATE/DELETE for anon it is almost always a hole.
- INSERT/UPDATE need `with check`; otherwise a user can write a row "on someone else's behalf"
  (forge `user_id`, `status`, `price`).
- Columns: RLS works per row. If anon may see a row but not the phone number, you need a
  separate RPC, a view with `security_invoker`, or `revoke select (phone)` / column-level grants.

An internal table that only functions touch:
```sql
alter table public.x enable row level security;
revoke all on public.x from public, anon, authenticated;
```

## 2. Functions (RPC) and SECURITY DEFINER

- New functions grant `EXECUTE` to the `PUBLIC` role by default. `revoke ... from anon` alone is
  not enough — anon inherits from PUBLIC. Do this:
  ```sql
  revoke execute on function public.f(args) from public, anon, authenticated;
  grant  execute on function public.f(args) to authenticated;   -- whoever actually needs it
  ```
  The signature in `revoke/grant` must match the arguments exactly (`public.f(text, int)`).
- `security definer` runs with the owner's (postgres) rights and bypasses RLS. Every such function
  needs `set search_path = public, pg_temp`, otherwise objects can be hijacked through search_path.
- Inside a definer function, check identity explicitly: `auth.uid()`,
  `public.is_staff(auth.uid())`, row ownership (`where courier_id = auth.uid()`), a secret token
  (`where track_token = p_token`).
- Access by a token from a link: only a `uuid` / random ≥128 bits, never a sequential order number.
  Return the minimum fields (no phone/address if tracking is public).
- Changing the return type: `create or replace` won't do it — you need
  `drop function ...; create function ...` and must re-grant (grants are dropped with the function).
- Errors: `raise exception 'too many orders'` — a short machine code that the client translates
  into friendly text. Don't leak SQL details.

## 3. Views and realtime

- A view created by postgres runs with the owner's rights by default and bypasses RLS.
  Postgres 15+: `alter view public.v set (security_invoker = true);` or revoke select from anon.
- Realtime (`postgres_changes`) delivers rows under the same SELECT policies. A table in the
  `supabase_realtime` publication with a broad SELECT policy streams every change to every subscriber.

## 4. Business logic: money, limits, idempotency

- Price, discount, total and status are computed on the server only. The client sends `id` and
  `qty`; the function takes prices from the table and checks `available`, the minimum order,
  cart length (1–100 lines), `qty` (1–50) and string lengths (name, address, comment).
- Rate limits inside the RPC: N orders per phone per window, a global ceiling per window.
  Races are prevented by an advisory lock on the key (`pg_advisory_xact_lock(<namespace>, hashtext(key))`)
  and an indexed counter (`created_at`, normalized phone).
- Normalize phone numbers with one function (`phone_key(text)` → digits only, local prefix
  normalized) and compare through it everywhere: per-phone promo codes, limits, referrals.
- Idempotency: the client sends a `client_key uuid`; a partial unique index plus an advisory lock.
  A retry returns the existing order instead of creating a second one (timeouts, double clicks).
- Promo codes and prizes: validation and redemption in one transaction (`update ... where used = false
  returning`), bound to the owner's phone, single use, expiry date.
- Statuses: only allowed transitions (`new→accepted→...`), and the role is checked at every step.

## 5. Client code

- The `service_role` key must never reach the client (grep for `service_role`, an `eyJ` JWT with role service).
- Move direct `.from('orders').insert/update` calls from the site into an RPC with validation.
- supabase-js queries are lazy: `sb.rpc(...)` / `sb.from(...).update(...)` without `await` or
  `.then()` never execute. Look for calls whose result is neither awaited nor returned.
- Check `error` on every call; otherwise a failure looks like "empty".
- XSS: user data (name, address, comment, review) goes into `innerHTML` only through escaping
  (`esc()`), or use `textContent`. Especially in staff panels: XSS there means hijacking an
  operator's session.
- Don't put personal data in URLs (query strings, `wa.me?text=`, analytics): it ends up in logs
  and the Referer. For pages with a token: `Referrer-Policy: no-referrer`, `Cache-Control: no-store`.
- Storage: public buckets are visible to everyone; uploads need policies on `storage.objects`.

## 6. Staff: roles and 2FA

- One source of truth: `is_staff(uid)`, `is_admin(uid)` (definer, search_path); every staff policy
  and RPC calls it. Then hardening (e.g. 2FA) happens in one place.
- 2FA (TOTP via Supabase MFA): add `coalesce(auth.jwt() ->> 'aal', '') = 'aal2'` to
  `is_staff/is_admin`. Rollout order is in `staff-mfa.md`.
- Sign-up is open (Auth → Email signup): anyone gets the `authenticated` role. So everything
  granted to `authenticated` must itself verify that the caller is staff or owns the row.

## 7. Fix-migration template

Don't edit applied migrations: the database owner has already run them. The new file is applied last.

```sql
-- ============================================================================
--  <project> — <what we fix, one line>.
--  Apply after <last file>. Idempotent — safe to run again.
--  What changes for the site: <which client versions are compatible, rollout order>.
--  Rollback: <command or file>.
-- ============================================================================
begin;

alter table public.orders add column if not exists client_key uuid;
create unique index if not exists orders_client_key_uidx on public.orders (client_key) where client_key is not null;

create or replace function public.f(p text)
returns ... language plpgsql security definer set search_path = public, pg_temp as $$
begin
  ...
end $$;

drop policy if exists "orders_staff_select" on public.orders;
create policy "orders_staff_select" on public.orders for select to authenticated
  using (public.is_staff(auth.uid()));

revoke execute on function public.f(text) from public, anon, authenticated;
grant  execute on function public.f(text) to anon;

commit;
```

Mandatory: a harness run (`sql-verification.md`) with all previous migrations, applying the file
a second time, and "a stranger can't / the owner can" scenarios.
