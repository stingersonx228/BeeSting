# Anti-spam with Cloudflare Turnstile and an Edge Function

- [Gate](#gate)
- [Keys, CORS and CSP](#keys-cors-and-csp)
- [Client](#client)
- [Rollout](#rollout) and [rollback](#rollback)
- [Pitfalls](#pitfalls)
- [How to verify](#how-to-verify)

```text
Browser → Turnstile widget → single-use token
Browser → POST /functions/v1/turnstile-gate { action, token, payload }
Gate    → Cloudflare Siteverify → success, action, hostname
Gate    → PostgREST as service_role → place_order(jsonb)
```

The Supabase URL and anon key are public. As long as browser roles have `EXECUTE`, the client
widget can be skipped by calling the RPC directly. Protection is only complete after two
changes: the gate requires a valid token, and the database revokes direct access. Check every
overload and any other path to the same write per `references/supabase-audit.md`.

## Gate

Use `assets/turnstile-gate.ts` as `supabase/functions/turnstile-gate/index.ts`. Keep in
`ACTIONS` only the public operations that need a captcha. The key `order` is the `action` value
in the widget and in the request JSON. `rpc` is the database function name; `args` turns the
request body into named PostgREST parameters.

```ts
const ACTIONS: Record<string, Action> = {
  order: {
    rpc: "place_order",
    args: ({ payload }) =>
      payload && typeof payload === "object" && !Array.isArray(payload)
        ? { payload }
        : null,
  },
};
```

The server decides the RPC name and argument set. Check types, sizes and required fields. Keep
price, availability, rate-limit and idempotency checks inside the RPC. `service_role` bypasses
RLS, so a public gate suits narrow operations such as creating an order. User operations that
depend on `auth.uid()` need their own identity and permission checks — Turnstile does not
identify the user.

Before calling the RPC the gate checks `success === true`, `action` against the `ACTIONS` key and
`hostname` against the allowed hosts. The action check binds the token to the operation; the host
check binds it to the site. On a Siteverify timeout or error the RPC is not called. The template
checks the host strictly: an empty host list blocks every request instead of silently allowing
all. A request without a token gets `403 captcha required`; a malformed request gets `400`.
[Cloudflare Siteverify](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/)

## Keys, CORS and CSP

- In Cloudflare, create a Managed widget and list the site's hosts, e.g. `my-site.vercel.app`.
  Only the public `TURNSTILE_SITE_KEY` goes into the browser's `config.js`.
- In Edge Function Secrets, set `TURNSTILE_SECRET_KEY` and `ALLOWED_ORIGINS` (comma-separated,
  e.g. `https://my-site.vercel.app`). An origin includes the scheme and a non-default port; drop
  the path and trailing slash. The template reads `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY`
  from the Supabase environment. Keep the service key and the Turnstile secret on the server.
- Handle `OPTIONS` before parsing the body. Echo an allowed origin in `Access-Control-Allow-Origin`
  together with `Vary: Origin`. Allow the headers the client actually sends. Outside a browser the
  sender sets `Origin` itself, so CORS does not replace Siteverify.
- The request examples below assume a legacy anon JWT. With `verify_jwt` enabled, the platform
  checks the Bearer JWT before the function runs. For a public gate with a modern publishable key,
  send it in `apikey` and set `verify_jwt = false` under `[functions.turnstile-gate]`. The gate
  still requires Turnstile. For RPCs from a signed-in client, the Bearer is their access token.
  [Supabase Edge Function auth](https://supabase.com/docs/guides/functions/auth-headers)
- In CSP, add `https://challenges.cloudflare.com` to `script-src` and `frame-src`, and
  `https://<project-ref>.supabase.co` (or your actual API origin) to `connect-src`. If you use
  `script-src-elem`, check it too. With `strict-dynamic`, make sure the widget loader inherits
  trust from an allowed script. For pre-clearance mode, add `'self'` to `connect-src`.
  [Cloudflare CSP](https://developers.cloudflare.com/turnstile/reference/content-security-policy/)

## Client

The site's external script loads `api.js?render=explicit`. Place the container
`<div id="ts-order"></div>` inside the visible form. The example uses `cfg.SUPABASE_URL`,
`cfg.SUPABASE_ANON_KEY` and `cfg.TURNSTILE_SITE_KEY` from the site config.

```js
let turnstileReady;

function loadTurnstile() {
  if (window.turnstile) return Promise.resolve(window.turnstile);
  return turnstileReady ??= new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
    script.async = true;
    const fail = () => {
      clearTimeout(timer);
      script.remove();
      reject(new Error("The verification failed to load. Please try again."));
    };
    const timer = setTimeout(fail, 15000);
    script.onload = () => {
      if (!window.turnstile) return fail();
      clearTimeout(timer);
      resolve(window.turnstile);
    };
    script.onerror = fail;
    document.head.append(script);
  }).catch(error => {
    turnstileReady = null;
    throw error;
  });
}

async function requestOrderToken() {
  const ts = await loadTurnstile();
  let widgetId;
  let timer;
  try {
    return await new Promise((resolve, reject) => {
      const fail = () => reject(new Error("The verification did not complete. Please try again."));
      timer = setTimeout(fail, 60000);
      widgetId = ts.render("#ts-order", {
        sitekey: cfg.TURNSTILE_SITE_KEY,
        action: "order",
        appearance: "interaction-only",
        callback: resolve,
        "error-callback": fail,
        "expired-callback": fail,
      });
    });
  } finally {
    clearTimeout(timer);
    if (widgetId !== undefined) ts.remove(widgetId);
  }
}

let prepared;
let pending;
const gateOn = Boolean(cfg.TURNSTILE_SITE_KEY);
const fresh = () => prepared && Date.now() - prepared.at < 280_000;

// Call when the form opens. Show an error on submit if verification fails again.
function prepareOrderToken() {
  if (!gateOn || fresh()) return Promise.resolve();
  return pending ??= requestOrderToken()
    .then(token => { prepared = { token, at: Date.now() }; })
    .finally(() => { pending = null; });
}

async function submitOrder(payload) {
  let path = "/rest/v1/rpc/place_order";
  let body = { payload };

  if (gateOn) {
    await prepareOrderToken();
    if (!fresh()) throw new Error("The verification expired. Please try again.");
    const { token } = prepared;
    prepared = null;
    path = "/functions/v1/turnstile-gate";
    body = { action: "order", token, payload };
  }

  const response = await fetch(cfg.SUPABASE_URL + path, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      apikey: cfg.SUPABASE_ANON_KEY,
      Authorization: "Bearer " + cfg.SUPABASE_ANON_KEY,
    },
    body: JSON.stringify(body),
  });
  const data = await response.json().catch(() => null);
  if (response.ok) return data;
  if (gateOn && response.status === 403) {
    throw new Error("The verification was rejected. Please try again.");
  }
  throw new Error("The server did not accept the order. Please try again.");
}
```

Call `prepareOrderToken().catch(() => {})` when the form opens. On submit, disable the button
until `submitOrder` finishes, show errors next to the form, keep the field values, and only open
any follow-up tab after a successful check. A token is valid for 300 seconds, once. The
20-second margin leaves time to deliver the request. The token is cleared from memory before
sending: even if the response is lost, it may already have been verified. On retry, get a new
token and keep the order's idempotency key if the RPC supports one.

An empty site key switches the client to the direct RPC — useful during the transition and for
rollback. After the lock migration this only works once the grant is restored. Don't fall back
to the direct path based on a widget or gate error status.

## Rollout

1. **Grant the gate access.** Record the current ACLs and apply a separate migration. The old site
   keeps using its own grants.

   ```sql
   grant execute on function public.place_order(jsonb) to service_role;
   ```

2. **Configure Cloudflare and secrets, deploy the gate.** For example,
   `supabase functions deploy turnstile-gate --project-ref <project-ref>` (substitute the value
   without the angle brackets). Check the preflight, the no-token rejection and a successful
   browser request on staging. Check that the site's old path still works.
3. **Deploy the site with the key and CSP.** On the target domain, check every action in `ACTIONS`
   and the resulting database row. Remember open tabs and cached `config.js`/JS: an old build keeps
   calling the RPC directly. Make sure CDN assets and open tabs have refreshed before revoking grants.
4. **Apply the lock as a separate migration.** Include every relevant signature. Repeat the browser
   check and confirm that browser roles are rejected.

   ```sql
   begin;
   revoke execute on function public.place_order(jsonb) from public, anon, authenticated;
   grant execute on function public.place_order(jsonb) to service_role;
   commit;
   ```

## Rollback

If the lock is already applied, first restore the direct grants for the roles the site used.
For example, if both roles had access:

```sql
grant execute on function public.place_order(jsonb) to anon, authenticated;
```

Then clear `TURNSTILE_SITE_KEY` and deploy the config, or roll back to a working direct build.
Test an order in a new tab. While old tabs still use the gate, keep its configuration working.
Restoring direct grants reopens the operation without a captcha.

## Pitfalls

- The gate passed the captcha but got `permission denied for function place_order`: `service_role`
  had no `EXECUTE`. Add that grant separately, before deploying the frontend and before revoking
  `PUBLIC`.
- Verification started after the user switched to a messenger app. If the widget needed an
  interaction, the user never saw it and the request waited until the timeout.
- Shipping the lock before the site would have cut the old client off. Grant, client deploy and
  lock must be separate steps.
- Checking only `success` loses the binding to the action and host. Cloudflare's test keys return
  a dummy hostname and no action, so use a separate real widget on staging to test both bindings.
  [Cloudflare test keys](https://developers.cloudflare.com/turnstile/troubleshooting/testing/)
- Preview, custom and primary Vercel domains are different origins. Check both lists (Cloudflare
  and `ALLOWED_ORIGINS`) and the preflight response. If the gateway answers `401` before the
  function runs, check `verify_jwt` and the key type.

## How to verify

On staging with the gate configured and the lock applied. Set `SUPABASE_URL` and `ANON_JWT` for
staging first. The origin must be allowed.

```bash
curl -i "$SUPABASE_URL/functions/v1/turnstile-gate" \
  -H 'Origin: https://my-site.vercel.app' -H 'Content-Type: application/json' \
  -H "apikey: $ANON_JWT" -H "Authorization: Bearer $ANON_JWT" \
  --data '{"action":"order","payload":{}}'
# 403, captcha required

curl -i "$SUPABASE_URL/rest/v1/rpc/place_order" \
  -H 'Content-Type: application/json' \
  -H "apikey: $ANON_JWT" -H "Authorization: Bearer $ANON_JWT" \
  --data '{"payload":{}}'
# PostgreSQL 42501, permission denied for function place_order
```

In the browser, check the preflight and a successful write with a fresh token. In the gate test,
resubmit a used token and confirm a `403` and no new row. Check CSP in the console and with
`scripts/csp_scan.mjs` for inline code.

On the `scripts/pg-harness/` harness, add this check to a scenario after preparing a valid order.
It covers SQL permissions; real token verification is covered by the gate test.

```js
async function checkOrderGate(h, validOrder) {
  const sql = "select * from public.place_order($1::jsonb)";
  const args = [JSON.stringify(validOrder)];
  await h.rejects(h.asAnon(sql, args), /permission denied/);
  const uid = await h.createUser({ email: "customer@example.com" });
  await h.rejects(h.asUser(uid, sql, args), /permission denied/);
  const result = await h.asService(sql, args);
  h.assert.ok(result.rows[0]?.id); // adapt to your RPC's result
}
```

Call `await checkOrderGate(h, validOrder)` from `export default async function (h)`. Run with the
full migration order and `--twice` for the lock file.

```bash
node "$HARNESS/harness.mjs" --repo "$PROJECT" --scenario "$CHECKS" --twice turnstile_lock.sql
```

`HARNESS` is a prepared copy of `scripts/pg-harness/` after `sh setup.sh`, `PROJECT` is the project
directory, `CHECKS` is the scenario path. If the order in DEPLOY.md isn't recognized, pass
`--migrations` with a comma-separated list of files.
