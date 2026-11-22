# CSP and SRI for a static site

Goal: the browser loads JavaScript only from explicitly allowed sources, blocks executable inline
scripts and HTML event handlers, and verifies CDN files by hash. CSP reduces XSS risk. Keep
inserting dynamic data with `textContent` and DOM APIs, or escape it for its context. Check data
access permissions in Supabase per `references/supabase-audit.md`.

## Contents

- [Target policy](#target-policy)
- [Migration and rollout](#migration-and-rollout)
- [CDN and SRI](#cdn-and-sri)
- [Other headers](#other-headers)
- [Pitfalls](#pitfalls)
- [How to verify](#how-to-verify)

## Target policy

Example `vercel.json` for a site with Supabase, Leaflet, Google Fonts and Turnstile.
Put in your own `<project-ref>`. Remove sources for components you don't use.

```json
{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        {
          "key": "Content-Security-Policy",
          "value": "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; script-src 'self' https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2.118.0/ https://unpkg.com/leaflet@1.9.4/ https://challenges.cloudflare.com; script-src-attr 'none'; style-src 'self' 'unsafe-inline' https://unpkg.com/leaflet@1.9.4/ https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https://tile.openstreetmap.org https://*.tile.openstreetmap.org https://unpkg.com/leaflet@1.9.4/; frame-src https://challenges.cloudflare.com; connect-src https://<project-ref>.supabase.co wss://<project-ref>.supabase.co; form-action 'self'; upgrade-insecure-requests"
        },
        { "key": "X-Frame-Options", "value": "DENY" },
        { "key": "X-Content-Type-Options", "value": "nosniff" },
        { "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" },
        { "key": "Permissions-Policy", "value": "geolocation=(self), camera=(), microphone=(), payment=()" },
        { "key": "Strict-Transport-Security", "value": "max-age=31536000" }
      ]
    },
    {
      "source": "/track.html",
      "headers": [
        { "key": "Cache-Control", "value": "no-store" },
        { "key": "Referrer-Policy", "value": "no-referrer" }
      ]
    }
  ]
}
```

| Directive | Why |
|---|---|
| `default-src 'self'` | Fallback for resource types without their own directive. An explicit directive replaces this list entirely. |
| `base-uri 'none'` | Forbids `<base>`, which changes how relative URLs resolve. |
| `frame-ancestors 'none'` | Forbids embedding the site's pages in a frame. Must be sent as an HTTP header. |
| `object-src 'none'` | Forbids loading via `<object>` and `<embed>`. |
| `script-src` | Allows local JS, the listed CDN directories and the Turnstile SDK. Without `'unsafe-inline'` it blocks executable inline scripts; without `'unsafe-eval'` it blocks compiling JS from strings. |
| `script-src-attr 'none'` | Blocks `onclick`, `onchange`, `onerror` and every other HTML handler attribute, including ones inserted after page load. |
| `style-src` | Allows local CSS, map CSS and Google Fonts. `'unsafe-inline'` is kept for `<style>`, `style=` attributes and libraries that create them. It only affects styles. |
| `font-src` | Allows font files from the site and `fonts.gstatic.com`. Google Fonts CSS loads under `style-src` from a different host. |
| `img-src` | Allows local images, `data:` for inline images, map tiles and Leaflet icons from its CSS. Keep only the tile hosts you actually use. Add your Supabase Storage origin here if you serve images from it. |
| `frame-src` | Allows the Turnstile iframe. Pages without external frames can use `'none'`. |
| `connect-src` | HTTPS is needed for Auth, REST, RPC and Edge Functions; WSS for Realtime. If the site `fetch`es its own origin, add `'self'`. |
| `form-action 'self'` | Restricts HTML form submission to your origin. `fetch` requests are governed by `connect-src`. |
| `upgrade-insecure-requests` | Upgrades insecure resource URLs to HTTPS. If a source doesn't serve HTTPS, loading still fails. |

The `default-src` fallback does not cover `base-uri`, `frame-ancestors` or `form-action`.
To tighten CSS as well, move `<style>` into files, replace `style=` with classes and check the
map, popups and animations. Assigning individual properties via `element.style` and setting the
whole `style` attribute behave differently under CSP.
[CSP specification](https://w3c.github.io/webappsec-csp/)

Turnstile needs `https://challenges.cloudflare.com` in both `script-src` and `frame-src`. In
pre-clearance mode, add `'self'` to `connect-src` for the request to `/cdn-cgi/`. Server-side
token verification from `assets/turnstile-gate.ts` happens in the Edge Function; the page's CSP
does not affect it.
[Cloudflare Turnstile and CSP](https://developers.cloudflare.com/turnstile/reference/content-security-policy/)

## Migration and rollout

1. **Take a baseline.** From the skill root, run:

   ```sh
   node scripts/csp_scan.mjs /path/to/site
   node scripts/csp_scan.mjs /path/to/site --json
   ```

   Exit code 1 means blocking findings. Review CDN warnings separately. The scanner is heuristic
   and skips tests and several output directories, including `dist`. If you publish a build,
   pass its directory explicitly. Manually check import maps, dynamically created scripts and
   HTML produced by templates.

2. **Move executable `<script>…</script>` blocks out.** Put the code into per-page files —
   `admin.js`, `track.js` and so on. Keep the load order. For example, at the end of `<body>`,
   dependencies and config first, then the page code:

   ```html
   <script src="./config.js"></script>
   <script src="./admin.js"></script>
   ```

   If you move classic scripts into `<head>`, give every link in the chain `defer` in the right
   order. `async` does not guarantee order. When switching to `type="module"`, check explicit
   imports and references to globals.

3. **Remove HTML event handlers.** Check pages and strings that end up in `innerHTML` or
   `insertAdjacentHTML`. In templates replace `onclick` with `data-act` and `data-id`, and
   `onchange` with `data-filter` plus a `change` listener. `setAttribute('onclick', '...')`
   creates the same forbidden attribute. A function passed to `addEventListener` comes from
   allowed JS and is fine.

4. **Delegate events to a stable container.** Buttons inside the container can be re-rendered
   with `innerHTML`. The listener stays on the container, and `closest` finds the button even when
   a nested icon is clicked.

   ```html
   <section id="orders">
     <article data-order>
       <button type="button" data-act="details" data-id="42">Details</button>
       <p data-details hidden>Order accepted</p>
     </article>
   </section>
   ```

   ```js
   // admin.js
   const orders = document.querySelector('#orders');
   orders.addEventListener('click', event => {
     const button = event.target instanceof Element
       ? event.target.closest('button[data-act="details"]')
       : null;
     if (!button || !orders.contains(button)) return;

     const details = button.closest('[data-order]')?.querySelector('[data-details]');
     if (details) details.hidden = !details.hidden;
   });
   ```

   For several actions use explicit branches on `dataset.act`. When calling an RPC, validate
   `dataset.id` and check permissions on the server. Image `error` events need the capture
   phase. Install the listener before the first render of the cards:

   ```js
   document.addEventListener('error', event => {
     const image = event.target;
     if (!(image instanceof HTMLImageElement)) return;
     const media = image.parentElement;
     if (!media?.matches('.card-media')) return;
     media.classList.add('no-image'); // the class shows a placeholder
     image.remove();
   }, { capture: true });
   ```

5. **Replace `javascript:` URLs and string execution.** Use `<button type="button">` for actions
   and a normal `href` for navigation. Check URLs assigned from data and allow only the schemes
   and origins you need. Use `JSON.parse` instead of `eval` for JSON, and `setTimeout(refresh, 1000)`
   instead of a string timer. If a dependency calls `new Function`, pick a build without string
   compilation or replace the dependency.

6. **Pin CDN files and add SRI.** For every third-party JS/CSS with fixed content, follow the
   section below and run the scanner again. Also reconcile dynamic loaders with `script-src`.

7. **Turn on observation.** On a preview deploy, send the target policy as
   `Content-Security-Policy-Report-Only`. If a blocking policy already exists, keep it as a
   separate header. Walk through every page and flow. Configure `Reporting-Endpoints` and
   `report-to` only if you have a collector. Check which URLs and data fragments end up in
   reports before enabling collection on pages with tokens.

8. **Turn on enforcement.** Test the target CSP as `Content-Security-Policy` on preview. Ship the
   headers together with the HTML, the external JS and current SRI hashes. After the switch,
   check the production headers and flows. On a regression, roll back the whole coordinated
   deploy, policy included.

## CDN and SRI

Pin the full version in the file URL and restrict the source to the version directory in CSP,
e.g. `https://cdn.jsdelivr.net/npm/pkg@1.2.3/`. The trailing `/` makes it a path prefix. The path
restriction narrows what's allowed on the CDN, and SRI verifies the bytes of the specific file.
After an HTTP redirect, CSP path matching is relaxed for the next hop, so use the final URL
with no redirect.

From the skill root, get the attributes for each exact URL:

```sh
sh scripts/sri.sh \
  'https://unpkg.com/leaflet@1.9.4/dist/leaflet.js' \
  'https://unpkg.com/leaflet@1.9.4/dist/leaflet.css'
```

```html
<link rel="stylesheet"
      href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"
      integrity="sha384-sHL9NAb7lN7rfvG5lfHpm643Xkcjzp4jFvuavGOndn6pjVqS6ny56CAt3nsEVT4H"
      crossorigin="anonymous">
<script defer
        src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"
        integrity="sha384-cxOPjt7s7Iz04uaHJceBmS+qpjv2JkIHNVcuOrM+YHwZOmJGBXI00mdUXEq65HTH"
        crossorigin="anonymous"></script>
```

The script prints SHA-384. Make sure the download succeeded: a `curl` failure inside the pipe
can leave you with the hash of empty input. Cross-origin SRI needs the CDN to send
`Access-Control-Allow-Origin` and the tag to have `crossorigin="anonymous"`. The hash covers the
resource itself; its imports, fonts and images need their own load rules. When upgrading,
change the URL, the CSP path and the SRI hash together on every page.
[SRI specification](https://w3c.github.io/webappsec-subresource-integrity/)

Load Turnstile from its official URL. The provider updates the SDK, so a pinned hash would break
loading after an update. Google Fonts CSS may differ by User-Agent; if you need fixed bytes,
self-host the CSS and font files.
[Loading the Turnstile SDK](https://developers.cloudflare.com/turnstile/get-started/client-side-rendering/)

## Other headers

- **HSTS** makes the browser use HTTPS for the domain after it first receives the header over
  HTTPS. Add `includeSubDomains` once HTTPS works on subdomains. `preload` is a separate decision
  and requires submitting the domain to the browsers' list.
- **X-Frame-Options: DENY** duplicates the framing ban for old browsers. Keep it consistent with
  `frame-ancestors`.
- **X-Content-Type-Options: nosniff** requires correct MIME types for JS and CSS. Make sure a
  script request doesn't get HTML from a fallback route.
- **Referrer-Policy: strict-origin-when-cross-origin** sends only the origin on cross-origin HTTPS
  navigations. On pages with tokens use `no-referrer` and `Cache-Control: no-store`, including
  aliases and clean URLs. If the flow allows `/track.html#t=…`, the fragment isn't sent in the
  HTTP request, but client JS still sees it. Keep tokens out of analytics and reports.
- **Permissions-Policy** disables APIs you don't need. `geolocation=(self)` suits a page that
  uses geolocation; `geolocation=()` a page that doesn't.

## Pitfalls

- `onclick` handlers lived in card templates that only appear after data loads. Searching static
  markup misses them. Open the panel, wait for data, refresh the list and click a nested element
  of a button. Attach delegation to a container that survives re-rendering.
- A fallback image was set via `onerror` in a template string. Under a strict CSP that handler
  never shows the placeholder. Ordinary bubbling doesn't help, because `error` on an image does
  not bubble.
- A dependency was added via `document.createElement('script')`. Checking only HTML tags missed
  the loader. Search for `src` assignments, `import()` and lazy-loading branches.
- A tracking link carried the token in the query string. Moving it to the fragment removed it
  from the page's HTTP requests. Keep `no-store` and `no-referrer` anyway and check every public
  URL of the page.

## How to verify

1. **Locally.** Run `node tests/serve.mjs 8780` if the project already has such a server. For
   your own server follow the same idea: read `vercel.json`, apply the matching rules to the
   request URL and serve the file with the right `Content-Type`. For local HTTP, drop HSTS and
   `upgrade-insecure-requests` from the local response. Apply rules to the URL before
   `index.html` substitution and check per-route overrides. For the rules in the example:

   ```js
   import { readFileSync } from 'node:fs';

   const { headers: rules } = JSON.parse(readFileSync('vercel.json', 'utf8'));
   function headersFor(pathname) {
     const headers = {};
     for (const rule of rules) {
       if (rule.source !== '/(.*)' && rule.source !== pathname) continue;
       for (const { key, value } of rule.headers) headers[key.toLowerCase()] = value;
     }
     delete headers['strict-transport-security'];
     for (const name of ['content-security-policy', 'content-security-policy-report-only']) {
       if (headers[name]) {
         headers[name] = headers[name].split(';')
           .filter(part => part.trim() !== 'upgrade-insecure-requests').join(';');
       }
     }
     return headers;
   }
   // Pass headersFor(url.pathname) to res.writeHead along with the MIME type.
   ```

   ```sh
   curl -fsS -D - -o /dev/null http://127.0.0.1:8780/
   curl -fsS -D - -o /dev/null http://127.0.0.1:8780/track.html
   curl -fsS -D - -o /dev/null http://127.0.0.1:8780/admin.js
   ```

2. **In a browser under the enforcing CSP.** Open Console and Network, disable the cache and
   reload. Check sign-in and MFA, buttons after re-rendering, filter changes, a failing photo, the
   map and its icons, fonts, Turnstile, a request to an RPC or Edge Function, and Realtime over
   WSS. In Playwright tests, attach a `securitypolicyviolation` listener via `page.addInitScript`
   before navigation and record `effectiveDirective` and `blockedURI`. On a local copy, briefly
   add a test inline `<script>` and an `onclick` button that change the page text; under the
   enforcing policy the text must not change. Likewise, plug in a wrong SRI hash and confirm the
   integrity error in the Console.

3. **On Vercel.** Check the real HTTPS response, the final URL after redirects, aliases, and token
   pages without a real token in the URL. The local server reproduces simple rules; check routing
   and CDN headers against the actual response.

   ```sh
   curl -fsS -D - -o /dev/null https://my-site.vercel.app/
   curl -fsS -D - -o /dev/null https://my-site.vercel.app/track.html
   ```

4. **External check.** If external requests are allowed, check the public URL (without a token)
   with [Security Headers](https://securityheaders.com/). Paste the policy string into
   [CSP Evaluator](https://csp-evaluator.withgoogle.com/). It may flag allowed CDNs or `'self'`,
   since trusted sources can also serve executable content. Remove unnecessary allowances and
   confirm the flows in a browser.
