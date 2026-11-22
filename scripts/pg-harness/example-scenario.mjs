// Example scenario for harness.mjs. Copy it next to the project and replace tables/functions with yours.
// Run: node harness.mjs --repo <project> --scenario ./checks.mjs
//
// h.q(sql, params)                   — as postgres (superuser, for preparing data)
// h.asAnon(sql, params)              — as the site without sign-in (anon key)
// h.asUser(uid, sql, params, claims) — as a signed-in user; default claims { aal: 'aal1' }
// h.asService(sql, params)           — as an Edge Function with service_role
// h.createUser({ email, phone })     — a row in auth.users, returns its uuid
// h.rejects(promise, /regex/)        — expect an error
// h.assert                           — node:assert/strict
export default async function (h) {
  // 1) An anonymous visitor can't read other people's orders directly. In Supabase anon has GRANTs
  //    on public tables, so RLS usually yields "0 rows" rather than an error. You only get
  //    "permission denied" if the rights were revoked.
  const seen = await h.asAnon('select count(*)::int n from public.orders');
  h.assert.equal(seen.rows[0].n, 0, 'anon can see orders');
  h.log('orders are not visible to anon');

  // 2) Ordering through the RPC: the server computes the price, not the client
  const menu = (await h.q(`select id, price from public.menu_items where available limit 1`)).rows[0];
  const r = await h.asAnon('select * from public.place_order($1::jsonb)', [JSON.stringify({
    phone: '+1 555 000 0001', name: 'Test', address: '1 Main St',
    items: [{ id: menu.id, qty: 2, price: 1 }], // a forged price must be ignored
  })]);
  const row = (await h.q('select total from public.orders where id = $1', [r.rows[0].id])).rows[0];
  h.assert.equal(Number(row.total), Number(menu.price) * 2, 'the server accepted the client price');
  h.log('the server computes the total');

  // 3) A retry with the same client_key does not create a second order (idempotency)
  // 4) Rate limit: the 4th order from one phone within 10 minutes is rejected
  // 5) Staff without 2FA (aal1) can't see orders; with aal2 they can
  const staff = await h.createUser({ email: 'op@example.com' });
  await h.q(`insert into public.staff (id, name, role) values ($1, 'Operator', 'operator')`, [staff]);
  const aal1 = await h.asUser(staff, 'select count(*)::int n from public.orders');
  const aal2 = await h.asUser(staff, 'select count(*)::int n from public.orders', [], { aal: 'aal2' });
  h.assert.equal(aal1.rows[0].n, 0, 'data is visible without the 2FA code');
  h.assert.ok(aal2.rows[0].n > 0);
  h.log('orders are visible to staff only after 2FA');
}
