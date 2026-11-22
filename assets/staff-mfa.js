/* Staff two-factor sign-in: password + a code from an authenticator app (TOTP, Supabase MFA).
   StaffMFA.ensure(sb, mount, { onSignOut, issuer }) → Promise<boolean>:
   mount — the container (may contain a .card), issuer — the name shown in the authenticator app.
   true — the session is confirmed with a code (aal2), false — verification failed.
   First sign-in: shows a QR code for Google Authenticator / Authy and asks for a code.
   After that: asks only for the 6-digit code. */
(() => {
  'use strict';

  let ISSUER = 'Website';
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c =>
    ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]));

  function codeForm(intro) {
    return `
      ${intro}
      <label for="mfaCode">Code from the app</label>
      <input id="mfaCode" inputmode="numeric" autocomplete="one-time-code" maxlength="6"
             pattern="[0-9]{6}" placeholder="000000"
             style="text-align:center;letter-spacing:8px;font-size:22px">
      <button id="mfaOk" style="width:100%;margin-top:14px">Confirm</button>
      <button id="mfaOut" class="ghost" style="width:100%;margin-top:10px">Sign out</button>
      <div id="mfaMsg" class="msg" role="alert"></div>`;
  }

  function wire(mount, factorId, sb, done, onSignOut) {
    const input = mount.querySelector('#mfaCode');
    const btn = mount.querySelector('#mfaOk');
    const msg = mount.querySelector('#mfaMsg');
    let busy = false;
    async function submit() {
      const code = input.value.replace(/\D/g, '');
      if (code.length !== 6) { msg.textContent = 'Enter the 6 digits from the app.'; input.focus(); return; }
      if (busy) return;
      busy = true; btn.disabled = true; msg.textContent = 'Checking…';
      const { error } = await sb.auth.mfa.challengeAndVerify({ factorId, code });
      busy = false; btn.disabled = false;
      if (error) {
        msg.textContent = /invalid|expired/i.test(error.message)
          ? 'Wrong or expired code. Wait for a new code and try again.'
          : /rate|too many/i.test(error.message)
            ? 'Too many attempts. Please wait a minute.'
            : 'Something went wrong: ' + error.message;
        input.select();
        return;
      }
      msg.textContent = '';
      done();
    }
    btn.onclick = submit;
    input.addEventListener('input', () => {
      input.value = input.value.replace(/\D/g, '').slice(0, 6);
      if (input.value.length === 6) submit();
    });
    input.addEventListener('keydown', e => { if (e.key === 'Enter') submit(); });
    mount.querySelector('#mfaOut').onclick = () => onSignOut?.();
    input.focus();
  }

  function showError(mount, text, onSignOut) {
    mount.innerHTML = `<h1>Sign in with a code</h1>
      <div class="msg" role="alert" style="margin-top:8px">${esc(text)}</div>
      <button id="mfaOut" class="ghost" style="width:100%;margin-top:14px">Sign out</button>`;
    mount.querySelector('#mfaOut').onclick = () => onSignOut?.();
  }

  async function ensure(sb, mount, { onSignOut, issuer } = {}) {
    if (issuer) ISSUER = String(issuer);
    const card = mount.querySelector('.card') || mount;
    const { data: aal, error } = await sb.auth.mfa.getAuthenticatorAssuranceLevel();
    if (error) { mount.classList.remove('hide'); showError(card, 'Could not verify the sign-in: ' + error.message, onSignOut); return false; }
    if (aal.currentLevel === 'aal2') { mount.classList.add('hide'); return true; }

    const { data: factors, error: listError } = await sb.auth.mfa.listFactors();
    if (listError) { mount.classList.remove('hide'); showError(card, 'Could not verify the sign-in: ' + listError.message, onSignOut); return false; }
    mount.classList.remove('hide');

    return new Promise(resolve => {
      const done = () => { mount.classList.add('hide'); card.innerHTML = ''; resolve(true); };
      const verified = (factors.totp || []).find(f => f.status === 'verified');

      if (verified) {
        card.innerHTML = `<h1>Code from the app</h1>` +
          codeForm(`<div class="who" style="margin:6px 0 4px">Open your authenticator app and enter the code for “${ISSUER}”.</div>`);
        wire(card, verified.id, sb, done, onSignOut);
        return;
      }

      (async () => {
        // Unfinished earlier enrollment attempts block a new one — remove them.
        const stale = (factors.all || []).filter(f => f.factor_type === 'totp' && f.status !== 'verified');
        for (const f of stale) await sb.auth.mfa.unenroll({ factorId: f.id });

        const { data, error: enrollError } = await sb.auth.mfa.enroll({
          factorType: 'totp',
          issuer: ISSUER,
          friendlyName: ISSUER + ' ' + new Date().toISOString().slice(0, 16).replace('T', ' '),
        });
        if (enrollError) { showError(card, 'Could not enable code sign-in: ' + enrollError.message, onSignOut); resolve(false); return; }

        const qr = String(data.totp?.qr_code || '');
        const secret = String(data.totp?.secret || '');
        card.innerHTML = `<h1>Protect your sign-in</h1>
          <div class="who" style="margin:6px 0 10px">Link your phone once — after that, signing in will require a code from the app.</div>
          <ol style="margin:0 0 10px 18px;padding:0;font-size:14px;line-height:1.5">
            <li>Install Google Authenticator, Authy or another authenticator app.</li>
            <li>Scan the QR code in the app.</li>
            <li>Enter the 6-digit code below.</li>
          </ol>
          ${/^data:image\/svg\+xml/.test(qr) ? `<img src="${esc(qr)}" alt="QR code for the authenticator app" width="200" height="200"
              style="display:block;margin:6px auto;background:#fff;border-radius:12px;padding:8px">` : ''}
          <div class="who" style="text-align:center;margin-bottom:6px">Can’t scan it? Enter the key manually:<br>
            <code style="user-select:all;word-break:break-all;font-size:13px">${esc(secret)}</code></div>` +
          codeForm('');
        wire(card, data.id, sb, done, onSignOut);
      })();
    });
  }

  window.StaffMFA = { ensure };
})();
