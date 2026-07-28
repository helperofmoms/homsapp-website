function json(data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: { 'content-type': 'application/json' }
  });
}

async function getList(env, key) {
  const raw = await env.PARTNERS_KV.get(key);
  return raw ? JSON.parse(raw) : [];
}

async function setList(env, key, list) {
  await env.PARTNERS_KV.put(key, JSON.stringify(list));
}

// ---------------------------------------------------------------------------
// Auth: Google Sign-In (session cookie) + legacy ADMIN_TOKEN as a fallback.
// ---------------------------------------------------------------------------

function base64UrlEncode(bytes) {
  let str = '';
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function hmacSign(message, secret) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return base64UrlEncode(new Uint8Array(sig));
}

function getCookie(request, name) {
  const cookieHeader = request.headers.get('Cookie') || '';
  const match = cookieHeader.match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
  return match ? decodeURIComponent(match[1]) : null;
}

function allowedAdminEmails(env) {
  return (env.ALLOWED_ADMIN_EMAILS || '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

async function createSessionCookie(email, env) {
  const expires = Date.now() + 1000 * 60 * 60 * 24 * 7; // 7 days
  const payload = base64UrlEncode(new TextEncoder().encode(JSON.stringify({ email, expires })));
  const sig = await hmacSign(payload, env.SESSION_SECRET);
  return payload + '.' + sig;
}

async function verifySessionCookie(cookieValue, env) {
  if (!cookieValue || cookieValue.indexOf('.') === -1) return null;
  const parts = cookieValue.split('.');
  const payload = parts[0];
  const sig = parts[1];
  const expectedSig = await hmacSign(payload, env.SESSION_SECRET);
  if (sig !== expectedSig) return null;
  try {
    const data = JSON.parse(new TextDecoder().decode(base64UrlDecode(payload)));
    if (!data.expires || Date.now() > data.expires) return null;
    return data.email;
  } catch (err) {
    return null;
  }
}

async function isSessionValid(request, env) {
  if (!env.SESSION_SECRET) return false;
  const cookie = getCookie(request, 'homs_admin_session');
  const email = await verifySessionCookie(cookie, env);
  if (!email) return false;
  return allowedAdminEmails(env).includes(email.toLowerCase());
}

async function isAdmin(request, env, body) {
  const url = new URL(request.url);
  const token = url.searchParams.get('token') || (body && body.token) || request.headers.get('x-admin-token');
  if (token && env.ADMIN_TOKEN && token === env.ADMIN_TOKEN) return true;
  return isSessionValid(request, env);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      // -----------------------------------------------------------------
      // Google Sign-In: login kickoff, callback, logout.
      // -----------------------------------------------------------------
      if (url.pathname === '/auth/google/login' && request.method === 'GET') {
        const state = base64UrlEncode(crypto.getRandomValues(new Uint8Array(16)));
        const redirectUri = url.origin + '/auth/google/callback';
        const params = new URLSearchParams({
          client_id: env.GOOGLE_CLIENT_ID,
          redirect_uri: redirectUri,
          response_type: 'code',
          scope: 'openid email',
          state: state,
          prompt: 'select_account'
        });
        const headers = new Headers({
          Location: 'https://accounts.google.com/o/oauth2/v2/auth?' + params.toString()
        });
        headers.append(
          'Set-Cookie',
          'homs_oauth_state=' + state + '; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600'
        );
        return new Response(null, { status: 302, headers });
      }

      if (url.pathname === '/auth/google/callback' && request.method === 'GET') {
        const code = url.searchParams.get('code');
        const state = url.searchParams.get('state');
        const savedState = getCookie(request, 'homs_oauth_state');

        if (!code || !state || !savedState || state !== savedState) {
          return new Response('Login failed: invalid or expired login attempt. Please try again.', { status: 400 });
        }

        const redirectUri = url.origin + '/auth/google/callback';
        const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            code: code,
            client_id: env.GOOGLE_CLIENT_ID,
            client_secret: env.GOOGLE_CLIENT_SECRET,
            redirect_uri: redirectUri,
            grant_type: 'authorization_code'
          })
        });

        if (!tokenRes.ok) {
          return new Response('Login failed: could not verify with Google. Please try again.', { status: 400 });
        }

        const tokenData = await tokenRes.json();
        const idToken = tokenData.id_token;
        if (!idToken) {
          return new Response('Login failed: Google did not return an identity token.', { status: 400 });
        }

        const claimsPart = idToken.split('.')[1];
        const claims = JSON.parse(new TextDecoder().decode(base64UrlDecode(claimsPart)));
        const email = (claims.email || '').toLowerCase();

        if (!claims.email_verified || !allowedAdminEmails(env).includes(email)) {
          return new Response(
            'Access denied. The Google account "' + email + '" is not authorized for HOMs admin.',
            { status: 403 }
          );
        }

        const sessionCookie = await createSessionCookie(email, env);
        const headers = new Headers({ Location: '/admin-pending-partners.html' });
        headers.append(
          'Set-Cookie',
          'homs_admin_session=' + sessionCookie + '; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800'
        );
        headers.append(
          'Set-Cookie',
          'homs_oauth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0'
        );
        return new Response(null, { status: 302, headers });
      }

      if (url.pathname === '/auth/logout') {
        const headers = new Headers({ Location: '/auth/google/login' });
        headers.append(
          'Set-Cookie',
          'homs_admin_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0'
        );
        return new Response(null, { status: 302, headers });
      }

      if (url.pathname === '/api/submit-partner' && request.method === 'POST') {
        const submission = await request.json();
        submission.id = submission.id || ('partner_' + Date.now());
        submission.status = 'pending';
        submission.submittedAt = submission.submittedAt || new Date().toISOString();

        const pending = await getList(env, 'pending');
        pending.push(submission);
        await setList(env, 'pending', pending);

        return json({ ok: true, id: submission.id });
      }

      if (url.pathname === '/api/admin/data' && request.method === 'GET') {
        if (!(await isAdmin(request, env))) return json({ error: 'unauthorized' }, 401);
        const [pending, approved, activated] = await Promise.all([
          getList(env, 'pending'),
          getList(env, 'approved'),
          getList(env, 'activated')
        ]);
        return json({ pending, approved, activated });
      }

      if (url.pathname === '/api/admin/approve' && request.method === 'POST') {
        const body = await request.json();
        if (!(await isAdmin(request, env, body))) return json({ error: 'unauthorized' }, 401);

        const pending = await getList(env, 'pending');
        const idx = pending.findIndex((p) => p.id === body.id);
        if (idx === -1) return json({ error: 'not found' }, 404);

        const [item] = pending.splice(idx, 1);
        item.status = 'approved';
        item.billingStatus = 'awaiting_payment';
        item.approvedAt = new Date().toISOString();

        await setList(env, 'pending', pending);
        const approved = await getList(env, 'approved');
        approved.push(item);
        await setList(env, 'approved', approved);

        return json({ ok: true, item });
      }

      if (url.pathname === '/api/admin/reject' && request.method === 'POST') {
        const body = await request.json();
        if (!(await isAdmin(request, env, body))) return json({ error: 'unauthorized' }, 401);

        const pending = await getList(env, 'pending');
        const idx = pending.findIndex((p) => p.id === body.id);
        if (idx === -1) return json({ error: 'not found' }, 404);

        pending.splice(idx, 1);
        await setList(env, 'pending', pending);

        return json({ ok: true });
      }

      if (url.pathname === '/api/admin/mark-paid' && request.method === 'POST') {
        const body = await request.json();
        if (!(await isAdmin(request, env, body))) return json({ error: 'unauthorized' }, 401);

        const approved = await getList(env, 'approved');
        const idx = approved.findIndex((p) => p.id === body.id);
        if (idx === -1) return json({ error: 'not found' }, 404);

        const [item] = approved.splice(idx, 1);
        item.billingStatus = 'active';
        item.activatedAt = new Date().toISOString();

        await setList(env, 'approved', approved);
        const activated = await getList(env, 'activated');
        activated.push(item);
        await setList(env, 'activated', activated);

        return json({ ok: true, item });
      }

      // NOTE: the one-time /api/admin/mirror-logo migration endpoint used to
      // pull the 14 partner logos off GoDaddy into LOGOS_KV has been removed
      // now that the migration is complete, to minimize the admin API's
      // attack surface. Logos are still served below from LOGOS_KV.

      // Kill-switch service worker: homsapp.com used to run GoDaddy's
      // Website Builder, which registers a Workbox service worker
      // (scope "/") in every visitor's browser. That old worker is still
      // active in returning visitors' browsers and intercepts requests
      // (including images) with its own stale Cache Storage, which is why
      // some visitors still see broken images even though the new site
      // serves everything correctly. Serving a real /sw.js here lets
      // browsers pick up "an update" to the worker they already have
      // installed; this version immediately clears all caches and
      // unregisters itself, then reloads any open tabs, so the browser
      // goes back to loading everything fresh from the network.
      if (url.pathname === '/sw.js' && request.method === 'GET') {
        const killSwitch = `
self.addEventListener('install', () => { self.skipWaiting(); });
self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.map((k) => caches.delete(k)));
    await self.registration.unregister();
    const clientsList = await self.clients.matchAll({ type: 'window' });
    for (const client of clientsList) {
      client.navigate(client.url);
    }
  })());
});
`;
        return new Response(killSwitch, {
          headers: {
            'content-type': 'application/javascript',
            'cache-control': 'no-cache, no-store, must-revalidate'
          }
        });
      }

      if (url.pathname.startsWith('/partner-logos/') && request.method === 'GET') {
        const filename = url.pathname.replace('/partner-logos/', '');
        const obj = await env.LOGOS_KV.getWithMetadata(filename, 'arrayBuffer');
        if (!obj || !obj.value) return new Response('Not found', { status: 404 });

        const contentType = (obj.metadata && obj.metadata.contentType) || 'application/octet-stream';
        return new Response(obj.value, {
          headers: {
            'content-type': contentType,
            'cache-control': 'public, max-age=86400'
          }
        });
      }
    } catch (err) {
      return json({ error: 'server error', message: String(err) }, 500);
    }

    // admin.homsapp.com should land directly on the admin review page,
    // not the marketing homepage. All /api/* and /auth/* routes above are
    // unaffected since they're matched before this point regardless of
    // hostname. Both entry points require a valid Google session before the
    // admin HTML is served.
    const isAdminPageRequest =
      url.pathname === '/admin-pending-partners.html' ||
      (url.hostname === 'admin.homsapp.com' && url.pathname === '/');

    if (isAdminPageRequest && request.method === 'GET') {
      const valid = await isSessionValid(request, env);
      if (!valid) {
        return Response.redirect(url.origin + '/auth/google/login', 302);
      }
      if (url.hostname === 'admin.homsapp.com' && url.pathname === '/') {
        const assetUrl = new URL(request.url);
        assetUrl.pathname = '/admin-pending-partners.html';
        return env.ASSETS.fetch(new Request(assetUrl, request));
      }
    }

    return env.ASSETS.fetch(request);
  }
};
