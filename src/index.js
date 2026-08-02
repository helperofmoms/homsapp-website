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

const PARTNER_TYPES = ['ep', 'rp'];
const STAGES = ['pending', 'updated', 'approved', 'activated', 'declined'];

function listKey(type, stage) {
  return type + '_' + stage;
}

function addBusinessDays(startDate, n) {
  const date = new Date(startDate);
  let added = 0;
  while (added < n) {
    date.setDate(date.getDate() + 1);
    const day = date.getDay();
    if (day !== 0 && day !== 6) added++;
  }
  return date;
}

function validTypeStage(type, stage) {
  return PARTNER_TYPES.indexOf(type) !== -1 && STAGES.indexOf(stage) !== -1;
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
      if (url.pathname === '/auth/google/start' && request.method === 'GET') {
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
        const headers = new Headers({ Location: '/admin-login.html' });
        headers.append(
          'Set-Cookie',
          'homs_admin_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0'
        );
        return new Response(null, { status: 302, headers });
      }

      if (url.pathname === '/api/partner/social-request' && request.method === 'POST') {
        const b = await request.json();
        if (!b.message) return json({ error: 'nothing to post' }, 400);
        const entry = {
          id: 'sp_' + Date.now(),
          message: b.message,
          link: b.link || '',
          platforms: Array.isArray(b.platforms) ? b.platforms : [],
          postAfter: b.postAfter || '',
          partnerType: b.partnerType || '',
          partnerName: b.partnerName || '',
          status: 'requested',
          submittedAt: new Date().toISOString()
        };
        entry.photos = [];
        const incoming = Array.isArray(b.photos) ? b.photos.slice(0, 3) : [];
        for (let i = 0; i < incoming.length; i++) {
          const ph = incoming[i];
          if (!ph || !ph.dataUrl || !ph.name) continue;
          const m = /^data:([^;]+);base64,(.*)$/.exec(ph.dataUrl);
          if (!m) continue;
          const bin = atob(m[2]);
          const bytes = new Uint8Array(bin.length);
          for (let k = 0; k < bin.length; k++) bytes[k] = bin.charCodeAt(k);
          const safe = ph.name.replace(/[^A-Za-z0-9._-]/g, '_');
          const photoKey = 'social_' + entry.id + '_' + i + '_' + safe;
          await env.LOGOS_KV.put(photoKey, bytes.buffer, { metadata: { contentType: m[1] } });
          entry.photos.push({ name: ph.name, key: photoKey });
        }
        const list = await getList(env, 'inbox_social');
        list.push(entry);
        await setList(env, 'inbox_social', list);
        return json({ ok: true, id: entry.id });
      }

      if (url.pathname === '/api/partner/feedback' && request.method === 'POST') {
        const b = await request.json();
        const entry = {
          id: 'fb_' + Date.now(),
          sentiments: Array.isArray(b.sentiments) ? b.sentiments : (b.sentiment ? [b.sentiment] : []),
          topic: b.topic || '',
          note: b.note || '',
          partnerType: b.partnerType || '',
          partnerName: b.partnerName || '',
          status: 'new',
          submittedAt: new Date().toISOString()
        };
        if (!entry.sentiments.length && !entry.note) return json({ error: 'empty feedback' }, 400);
        const list = await getList(env, 'inbox_feedback');
        list.push(entry);
        await setList(env, 'inbox_feedback', list);
        return json({ ok: true, id: entry.id });
      }

      if (url.pathname === '/api/partner/support' && request.method === 'POST') {
        const b = await request.json();
        if (!b.topic || !b.summary || !b.details) return json({ error: 'missing required fields' }, 400);
        const now = new Date();
        const entry = {
          id: 'tk_' + Date.now(),
          topic: b.topic,
          summary: b.summary,
          details: b.details,
          grantAccess: !!b.grantAccess,
          accessExpiresAt: b.grantAccess ? addBusinessDays(now, 7).toISOString() : null,
          accessLog: [],
          appVersion: b.appVersion || '',
          device: b.device || '',
          partnerType: b.partnerType || '',
          partnerName: b.partnerName || '',
          contactEmail: b.contactEmail || '',
          status: 'open',
          submittedAt: now.toISOString()
        };
        const list = await getList(env, 'inbox_support');
        list.push(entry);
        await setList(env, 'inbox_support', list);
        return json({ ok: true, id: entry.id });
      }

      if (url.pathname === '/api/admin/inbox' && request.method === 'GET') {
        if (!await isAdmin(request, env)) return json({ error: 'unauthorized' }, 401);
        const feedback = await getList(env, 'inbox_feedback');
        const support = await getList(env, 'inbox_support');
        const social = await getList(env, 'inbox_social');
        return json({ feedback, support, social });
      }

      if (url.pathname === '/api/admin/inbox-update' && request.method === 'POST') {
        const b = await request.json();
        if (!await isAdmin(request, env, b)) return json({ error: 'unauthorized' }, 401);
        const key = b.kind === 'support' ? 'inbox_support' : (b.kind === 'social' ? 'inbox_social' : 'inbox_feedback');
        const list = await getList(env, key);
        const idx = list.findIndex((x) => x.id === b.id);
        if (idx === -1) return json({ error: 'not found' }, 404);
        if (b.remove) list.splice(idx, 1);
        else if (b.status) list[idx].status = b.status;
        await setList(env, key, list);
        return json({ ok: true });
      }

      if (url.pathname === '/api/public/resources' && request.method === 'GET') {
        const live = await getList(env, listKey('rp', 'activated'));
        const safe = live.map((it) => ({
          id: it.id,
          title: it.title,
          resourceType: it.resourceType,
          workingStyle: it.workingStyle,
          subject: it.subject,
          subTopic: it.subTopic,
          fromGrade: it.fromGrade,
          toGrade: it.toGrade,
          fromAge: it.fromAge,
          toAge: it.toAge,
          description: it.description,
          sampleLink: it.sampleLink,
          businessName: it.businessName,
          resourceFileKey: it.resourceFileKey,
          resourceFileName: it.resourceFileName
        }));
        return json({ resources: safe });
      }

      if (url.pathname === '/api/submit-resource' && request.method === 'POST') {
        const submission = await request.json();
        submission.id = submission.id || 'rp_' + Date.now();
        submission.partnerType = 'rp';
        submission.status = 'pending';
        submission.submittedAt = submission.submittedAt || new Date().toISOString();
        if (submission.fileDataUrl && submission.resourceFileName) {
          const m = /^data:([^;]+);base64,(.*)$/.exec(submission.fileDataUrl);
          if (m) {
            const bin = atob(m[2]);
            const bytes = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
            const safeName = submission.resourceFileName.replace(/[^A-Za-z0-9._-]/g, '_');
            const fileKey = 'resource_' + submission.id + '_' + safeName;
            await env.LOGOS_KV.put(fileKey, bytes.buffer, { metadata: { contentType: m[1] } });
            submission.resourceFileKey = fileKey;
          }
        }
        delete submission.fileDataUrl;
        const list = await getList(env, listKey('rp', 'pending'));
        list.push(submission);
        await setList(env, listKey('rp', 'pending'), list);
        return json({ ok: true, id: submission.id });
      }

      if (url.pathname === '/api/admin/all' && request.method === 'GET') {
        if (!await isAdmin(request, env)) return json({ error: 'unauthorized' }, 401);
        const out = {};
        for (const t of PARTNER_TYPES) {
          out[t] = {};
          for (const st of STAGES) {
            out[t][st] = await getList(env, listKey(t, st));
          }
        }
        return json(out);
      }

      if (url.pathname === '/api/admin/move' && request.method === 'POST') {
        const body = await request.json();
        if (!await isAdmin(request, env, body)) return json({ error: 'unauthorized' }, 401);
        const type = body.type, id = body.id, from = body.from, to = body.to;
        if (!validTypeStage(type, from) || !validTypeStage(type, to)) return json({ error: 'bad request' }, 400);
        const fromList = await getList(env, listKey(type, from));
        const idx = fromList.findIndex((p) => p.id === id);
        if (idx === -1) return json({ error: 'not found' }, 404);
        const item = fromList.splice(idx, 1)[0];
        const now = new Date().toISOString();
        item.status = to;
        if (to === 'approved') item.approvedAt = now;
        if (to === 'activated') { item.activatedAt = now; item.billingStatus = 'active'; }
        if (to === 'declined') item.declinedAt = now;
        await setList(env, listKey(type, from), fromList);
        const toList = await getList(env, listKey(type, to));
        toList.push(item);
        await setList(env, listKey(type, to), toList);
        return json({ ok: true, item });
      }

      if (url.pathname === '/api/admin/save-item' && request.method === 'POST') {
        const body = await request.json();
        if (!await isAdmin(request, env, body)) return json({ error: 'unauthorized' }, 401);
        const type = body.type, stage = body.stage, id = body.id, fields = body.fields || {};
        if (!validTypeStage(type, stage)) return json({ error: 'bad request' }, 400);
        const list = await getList(env, listKey(type, stage));
        const idx = list.findIndex((p) => p.id === id);
        if (idx === -1) return json({ error: 'not found' }, 404);
        const merged = Object.assign({}, list[idx], fields);
        merged.id = list[idx].id;
        merged.partnerType = list[idx].partnerType || type;
        merged.updatedAt = new Date().toISOString();
        list[idx] = merged;
        await setList(env, listKey(type, stage), list);
        return json({ ok: true, item: merged });
      }

      if (url.pathname === '/api/admin/delete-item' && request.method === 'POST') {
        const body = await request.json();
        if (!await isAdmin(request, env, body)) return json({ error: 'unauthorized' }, 401);
        const type = body.type, stage = body.stage, id = body.id;
        if (!validTypeStage(type, stage)) return json({ error: 'bad request' }, 400);
        const list = await getList(env, listKey(type, stage));
        const idx = list.findIndex((p) => p.id === id);
        if (idx === -1) return json({ error: 'not found' }, 404);
        list.splice(idx, 1);
        await setList(env, listKey(type, stage), list);
        return json({ ok: true });
      }

      if (url.pathname === '/api/submit-partner' && request.method === 'POST') {
        const submission = await request.json();
        submission.id = submission.id || ('partner_' + Date.now());
        submission.status = 'pending';
        submission.submittedAt = submission.submittedAt || new Date().toISOString();

        const pending = await getList(env, listKey('ep', 'pending'));
        pending.push(submission);
        await setList(env, listKey('ep', 'pending'), pending);

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
      url.pathname === '/admin-pending-partners.html' || url.pathname === '/admin-pending-partners' ||
      (url.hostname === 'admin.homsapp.com' && url.pathname === '/');

    if (isAdminPageRequest && request.method === 'GET') {
      const valid = await isSessionValid(request, env);
      if (!valid) {
        return Response.redirect(url.origin + '/admin-login.html', 302);
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
