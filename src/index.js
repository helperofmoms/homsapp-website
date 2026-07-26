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

function isAdmin(request, env, body) {
  const url = new URL(request.url);
  const token = url.searchParams.get('token') || (body && body.token) || request.headers.get('x-admin-token');
  return Boolean(token) && Boolean(env.ADMIN_TOKEN) && token === env.ADMIN_TOKEN;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
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
        if (!isAdmin(request, env)) return json({ error: 'unauthorized' }, 401);
        const [pending, approved, activated] = await Promise.all([
          getList(env, 'pending'),
          getList(env, 'approved'),
          getList(env, 'activated')
        ]);
        return json({ pending, approved, activated });
      }

      if (url.pathname === '/api/admin/approve' && request.method === 'POST') {
        const body = await request.json();
        if (!isAdmin(request, env, body)) return json({ error: 'unauthorized' }, 401);

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
        if (!isAdmin(request, env, body)) return json({ error: 'unauthorized' }, 401);

        const pending = await getList(env, 'pending');
        const idx = pending.findIndex((p) => p.id === body.id);
        if (idx === -1) return json({ error: 'not found' }, 404);

        pending.splice(idx, 1);
        await setList(env, 'pending', pending);

        return json({ ok: true });
      }

      if (url.pathname === '/api/admin/mark-paid' && request.method === 'POST') {
        const body = await request.json();
        if (!isAdmin(request, env, body)) return json({ error: 'unauthorized' }, 401);

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

    return env.ASSETS.fetch(request);
  }
};
