// Teer Online service worker: refresh HTML from GitHub Pages instead of serving stale app UI.
const CACHE_NAME = 'teer-online-supabase-v3';
const urlsToCache = [
  './',
  './index.html',
  './manifest.json',
  './logo.png',
  './icon-192.png',
  './icon-512.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE_NAME);
    try { await cache.addAll(urlsToCache); } catch (_) {}
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys
      .filter(key => key.startsWith('teer-online-') && key !== CACHE_NAME)
      .map(key => caches.delete(key)));
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;
  const url = new URL(event.request.url);
  const isAppHtml = event.request.mode === 'navigate' || /\/index\.html$/.test(url.pathname);

  if (isAppHtml) {
    event.respondWith((async () => {
      const cache = await caches.open(CACHE_NAME);
      try {
        const fresh = await fetch(event.request, { cache: 'no-store' });
        if (fresh && fresh.ok) await cache.put(event.request, fresh.clone());
        return fresh;
      } catch (_) {
        return (await cache.match(event.request)) || (await cache.match('./index.html'));
      }
    })());
    return;
  }

  event.respondWith((async () => {
    const cached = await caches.match(event.request);
    if (cached) return cached;
    try {
      const fresh = await fetch(event.request);
      if (fresh && fresh.ok && url.origin === self.location.origin) {
        const cache = await caches.open(CACHE_NAME);
        await cache.put(event.request, fresh.clone());
      }
      return fresh;
    } catch (_) {
      return undefined;
    }
  })());
});
