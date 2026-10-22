// ============================================
// ALPHA HSE RISK — Service Worker
// Caches pages for offline use
// ============================================
const CACHE_NAME = 'alpha-hse-v2'; // <--- BUMPED TO V2 TO CLEAR BAD CACHE

const URLS_TO_CACHE = [
  '/login',
  '/dashboard',
  '/new',
  '/history',
  '/profile',
  '/static/icon-192.png',
  '/static/icon-512.png',
  '/static/manifest.json'
];

// ---- Install: pre-cache the core pages ----
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(URLS_TO_CACHE))
      .then(() => self.skipWaiting())
  );
});

// ---- Activate: remove old caches ----
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys.filter(k => k !== CACHE_NAME)
            .map(k => caches.delete(k))
      )
    ).then(() => self.clients.claim())
  );
});

// ---- Fetch: network-first, fall back to cache ----
self.addEventListener('fetch', event => {
  // Only handle GET requests
  if (event.request.method !== 'GET') return;

  // Skip PDFs & Excel — they need fresh server data
  if (event.request.url.includes('/pdf') || event.request.url.includes('/excel')) return;

  // Skip the service worker file itself to prevent caching loops
  if (event.request.url.includes('/sw.js')) return;

  // Skip non-origin requests
  if (!event.request.url.startsWith(self.location.origin)) return;

  event.respondWith(
    fetch(event.request)
      .then(response => {
        // Cache successful responses
        if (response && response.status === 200) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(cache => {
            cache.put(event.request, clone);
          });
        }
        return response;
      })
      .catch(() => {
        // Network failed — serve from cache
        return caches.match(event.request).then(cached => {
          if (cached) return cached;
          return new Response(
            '<h1>Offline</h1><p>This page is not cached yet.</p>',
            { status: 503, headers: { 'Content-Type': 'text/html' } }
          );
        });
      })
  );
});