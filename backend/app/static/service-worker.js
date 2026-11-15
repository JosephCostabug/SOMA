const CACHE_NAME = "soma-app-shell-v1";

self.addEventListener("install", event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.add("/"))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys.filter(key => key.startsWith("soma-app-shell-") && key !== CACHE_NAME)
          .map(key => caches.delete(key))
      ))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", event => {
  const request = event.request;
  const url = new URL(request.url);
  if (request.method !== "GET" || url.origin !== self.location.origin
    || url.pathname.startsWith("/api/")) {
    return;
  }
  if (request.mode !== "navigate" || url.pathname !== "/") return;
  event.respondWith(
    fetch(request)
      .then(response => {
        if (response.ok) {
          return caches.open(CACHE_NAME)
            .then(cache => cache.put("/", response.clone()))
            .then(() => response);
        }
        return response;
      })
      .catch(async () => {
        const cached = await caches.match("/");
        if (!cached) throw new Error("Shell offline indisponível.");
        return cached;
      })
  );
});
