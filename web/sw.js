/**
 * Service worker do Sigilo.
 * Versão: 2 — não cacheia o app; só trata push e clique.
 */
self.addEventListener("install", (event) => {
  event.waitUntil(self.skipWaiting());
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener("push", (event) => {
  const icon = new URL("icon-192.png", self.registration.scope).href;
  let title = "Sigilo";
  let body = "Nova mensagem";
  try {
    if (event.data) {
      const data = event.data.json();
      if (data?.title) title = String(data.title);
      if (data?.body) body = String(data.body);
    }
  } catch {
    try {
      const texto = event.data?.text?.();
      if (texto) body = texto.slice(0, 80);
    } catch { /* genérico */ }
  }

  event.waitUntil(
    self.registration.showNotification(title, {
      body,
      icon,
      badge: icon,
      tag: "sigilo-msg-" + Date.now(),
      renotify: true,
      requireInteraction: false,
      data: { url: self.registration.scope },
    }),
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const alvo = event.notification.data?.url || self.registration.scope;

  event.waitUntil(
    (async () => {
      const janelas = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
      for (const c of janelas) {
        if ("focus" in c) {
          await c.focus();
          return;
        }
      }
      if (self.clients.openWindow) await self.clients.openWindow(alvo);
    })(),
  );
});
