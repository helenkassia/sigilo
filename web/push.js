import { signChallenge } from "./crypto.js";

/**
 * Web Push opt-in. Payload no servidor é genérico ("Nova mensagem");
 * o conteúdo continua só no WebSocket.
 */

function urlBase64ToUint8Array(base64String) {
  const padding = "=".repeat((4 - (base64String.length % 4)) % 4);
  const base64 = (base64String + padding).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(base64);
  return Uint8Array.from(raw, (c) => c.charCodeAt(0));
}

export function pushSuportado() {
  return (
    window.isSecureContext &&
    "serviceWorker" in navigator &&
    "PushManager" in window &&
    "Notification" in window
  );
}

export async function registrarServiceWorker() {
  if (!("serviceWorker" in navigator)) return null;
  const reg = await navigator.serviceWorker.register("/sw.js", { scope: "/" });
  // Força checar atualização — o worker antigo engolia notificações.
  try { await reg.update(); } catch { /* ignore */ }
  return reg;
}

/** Mostra um aviso local na hora (não depende do FCM). */
export async function testarAvisoLocal() {
  const perm = Notification.permission;
  if (perm !== "granted") {
    const pedida = await Notification.requestPermission();
    if (pedida !== "granted") throw new Error("denied");
  }

  // Preferir a API da página: não depende do service worker estar "ready"
  // (que pode pendurar para sempre se o registro falhou).
  try {
    const n = new Notification("Sigilo", {
      body: "Se você está vendo isto, os avisos do sistema estão ok.",
      icon: "/icon-192.png",
      tag: "sigilo-teste-" + Date.now(),
    });
    n.onclick = () => { try { window.focus(); n.close(); } catch { /* ignore */ } };
    return { via: "notification" };
  } catch (err) {
    // Fallback via service worker, com timeout para não travar o botão.
    const reg = await Promise.race([
      navigator.serviceWorker.ready,
      new Promise((_, rej) => setTimeout(() => rej(new Error("sw_timeout")), 3000)),
    ]);
    await reg.showNotification("Sigilo", {
      body: "Se você está vendo isto, os avisos do sistema estão ok.",
      icon: "/icon-192.png",
      tag: "sigilo-teste-" + Date.now(),
    });
    return { via: "serviceworker" };
  }
}

/** Aviso local quando a aba está em segundo plano e chega mensagem pelo WS. */
export async function avisarLocalSeOculto() {
  if (Notification.permission !== "granted") return;
  if (!document.hidden && document.visibilityState === "visible") return;
  try {
    new Notification("Sigilo", {
      body: "Nova mensagem",
      icon: "/icon-192.png",
      tag: "sigilo-msg-local",
    });
  } catch {
    try {
      const reg = await Promise.race([
        navigator.serviceWorker.ready,
        new Promise((_, rej) => setTimeout(() => rej(new Error("sw_timeout")), 2000)),
      ]);
      await reg.showNotification("Sigilo", {
        body: "Nova mensagem",
        icon: "/icon-192.png",
        tag: "sigilo-msg-local",
        renotify: true,
      });
    } catch { /* ignore */ }
  }
}

export async function estadoPush(identity) {
  if (!pushSuportado() || !identity) {
    return { disponivel: false, inscrito: false, permissao: "denied" };
  }

  const vapid = await fetch("/api/push/vapid").then((r) => (r.ok ? r.json() : null)).catch(() => null);
  if (!vapid?.publicKey) {
    return { disponivel: false, inscrito: false, permissao: Notification.permission };
  }

  const reg = await navigator.serviceWorker.ready;
  const sub = await reg.pushManager.getSubscription();
  return {
    disponivel: true,
    inscrito: Boolean(sub),
    permissao: Notification.permission,
  };
}

async function assinarPedido(identity, path, extra = {}) {
  const chal = await fetch("/api/push/challenge", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ userId: identity.userId }),
  });
  if (!chal.ok) throw new Error("challenge");
  const { nonce } = await chal.json();
  const signature = await signChallenge(identity, nonce);
  const res = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      userId: identity.userId,
      nonce,
      signature,
      ...extra,
    }),
  });
  if (!res.ok) throw new Error("push_api");
  return res.json();
}

export async function ativarPush(identity) {
  if (!pushSuportado()) throw new Error("unsupported");

  await registrarServiceWorker();
  const perm = await Notification.requestPermission();
  if (perm !== "granted") throw new Error("denied");

  const vapid = await fetch("/api/push/vapid").then((r) => {
    if (!r.ok) throw new Error("push_disabled");
    return r.json();
  });

  const reg = await navigator.serviceWorker.ready;
  let sub = await reg.pushManager.getSubscription();
  if (!sub) {
    sub = await reg.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: urlBase64ToUint8Array(vapid.publicKey),
    });
  }

  await assinarPedido(identity, "/api/push/subscribe", { subscription: sub.toJSON() });
  return true;
}

export async function desativarPush(identity) {
  if (!pushSuportado() || !identity) return;

  const reg = await navigator.serviceWorker.getRegistration();
  const sub = await reg?.pushManager.getSubscription();
  const endpoint = sub?.endpoint;

  try {
    await assinarPedido(identity, "/api/push/unsubscribe", { endpoint: endpoint ?? "" });
  } catch {
    // Mesmo se a API falhar, tenta limpar a inscrição local.
  }

  if (sub) await sub.unsubscribe();
}
