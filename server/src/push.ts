import webpush from "web-push";
import { env } from "./env.js";
import { redis } from "./store.js";

/**
 * Web Push genérico: só acorda o dispositivo. Sem remetente, sem preview,
 * sem id — o conteúdo continua vindo pelo WebSocket após abrir o app.
 */

type PushSub = {
  endpoint: string;
  keys: { p256dh: string; auth: string };
};

const subKey = (userId: string) => `p:${userId}`;

const enabled = Boolean(env.vapidPublicKey && env.vapidPrivateKey);

if (enabled) {
  webpush.setVapidDetails(
    env.vapidSubject,
    env.vapidPublicKey!,
    env.vapidPrivateKey!,
  );
}

export function pushDisponivel(): boolean {
  return enabled;
}

export function vapidPublicKey(): string | null {
  return env.vapidPublicKey;
}

function validar(sub: unknown): PushSub | null {
  if (!sub || typeof sub !== "object") return null;
  const s = sub as Record<string, unknown>;
  const endpoint = String(s.endpoint ?? "");
  const keys = s.keys as Record<string, unknown> | undefined;
  const p256dh = String(keys?.p256dh ?? "");
  const auth = String(keys?.auth ?? "");
  if (!/^https:\/\//i.test(endpoint) || !p256dh || !auth) return null;
  if (endpoint.length > 2048 || p256dh.length > 256 || auth.length > 64) return null;
  return { endpoint, keys: { p256dh, auth } };
}

export async function salvarInscricao(userId: string, raw: unknown): Promise<boolean> {
  const sub = validar(raw);
  if (!sub) return false;
  await redis.hset(subKey(userId), sub.endpoint, JSON.stringify(sub));
  return true;
}

export async function removerInscricao(userId: string, endpoint: string): Promise<void> {
  if (!endpoint) return;
  await redis.hdel(subKey(userId), endpoint);
}

export async function limparInscricoes(userId: string): Promise<void> {
  await redis.del(subKey(userId));
}

/**
 * Avisa todos os dispositivos inscritos deste usuário.
 * Dispara mesmo com WebSocket aberto: no celular a aba em background
 * ainda precisa do alerta do sistema.
 */
export async function avisar(userId: string): Promise<void> {
  if (!enabled) return;

  const mapa = await redis.hgetall(subKey(userId));
  const endpoints = Object.keys(mapa);
  if (endpoints.length === 0) return;

  const payload = JSON.stringify({
    title: "Sigilo",
    body: "Nova mensagem",
  });

  await Promise.all(
    endpoints.map(async (endpoint) => {
      const sub = JSON.parse(mapa[endpoint]!) as PushSub;
      try {
        await webpush.sendNotification(sub, payload, {
          TTL: 300,
          urgency: "high",
        });
      } catch (err: any) {
        const status = err?.statusCode ?? err?.status;
        console.warn(`push falhou para ${userId}:`, status ?? err?.message ?? err);
        // Inscrição morta ou revogada: some do Redis.
        if (status === 404 || status === 410) {
          await redis.hdel(subKey(userId), endpoint);
        }
      }
    }),
  );
}
