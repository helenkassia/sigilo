import { parseDuration } from "./duration.js";

function req(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`variável de ambiente obrigatória ausente: ${name}`);
  return v;
}

function num(name: string, fallback: number): number {
  const v = process.env[name];
  return v ? Number(v) : fallback;
}

/** Aceita "45s", "10m", "2h", "1d" ou um número puro (= segundos). */
function dur(name: string, fallback: string): number {
  return parseDuration(process.env[name] ?? fallback);
}

export const env = {
  redisUrl: process.env.REDIS_URL ?? "redis://127.0.0.1:6379",
  port: num("PORT", 8090),

  /** Exigido para aprovar troca de chave pública de um usuário já conhecido. */
  rotationToken: req("ROTATION_TOKEN"),

  /**
   * Código do grupo: só quem o tem consegue criar identidade e entrar no
   * canal geral. Entregue fora de banda — o link público sozinho não basta.
   */
  groupToken: req("GROUP_TOKEN"),

  /**
   * Vida da mensagem, contada da CRIAÇÃO. Um relógio só: ler não destrói,
   * não ler não prolonga. A mensagem existe pelo tempo que o remetente
   * escolheu e some quando ele acaba, tenha sido lida ou não.
   */
  msgTtl: dur("MSG_TTL", "1d"),
  msgTtlMin: dur("MSG_TTL_MIN", "30s"),
  msgTtlMax: dur("MSG_TTL_MAX", "7d"),

  /** Opções oferecidas na interface. O servidor ainda valida cada uma. */
  ttlOptions: (process.env.TTL_OPTIONS ?? "5m,1h,8h,1d,3d,7d")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map(parseDuration),

  /** Teto de tamanho do envelope cifrado, em bytes. */
  maxEnvelopeBytes: num("MAX_ENVELOPE_BYTES", 5 * 1024 * 1024),

  /**
   * Web Push (VAPID). Opcionais: sem elas o app sobe normal e o opt-in
   * de notificação fica desligado no cliente.
   * Gere com: npx web-push generate-vapid-keys
   */
  vapidPublicKey: process.env.VAPID_PUBLIC_KEY || null,
  vapidPrivateKey: process.env.VAPID_PRIVATE_KEY || null,
  vapidSubject: process.env.VAPID_SUBJECT ?? "mailto:admin@localhost",
};

/** Mantém o pedido do cliente dentro do que a instalação permite. */
export function clampTtl(pedido: unknown): number {
  const ms = typeof pedido === "number" && Number.isFinite(pedido) ? pedido : env.msgTtl;
  return Math.min(env.msgTtlMax, Math.max(env.msgTtlMin, Math.round(ms)));
}
