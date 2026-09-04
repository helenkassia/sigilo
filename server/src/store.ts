import Redis from "ioredis";
import { randomUUID } from "node:crypto";
import { env } from "./env.js";
import { wrap, unwrap } from "./wrap.js";

export const redis = new Redis(env.redisUrl, { lazyConnect: false });
/** Conexão dedicada: um cliente em modo subscribe não aceita outros comandos. */
export const sub = new Redis(env.redisUrl, { lazyConnect: false });

const msgKey = (id: string) => `m:${id}`;
const ROSTER = "u:all";
const inboxKey = (user: string) => `i:${user}`;
export const chan = (user: string) => `c:${user}`;

/**
 * Guarda o envelope cifrado e enfileira o id para o destinatário.
 * O valor gravado é opaco duas vezes: cifrado pelo remetente, empacotado
 * de novo por nós. Remetente e destinatário NÃO são gravados no Redis —
 * esse metadado fica só na memória do processo (ver relay.ts).
 *
 * O TTL é armado aqui, na criação, e nada depois disso o altera. Quem apaga
 * a mensagem é o Redis, no horário combinado — ler não adianta o relógio.
 */
export async function put(to: string, envelope: Buffer, ttlMs: number): Promise<string> {
  const id = randomUUID();
  await redis
    .multi()
    .set(msgKey(id), wrap(envelope), "PX", ttlMs)
    .rpush(inboxKey(to), id)
    // A caixa vive pelo menos o tempo da mensagem mais longa que pode carregar.
    .expire(inboxKey(to), Math.ceil(env.msgTtlMax / 1000))
    .exec();
  return id;
}

/** Apaga uma cópia antes do prazo: queima por leitura ou exclusão. */
export async function apagarMensagem(to: string, id: string): Promise<void> {
  await redis.multi().del(msgKey(id)).lrem(inboxKey(to), 0, id).exec();
}

/** Quanto ainda resta desta mensagem, em ms. Null se já morreu. */
export async function restante(id: string): Promise<number | null> {
  const pttl = await redis.pttl(msgKey(id));
  return pttl > 0 ? pttl : null;
}

export async function take(id: string): Promise<Buffer | null> {
  const raw = await redis.getBuffer(msgKey(id));
  return raw ? unwrap(raw) : null;
}

/** Elenco do canal geral: todo mundo que já registrou uma identidade. */
export async function joinRoster(userId: string): Promise<void> {
  await redis.sadd(ROSTER, userId);
}

export async function roster(): Promise<string[]> {
  return (await redis.smembers(ROSTER)).sort();
}

/** Ids ainda pendentes para um usuário; ids já expirados são varridos. */
export async function pending(to: string): Promise<string[]> {
  const ids = await redis.lrange(inboxKey(to), 0, -1);
  if (ids.length === 0) return [];
  const exists = await redis.mget(...ids.map(msgKey));
  const alive: string[] = [];
  const dead: string[] = [];
  ids.forEach((id, i) => (exists[i] === null ? dead : alive).push(id));
  if (dead.length) {
    const p = redis.multi();
    for (const id of dead) p.lrem(inboxKey(to), 0, id);
    await p.exec();
  }
  return alive;
}
