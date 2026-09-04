import { webcrypto as wc } from "node:crypto";

type JsonWebKey = wc.JsonWebKey;
import { redis } from "./store.js";

export type Identity = {
  userId: string;
  /** Chave de acordo (ECDH P-256), usada para derivar o segredo da conversa. */
  ecdh: JsonWebKey;
  /** Chave de assinatura (ECDSA P-256), usada para provar quem é no login. */
  ecdsa: JsonWebKey;
  firstSeen: number;
  /** Incrementa a cada rotação aprovada. O cliente trava se isto mudar. */
  version: number;
};

const key = (userId: string) => `k:${userId}`;

export async function get(userId: string): Promise<Identity | null> {
  const raw = await redis.get(key(userId));
  return raw ? (JSON.parse(raw) as Identity) : null;
}

export type RegisterResult =
  | { ok: true; identity: Identity; rotated: boolean }
  | { ok: false; reason: "key_change_requires_approval"; current: Identity };

/**
 * TOFU (trust on first use) com trava explícita na segunda.
 *
 * Primeira vez que vemos um userId, aceitamos a chave. Se depois disso a
 * chave mudar, recusamos — a menos que venha um token de rotação entregue
 * FORA DE BANDA. É exatamente aqui que um servidor malicioso tentaria
 * empurrar a própria chave para ficar no meio da conversa; sem essa trava,
 * o E2EE inteiro não vale nada.
 */
export async function register(
  id: Omit<Identity, "firstSeen" | "version">,
  rotationToken: string | null,
  expectedToken: string,
): Promise<RegisterResult> {
  const current = await get(id.userId);

  if (current) {
    const same =
      JSON.stringify(current.ecdh) === JSON.stringify(id.ecdh) &&
      JSON.stringify(current.ecdsa) === JSON.stringify(id.ecdsa);
    if (same) return { ok: true, identity: current, rotated: false };

    const approved =
      rotationToken !== null &&
      rotationToken.length === expectedToken.length &&
      timingSafeEqualStr(rotationToken, expectedToken);
    if (!approved) {
      return { ok: false, reason: "key_change_requires_approval", current };
    }

    const next: Identity = {
      ...id,
      firstSeen: current.firstSeen,
      version: current.version + 1,
    };
    await redis.set(key(id.userId), JSON.stringify(next));
    return { ok: true, identity: next, rotated: true };
  }

  const fresh: Identity = { ...id, firstSeen: Date.now(), version: 1 };
  await redis.set(key(id.userId), JSON.stringify(fresh));
  return { ok: true, identity: fresh, rotated: false };
}

function timingSafeEqualStr(a: string, b: string): boolean {
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** Verifica a assinatura do desafio de conexão com a chave ECDSA registrada. */
export async function verifyChallenge(
  identity: Identity,
  nonce: Buffer,
  signature: Buffer,
): Promise<boolean> {
  try {
    const pub = await wc.subtle.importKey(
      "jwk",
      identity.ecdsa,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    return await wc.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      pub,
      signature,
      nonce,
    );
  } catch {
    return false;
  }
}
