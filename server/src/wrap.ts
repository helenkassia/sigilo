import { randomBytes, createCipheriv, createDecipheriv } from "node:crypto";

/**
 * Segunda camada de cifra, do lado do servidor.
 *
 * O envelope que chega do cliente já é indecifrável para nós (E2EE). Esta
 * camada existe para um cenário diferente: alguém que consiga LER a memória
 * do Redis — dump, réplica indevida, acesso ao processo redis-server — mas
 * não o processo Node. Sem a chave abaixo, o que está no Redis é ruído.
 *
 * A chave é gerada no boot e vive apenas na heap deste processo. Não vai
 * para variável de ambiente, arquivo, log ou Redis. Reiniciar o servidor
 * torna ilegível tudo que ainda estava em trânsito — o que é o
 * comportamento desejado, não um bug.
 */
const bootKey = randomBytes(32);

export function wrap(plain: Buffer): Buffer {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", bootKey, iv);
  const ct = Buffer.concat([c.update(plain), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), ct]);
}

export function unwrap(blob: Buffer): Buffer | null {
  try {
    const iv = blob.subarray(0, 12);
    const tag = blob.subarray(12, 28);
    const ct = blob.subarray(28);
    const d = createDecipheriv("aes-256-gcm", bootKey, iv);
    d.setAuthTag(tag);
    return Buffer.concat([d.update(ct), d.final()]);
  } catch {
    // Chave de boot diferente (servidor reiniciou) ou blob adulterado.
    return null;
  }
}
