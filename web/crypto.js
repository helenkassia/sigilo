// ---------------------------------------------------------------------------
// Sigilo :: criptografia do lado do cliente
//
// Só WebCrypto nativo. Nenhuma dependência externa, nenhum CDN — num app web
// o maior risco ao E2EE é o código que o navegador baixa, então o objetivo é
// que a superfície seja pequena e auditável.
//
// A chave privada é gerada com extractable=false: ela existe como CryptoKey
// dentro do IndexedDB e NUNCA pode ser lida por JavaScript, nem por este
// código, nem por um script injetado.
// ---------------------------------------------------------------------------

const DB = "sigilo";
const STORE_ID = "identity";
const STORE_PINS = "pins";

function db() {
  return new Promise((resolve, reject) => {
    const r = indexedDB.open(DB, 1);
    r.onupgradeneeded = () => {
      r.result.createObjectStore(STORE_ID);
      r.result.createObjectStore(STORE_PINS);
    };
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

async function idb(store, mode, fn) {
  const conn = await db();
  return new Promise((resolve, reject) => {
    const tx = conn.transaction(store, mode);
    const req = fn(tx.objectStore(store));
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

const b64 = {
  enc: (buf) => {
    const bytes = new Uint8Array(buf);
    let binary = "";
    for (let i = 0; i < bytes.length; i += 8192) {
      binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
    }
    return btoa(binary);
  },
  dec: (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0)),
};

// --- Identidade ------------------------------------------------------------

/** Carrega a identidade local ou cria uma nova. Idempotente. */
export async function loadIdentity(userId) {
  const existing = await idb(STORE_ID, "readonly", (s) => s.get(userId));
  if (existing) return existing;

  const ecdh = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    false, // privada NÃO extraível
    ["deriveBits"],
  );
  const ecdsa = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign", "verify"],
  );

  const identity = {
    userId,
    ecdhPriv: ecdh.privateKey,
    ecdhPub: await crypto.subtle.exportKey("jwk", ecdh.publicKey),
    ecdsaPriv: ecdsa.privateKey,
    ecdsaPub: await crypto.subtle.exportKey("jwk", ecdsa.publicKey),
  };
  await idb(STORE_ID, "readwrite", (s) => s.put(identity, userId));
  return identity;
}

export async function signChallenge(identity, nonceB64) {
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    identity.ecdsaPriv,
    b64.dec(nonceB64),
  );
  return b64.enc(sig);
}

// --- Impressão digital -----------------------------------------------------

/**
 * Número de segurança no estilo Signal: 25 dígitos derivados das DUAS chaves
 * públicas. Serve para conferência fora de banda (olho no olho, ligação,
 * QR code). É o único mecanismo que fecha o ataque de troca de chave pelo
 * próprio servidor — nenhuma quantidade de TLS substitui isso.
 */
export async function fingerprint(ecdhJwk, ecdsaJwk) {
  const canon = [ecdhJwk, ecdsaJwk].map((k) => `${k.crv}.${k.x}.${k.y}`).join("|");
  let bytes = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canon)));
  // Iterações encarecem uma busca por colisão parcial nos dígitos exibidos.
  for (let i = 0; i < 2000; i++) {
    bytes = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  }
  const groups = [];
  for (let i = 0; i < 5; i++) {
    const n = (bytes[i * 3] << 16) | (bytes[i * 3 + 1] << 8) | bytes[i * 3 + 2];
    groups.push(String(n % 100000).padStart(5, "0"));
  }
  return groups.join(" ");
}

/** Número de segurança da conversa: os dois lados, em ordem estável. */
export async function safetyNumber(a, b) {
  const [x, y] = [a, b].sort((p, q) => p.userId.localeCompare(q.userId));
  return [
    await fingerprint(x.ecdh ?? x.ecdhPub, x.ecdsa ?? x.ecdsaPub),
    await fingerprint(y.ecdh ?? y.ecdhPub, y.ecdsa ?? y.ecdsaPub),
  ];
}

// --- Fixação (pinning) de chave -------------------------------------------

export const pins = {
  get: (userId) => idb(STORE_PINS, "readonly", (s) => s.get(userId)),
  set: (userId, pin) => idb(STORE_PINS, "readwrite", (s) => s.put(pin, userId)),
};

/**
 * Compara a identidade que o servidor entregou com a que fixamos antes.
 * "new"      -> nunca vimos, exige confirmação da impressão digital
 * "match"    -> igual à fixada, segue o jogo
 * "CHANGED"  -> mudou. Trava a conversa. Isto é indistinguível de um ataque
 *               de intermediário e deve ser tratado como um até prova em
 *               contrário, obtida fora deste canal.
 *
 * `conferido` é diferente de `match`: fixar é automático, conferir é um ato
 * humano. Uma chave pode bater com a fixada e mesmo assim nunca ter sido
 * comparada com ninguém — e o rótulo na tela precisa dizer isso.
 */
export async function checkPin(remote) {
  const pinned = await pins.get(remote.userId);
  if (!pinned) return { status: "new", conferido: false };
  const same =
    JSON.stringify(pinned.ecdh) === JSON.stringify(remote.ecdh) &&
    JSON.stringify(pinned.ecdsa) === JSON.stringify(remote.ecdsa);
  return same
    ? { status: "match", pinned, conferido: pinned.conferido === true }
    : { status: "CHANGED", pinned, conferido: false };
}

// --- Envelope --------------------------------------------------------------
//
// Um formato só, para conversa direta e para canal. Cada mensagem nasce com
// uma chave própria (MK): o conteúdo é cifrado UMA vez com ela, e a MK é
// envelopada individualmente para cada destinatário via ECDH do par.
//
// O remetente entra na própria lista de destinatários. Sem isso ele não
// consegue reabrir o que escreveu — e a mensagem sumiria da tela dele a cada
// recarregamento, enquanto continua viva para todo mundo.
//
// Consequências que importam:
//   · não existe "chave do grupo" guardada em lugar nenhum;
//   · quem entrar depois não alcança nada do que já passou;
//   · sair é deixar de receber envelopes — não há chave a revogar;
//   · o envelope cresce ~120 bytes por destinatário.

async function ecdhBits(identity, peer) {
  const peerPub = await crypto.subtle.importKey(
    "jwk", peer.ecdh, { name: "ECDH", namedCurve: "P-256" }, false, [],
  );
  return crypto.subtle.deriveBits({ name: "ECDH", public: peerPub }, identity.ecdhPriv, 256);
}

/**
 * Chave simétrica de um par, derivada do segredo ECDH via HKDF. O `info`
 * amarra a chave aos dois identificadores, em ordem estável, para que os dois
 * lados cheguem ao mesmo valor — e para que ela não sirva em outro contexto.
 */
async function pairKey(identity, peer, salt, escopo) {
  const hkdf = await crypto.subtle.importKey(
    "raw", await ecdhBits(identity, peer), "HKDF", false, ["deriveKey"],
  );
  const info = new TextEncoder().encode(
    `sigilo/v1/${escopo}|${[identity.userId, peer.userId].sort().join("|")}`,
  );
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info },
    hkdf,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/** Você mesmo como destinatário: ECDH da sua chave com ela própria. */
export const eu = (identity) => ({ userId: identity.userId, ecdh: identity.ecdhPub });

export const AUDIO_MAX_BYTES = 512 * 1024;
export const AUDIO_MAX_MS = 120_000;
export const AUDIO_TYPES = ["audio/webm;codecs=opus", "audio/ogg;codecs=opus", "audio/mp4", "audio/mp4;codecs=mp4a.40.2", "audio/webm", "audio/ogg"];
const AUDIO_BUCKET = AUDIO_MAX_BYTES + 2048;

export const FILE_MAX_BYTES = 4 * 1024 * 1024;
export const IMAGE_TYPES = ["image/jpeg", "image/png", "image/webp", "image/gif"];
export const PDF_TYPE = "application/pdf";
export const FILE_TYPES = [...IMAGE_TYPES, PDF_TYPE];
const FILE_BUCKETS = [
  256 * 1024,
  1024 * 1024,
  2 * 1024 * 1024,
  FILE_MAX_BYTES + 4096,
];
const NOME_MAX = 200;
const LEGENDA_MAX = 2000;

export function validarAudio(audio) {
  if (!audio || !AUDIO_TYPES.includes(audio.mime) ||
      !Number.isFinite(audio.duracaoMs) || audio.duracaoMs <= 0 || audio.duracaoMs > AUDIO_MAX_MS ||
      !(audio.bytes instanceof Uint8Array) || !audio.bytes.length || audio.bytes.length > AUDIO_MAX_BYTES) {
    throw new Error("Áudio inválido: limite de 2 minutos e 512 KiB.");
  }
}

/** Assinaturas mínimas — MIME declarado sozinho não basta. */
export function detectarMimeArquivo(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 4) return null;
  if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return "image/jpeg";
  if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) return "image/png";
  if (bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x38) return "image/gif";
  if (bytes.length >= 12 &&
      bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46 &&
      bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50) {
    return "image/webp";
  }
  if (bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46) return PDF_TYPE;
  return null;
}

function limparNome(nome) {
  if (typeof nome !== "string") return "";
  return nome.normalize("NFC").replace(/[\u0000-\u001f\u007f]/g, "").trim().slice(0, NOME_MAX);
}

function limparLegenda(texto) {
  if (typeof texto !== "string") return "";
  return texto.normalize("NFC").slice(0, LEGENDA_MAX);
}

export function validarArquivo(arquivo) {
  if (!arquivo || !FILE_TYPES.includes(arquivo.mime) ||
      !(arquivo.bytes instanceof Uint8Array) || !arquivo.bytes.length ||
      arquivo.bytes.length > FILE_MAX_BYTES) {
    throw new Error("Arquivo inválido: use imagem (JPEG, PNG, WebP, GIF) ou PDF de até 4 MiB.");
  }
  const detectado = detectarMimeArquivo(arquivo.bytes);
  if (!detectado || detectado !== arquivo.mime) {
    throw new Error("Arquivo inválido: o conteúdo não confere com o tipo declarado.");
  }
  const tipo = arquivo.mime === PDF_TYPE ? "pdf" : "imagem";
  if (arquivo.tipo && arquivo.tipo !== tipo) {
    throw new Error("Arquivo inválido: tipo inconsistente.");
  }
  if (arquivo.nome != null && (typeof arquivo.nome !== "string" || arquivo.nome.length > NOME_MAX)) {
    throw new Error("Arquivo inválido: nome longo demais.");
  }
  if (arquivo.texto != null && (typeof arquivo.texto !== "string" || arquivo.texto.length > LEGENDA_MAX)) {
    throw new Error("Arquivo inválido: legenda longa demais.");
  }
}

export async function seal(identity, destinatarios, texto, context) {
  return sealRaw(identity, destinatarios, new TextEncoder().encode(texto), context, 2);
}

/** Tipo, codec e duração ficam DENTRO da cifra. Nenhum upload em claro. */
export async function sealAudio(identity, destinatarios, audio, context) {
  validarAudio(audio);
  const meta = new TextEncoder().encode(JSON.stringify({ tipo: "audio", mime: audio.mime, duracaoMs: audio.duracaoMs }));
  const raw = new Uint8Array(4 + meta.length + audio.bytes.length);
  new DataView(raw.buffer).setUint32(0, meta.length);
  raw.set(meta, 4);
  raw.set(audio.bytes, 4 + meta.length);
  return sealRaw(identity, destinatarios, raw, context, 3);
}

/** MIME, nome e legenda ficam DENTRO da cifra. Nenhum upload em claro. */
export async function sealFile(identity, destinatarios, arquivo, context) {
  validarArquivo(arquivo);
  const tipo = arquivo.mime === PDF_TYPE ? "pdf" : "imagem";
  const meta = new TextEncoder().encode(JSON.stringify({
    tipo,
    mime: arquivo.mime,
    nome: limparNome(arquivo.nome || ""),
    texto: limparLegenda(arquivo.texto || ""),
  }));
  if (meta.length > 4096) throw new Error("Metadados do arquivo longos demais.");
  const raw = new Uint8Array(4 + meta.length + arquivo.bytes.length);
  new DataView(raw.buffer).setUint32(0, meta.length);
  raw.set(meta, 4);
  raw.set(arquivo.bytes, 4 + meta.length);
  return sealRaw(identity, destinatarios, raw, context, 4);
}

const aad = (env) => new TextEncoder().encode(JSON.stringify([env.v, env.canal, env.dm, env.from]));

function bucketPara(v, rawLen) {
  if (v === 3) return AUDIO_BUCKET;
  if (v === 4) {
    const precisa = rawLen + 4;
    const bucket = FILE_BUCKETS.find((b) => precisa <= b);
    if (!bucket) throw new Error("Arquivo grande demais após o preenchimento.");
    return bucket;
  }
  return [256, 1024, 4096, 16384].find((b) => rawLen + 4 <= b) ?? rawLen + 4;
}

async function sealRaw(identity, destinatarios, raw, { canal, dm = null }, v) {
  const mk = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
    "encrypt", "decrypt",
  ]);
  const mkRaw = await crypto.subtle.exportKey("raw", mk);

  const iv = crypto.getRandomValues(new Uint8Array(12));
  // Áudio e arquivo usam buckets fixos para o tamanho cifrado não vazar duração/conteúdo.
  const bucket = bucketPara(v, raw.length);
  const padded = new Uint8Array(bucket);
  new DataView(padded.buffer).setUint32(0, raw.length);
  padded.set(raw, 4);
  const header = { v, canal, dm, from: identity.userId };
  const usaAad = v === 3 || v === 4;
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, ...(usaAad ? { additionalData: aad(header) } : {}) }, mk, padded);

  const chaves = {};
  for (const d of destinatarios) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const kiv = crypto.getRandomValues(new Uint8Array(12));
    const kek = await pairKey(identity, d, salt, `v${v}`);
    chaves[d.userId] = {
      salt: b64.enc(salt),
      iv: b64.enc(kiv),
      wk: b64.enc(await crypto.subtle.encrypt({ name: "AES-GCM", iv: kiv }, kek, mkRaw)),
    };
  }

  const envelope = { ...header, iv: b64.enc(iv), ct: b64.enc(ct), chaves };
  return b64.enc(new TextEncoder().encode(JSON.stringify(envelope)));
}

function abrirMetaBinario(padded, len, bucketEsperado) {
  if (bucketEsperado != null && padded.length !== bucketEsperado) throw new Error("payload inválido");
  if (len < 4) throw new Error("payload inválido");
  const metaLen = new DataView(padded.buffer).getUint32(4);
  if (metaLen > 4096 || metaLen > len - 4) throw new Error("metadados inválidos");
  const meta = JSON.parse(new TextDecoder().decode(padded.subarray(8, 8 + metaLen)));
  const bytes = padded.slice(8 + metaLen, 4 + len);
  return { meta, bytes };
}

/** `remetente` é a identidade de quem enviou — pode ser você mesmo. */
export async function open(identity, remetente, envelopeB64) {
  const env = ler(envelopeB64);
  if (env.v !== 2 && env.v !== 3 && env.v !== 4) throw new Error("versão de mensagem não suportada");
  const minha = env.chaves?.[identity.userId];
  if (!minha) throw new Error("sem chave para este destinatário");

  const kek = await pairKey(identity, remetente, b64.dec(minha.salt), `v${env.v}`);
  const mkRaw = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64.dec(minha.iv) }, kek, b64.dec(minha.wk),
  );
  const mk = await crypto.subtle.importKey("raw", mkRaw, "AES-GCM", false, ["decrypt"]);

  const usaAad = env.v === 3 || env.v === 4;
  const padded = new Uint8Array(
    await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64.dec(env.iv), ...(usaAad ? { additionalData: aad(env) } : {}) }, mk, b64.dec(env.ct)),
  );
  if (padded.length < 4) throw new Error("mensagem inválida");
  const len = new DataView(padded.buffer).getUint32(0);
  if (len > padded.length - 4) throw new Error("mensagem truncada");
  if (env.v === 3) {
    const { meta, bytes } = abrirMetaBinario(padded, len, AUDIO_BUCKET);
    if (meta.tipo !== "audio") throw new Error("tipo não suportado");
    const audio = { mime: meta.mime, duracaoMs: meta.duracaoMs, bytes };
    validarAudio(audio);
    return { from: env.from, texto: "", audio };
  }
  if (env.v === 4) {
    if (!FILE_BUCKETS.includes(padded.length)) throw new Error("arquivo inválido");
    const { meta, bytes } = abrirMetaBinario(padded, len);
    if (meta.tipo !== "imagem" && meta.tipo !== "pdf") throw new Error("tipo não suportado");
    const arquivo = {
      tipo: meta.tipo,
      mime: meta.mime,
      nome: limparNome(meta.nome || ""),
      texto: limparLegenda(meta.texto || ""),
      bytes,
    };
    validarArquivo(arquivo);
    return { from: env.from, texto: arquivo.texto, arquivo };
  }
  return { from: env.from, texto: new TextDecoder().decode(padded.subarray(4, 4 + len)) };
}

/** Cabeçalho em claro: quem mandou e para qual conversa. */
export function cabecalho(envelopeB64) {
  const { from, canal, dm } = ler(envelopeB64);
  return { from, canal, dm };
}

function ler(envelopeB64) {
  return JSON.parse(new TextDecoder().decode(b64.dec(envelopeB64)));
}
