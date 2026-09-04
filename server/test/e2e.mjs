// Teste E2E: simula dois clientes usando a MESMA lógica de crypto do browser
// (WebCrypto do Node), contra o servidor real + Redis real.
import WebSocket from "ws";
import Redis from "ioredis";
import * as BrowserCrypto from "../../web/crypto.js";

const BASE = process.env.BASE ?? "http://127.0.0.1:8090";
const REDIS = process.env.REDIS_URL ?? "redis://127.0.0.1:6379";
const ROT = process.env.ROTATION_TOKEN;
if (!ROT) throw new Error("Defina ROTATION_TOKEN para executar os testes de rotação.");
const sub = crypto.subtle;
const b64e = (b) => Buffer.from(b).toString("base64");
const b64d = (s) => new Uint8Array(Buffer.from(s, "base64"));
const ok = (c, m) => console.log(`${c ? "  ok " : "FALHA"}  ${m}`) || c;
let falhas = 0;
const check = (c, m) => { if (!ok(c, m)) falhas++; };

async function mkIdentity(userId) {
  const ecdh = await sub.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const ecdsa = await sub.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  return {
    userId, ecdhPriv: ecdh.privateKey, ecdsaPriv: ecdsa.privateKey,
    ecdhPub: await sub.exportKey("jwk", ecdh.publicKey),
    ecdsaPub: await sub.exportKey("jwk", ecdsa.publicKey),
  };
}
async function pairKey(me, peer, salt, escopo) {
  const pk = await sub.importKey("jwk", peer.ecdh, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = await sub.deriveBits({ name: "ECDH", public: pk }, me.ecdhPriv, 256);
  const hkdf = await sub.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const info = new TextEncoder().encode(`sigilo/v1/${escopo}|${[me.userId, peer.userId].sort().join("|")}`);
  return sub.deriveKey({ name: "HKDF", hash: "SHA-256", salt, info }, hkdf, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

const eu = (id) => ({ userId: id.userId, ecdh: id.ecdhPub });

/** Envelope v2: uma chave por mensagem, envelopada para cada destinatário. */
async function seal(me, destinatarios, texto, { canal = "dm", dm = null } = {}) {
  const mk = await sub.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const mkRaw = await sub.exportKey("raw", mk);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const raw = new TextEncoder().encode(texto);
  const bucket = [256, 1024, 4096, 16384].find((b) => raw.length + 4 <= b);
  const padded = new Uint8Array(bucket);
  new DataView(padded.buffer).setUint32(0, raw.length);
  padded.set(raw, 4);
  const ct = await sub.encrypt({ name: "AES-GCM", iv }, mk, padded);

  const chaves = {};
  for (const d of destinatarios) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const kiv = crypto.getRandomValues(new Uint8Array(12));
    const kek = await pairKey(me, d, salt, "v2");
    chaves[d.userId] = { salt: b64e(salt), iv: b64e(kiv), wk: b64e(await sub.encrypt({ name: "AES-GCM", iv: kiv }, kek, mkRaw)) };
  }
  return { envelope: b64e(new TextEncoder().encode(JSON.stringify({ v: 2, canal, dm, from: me.userId, iv: b64e(iv), ct: b64e(ct), chaves }))), bucket };
}

async function open(me, remetente, envB64) {
  const env = JSON.parse(Buffer.from(envB64, "base64").toString("utf8"));
  const minha = env.chaves[me.userId];
  if (!minha) throw new Error("sem chave para este destinatário");
  const kek = await pairKey(me, remetente, b64d(minha.salt), "v2");
  const mkRaw = await sub.decrypt({ name: "AES-GCM", iv: b64d(minha.iv) }, kek, b64d(minha.wk));
  const mk = await sub.importKey("raw", mkRaw, "AES-GCM", false, ["decrypt"]);
  const padded = new Uint8Array(await sub.decrypt({ name: "AES-GCM", iv: b64d(env.iv) }, mk, b64d(env.ct)));
  const len = new DataView(padded.buffer).getUint32(0);
  return { from: env.from, text: new TextDecoder().decode(padded.subarray(4, 4 + len)) };
}

async function register(id, token) {
  const r = await fetch(`${BASE}/api/identity`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(token ? { "x-rotation-token": token } : {}) },
    body: JSON.stringify({ userId: id.userId, ecdh: id.ecdhPub, ecdsa: id.ecdsaPub }),
  });
  return { status: r.status, body: await r.json() };
}
function connect(id) {
  return new Promise((resolve) => {
    const ws = new WebSocket(`${BASE.replace("http","ws")}/ws`);
    const inbox = [];
    ws.on("message", async (d) => {
      const m = JSON.parse(String(d));
      if (m.type === "challenge") {
        const sig = await sub.sign({ name: "ECDSA", hash: "SHA-256" }, id.ecdsaPriv, b64d(m.nonce));
        return ws.send(JSON.stringify({ type: "auth", userId: id.userId, signature: b64e(sig) }));
      }
      if (m.type === "ready") return resolve({ ws, inbox, ready: m });
      inbox.push(m);
    });
  });
}
const waitFor = async (inbox, type, ms = 4000, pred = () => true) => {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) {
    const i = inbox.findIndex((m) => m.type === type && pred(m));
    if (i >= 0) return inbox.splice(i, 1)[0];
    await new Promise((r) => setTimeout(r, 40));
  }
  return null;
};

console.log("\n== identidade e trava de rotação ==");
const suf = Date.now().toString(36);
const ana = await mkIdentity(`ana${suf}`), bru = await mkIdentity(`bru${suf}`);
check((await register(ana)).status === 200, "registro TOFU aceito na primeira vez");
check((await register(ana)).status === 200, "reenviar a MESMA chave é idempotente");
const impostor = await mkIdentity(ana.userId);
const conflito = await register(impostor);
check(conflito.status === 409 && conflito.body.error === "key_change_requires_approval",
  "chave DIFERENTE para o mesmo usuário é recusada (bloqueia MITM)");
check((await register(impostor, "token-errado")).status === 409, "token de rotação errado não passa");
check((await register(impostor, ROT)).body.rotated === true, "token correto fora de banda autoriza rotação");
await register(ana, ROT); // devolve a identidade real da Ana
await register(bru);
const cah0 = await mkIdentity(`cz${suf}`);
await register(cah0);

console.log("\n== autenticação por assinatura ==");
const falso = new WebSocket(`${BASE.replace("http","ws")}/ws`);
const negado = await new Promise((res) => {
  falso.on("message", (d) => {
    const m = JSON.parse(String(d));
    if (m.type === "challenge") falso.send(JSON.stringify({ type: "auth", userId: ana.userId, signature: b64e(crypto.getRandomValues(new Uint8Array(64))) }));
    if (m.type === "denied") res(m.reason);
  });
});
check(negado === "bad_signature", "conexão sem a chave privada é recusada");
falso.close();

console.log("\n== trânsito da mensagem ==");
const A = await connect(ana), B = await connect(bru);
const segredo = "reunião às 14h, sala 3 — não repassar";
const pubBru = { userId: bru.userId, ecdh: bru.ecdhPub };
const pubAna = { userId: ana.userId, ecdh: ana.ecdhPub };
const { envelope, bucket } = await seal(ana, [pubBru, eu(ana)], segredo, { dm: bru.userId });
A.ws.send(JSON.stringify({ type: "send", to: bru.userId, envelope, clientRef: "r1", para: [bru.userId, ana.userId] }));
const queued = await waitFor(A.inbox, "queued");
check(queued?.ids?.length === 2, "servidor guardou uma cópia para cada lado, remetente incluído");
check(queued.destinatarios === 1, "a própria cópia não conta como destinatário na tela do remetente");
queued.id = queued.ids[0];
check(queued.ttlMs === A.ready.ttl.padrao, `sem prazo pedido, vale o padrão da instalação (${queued.ttlMs / 3600000}h)`);
check(bucket === 256, "padding levou a mensagem para o bucket de 256 bytes");

// As verificações de Redis exigem acesso direto ao banco. No compose, o Redis
// fica só na rede interna — de propósito. Quando não dá para alcançar, essas
// checagens são PULADAS em vez de falharem.
const redis = new Redis(REDIS, { maxRetriesPerRequest: 2, retryStrategy: () => null, lazyConnect: true });
let temRedis = true;
try { await redis.connect(); await redis.ping(); } catch { temRedis = false; }
const checkRedis = async (fn, m) => {
  if (!temRedis) return console.log(`  pulado  ${m} (sem acesso direto ao Redis)`);
  check(await fn(), m);
};
redis.on("error", () => {});
await checkRedis(async () => (await redis.getBuffer(`m:${queued.id}`)) !== null, "envelope está no Redis");
await checkRedis(async () => !(await redis.getBuffer(`m:${queued.id}`)).toString("utf8").includes("reunião"), "texto claro NÃO aparece no Redis");
await checkRedis(async () => !(await redis.getBuffer(`m:${queued.id}`)).toString("utf8").includes(ana.userId), "remetente NÃO aparece no Redis");
await checkRedis(async () => !(await redis.getBuffer(`m:${queued.id}`)).toString("utf8").includes("salt"), "nem a estrutura do envelope vaza (2ª camada aplicada)");
await checkRedis(async () => {
  const chaves = await redis.call("SCAN", "0", "COUNT", "1000");
  return !chaves[1].some((k) => k.startsWith("m:") && k.includes(ana.userId));
}, "nenhuma chave do Redis correlaciona remetente e destinatário");

const recebida = await waitFor(B.inbox, "msg");
check(!!recebida, "destinatário recebeu o envelope");
const aberta = await open(bru, pubAna, recebida.envelope);
check(aberta.text === segredo, "destinatário decifrou o texto original");
check(aberta.from === ana.userId, "remetente confere");

console.log("\n== leitura NÃO destrói ==");
check(!!(await waitFor(A.inbox, "delivered")), "remetente foi avisado da entrega");
B.ws.send(JSON.stringify({ type: "read", id: recebida.id }));
const lida = await waitFor(A.inbox, "lida");
check(lida?.por === bru.userId, "remetente recebe confirmação de leitura");
await new Promise((r) => setTimeout(r, 300));
await checkRedis(async () => (await redis.exists(`m:${recebida.id}`)) === 1, "a mensagem CONTINUA no Redis depois de lida");
await checkRedis(async () => {
  const ttl = await redis.pttl(`m:${recebida.id}`);
  return ttl > A.ready.ttl.padrao - 60_000;
}, "ler não encurtou o prazo");

console.log("\n== expira sozinha, no prazo ==");
// Usa o piso da instalação: é o menor prazo que dá para observar de verdade.
const curto = A.ready.ttl.min;
const { envelope: env2 } = await seal(ana, [pubBru], "essa ninguém lê", { dm: bru.userId });
B.ws.close();
await new Promise((r) => setTimeout(r, 300));
A.ws.send(JSON.stringify({ type: "send", to: bru.userId, envelope: env2, clientRef: "r2", ttlMs: curto, para: [bru.userId] }));
const q2 = await waitFor(A.inbox, "queued");
await checkRedis(async () => {
  const ttl = await redis.pttl(`m:${q2.ids[0]}`);
  return ttl > 0 && ttl <= curto;
}, "TTL armado na criação");

if (curto <= 5000) {
  const sumiu = await waitFor(A.inbox, "gone", curto + 4000, (m) => m.ref === "r2");
  check(!!sumiu, `remetente é avisado quando a mensagem expira (${curto / 1000}s)`);
  await checkRedis(async () => (await redis.exists(`m:${q2.ids[0]}`)) === 0, "mensagem não lida sumiu sozinha, sem ninguém pedir");
} else {
  console.log(`  pulado  expiração observada em tempo real (piso da instalação é ${curto / 1000}s)`);
}

console.log("\n== persistência em disco ==");
await checkRedis(async () => {
  const info = await redis.info("persistence");
  return /aof_enabled:0/.test(info) && /rdb_changes_since_last_save:\d+/.test(info);
}, "AOF desligado no Redis em uso");

console.log("\n== TTL configurável por mensagem ==");
const opcoes = A.ready.ttl.opcoes;
check(Array.isArray(opcoes) && opcoes.length > 0, `servidor publica opções de queima (${opcoes.map((o) => o / 1000 + "s").join(", ")})`);

// Bru volta a ficar online e esvaziamos o que estava pendente, para que os
// próximos envios sejam entregues na hora e possam ser medidos um a um.
const B2 = await connect(bru);
await new Promise((r) => setTimeout(r, 400));
for (const m of B2.inbox.filter((m) => m.type === "msg")) B2.ws.send(JSON.stringify({ type: "read", id: m.id }));
B2.inbox.length = 0; A.inbox.length = 0;

async function enviarComPrazo(ref, texto, ttlMs) {
  const { envelope } = await seal(ana, [pubBru], texto, { dm: bru.userId });
  A.ws.send(JSON.stringify({ type: "send", to: bru.userId, envelope, clientRef: ref, ttlMs, para: [bru.userId] }));
  return waitFor(A.inbox, "queued");
}

const q3 = await enviarComPrazo("r3", "vida curta", 60_000);
check(q3.ttlMs === 60_000, "servidor aceitou o prazo pedido pelo remetente (1m)");
const recebida3 = await waitFor(B2.inbox, "msg");
check(recebida3.expiraEm > Date.now() && recebida3.expiraEm <= q3.expiraEm + 1000,
  "destinatário recebe o instante exato em que a mensagem expira");
await checkRedis(async () => {
  const pttl = await redis.pttl(`m:${recebida3.id}`);
  return pttl > 0 && pttl <= 60_000;
}, "TTL no Redis é o prazo pedido, contado da criação");
B2.ws.send(JSON.stringify({ type: "read", id: recebida3.id }));
await waitFor(A.inbox, "lida");

const q4 = await enviarComPrazo("r4", "prazo absurdo", 999 * 86_400_000);
check(q4.ttlMs === A.ready.ttl.max, `prazo acima do teto foi limitado ao máximo da instalação (${q4.ttlMs / 86400000}d)`);
const q5 = await enviarComPrazo("r5", "prazo ridículo", 1);
check(q5.ttlMs === A.ready.ttl.min, "prazo abaixo do mínimo foi elevado ao piso");

// Limpa o que ficou para não confundir o teste de grupo.
await new Promise((r) => setTimeout(r, 300));
for (const m of B2.inbox.filter((m) => m.type === "msg")) B2.ws.send(JSON.stringify({ type: "read", id: m.id }));
B2.inbox.length = 0; A.inbox.length = 0;

console.log("\n== queima ao ser lida ==");
const { envelope: envQ } = await seal(ana, [pubBru, eu(ana)], "some ao ler", { dm: bru.userId });
A.ws.send(JSON.stringify({
  type: "send", to: bru.userId, envelope: envQ, clientRef: "k1",
  para: [bru.userId, ana.userId], queimar: true,
}));
const qk = await waitFor(A.inbox, "queued");
check(qk.queimar === true, "servidor registrou o pedido de queima ao ler");
const recQ = await waitFor(B2.inbox, "msg");
check(recQ.queimar === true, "destinatário é avisado ANTES de ler que a mensagem some ao ser lida");
await checkRedis(async () => (await redis.exists(`m:${recQ.id}`)) === 1, "antes da leitura, a mensagem está lá");

B2.ws.send(JSON.stringify({ type: "read", id: recQ.id }));
const kb = await waitFor(A.inbox, "gone", 3000, (m) => m.to === bru.userId && m.ref === "k1");
check(kb?.motivo === "lida", "cópia do destinatário morre no ato da leitura");
const ka = await waitFor(A.inbox, "gone", 3000, (m) => m.to === ana.userId && m.ref === "k1");
check(ka?.motivo === "lida", "cópia do remetente morre quando todos leram");
const avisoB = await waitFor(B2.inbox, "sumiu", 2000);
check(avisoB?.motivo === "lida", "destinatário é avisado de que a cópia foi destruída");
await checkRedis(async () => (await redis.exists(`m:${recQ.id}`)) === 0, "nada sobra no Redis depois da leitura");

console.log("\n== exclusão pelo remetente ==");
const { envelope: envX } = await seal(ana, [pubBru, eu(ana)], "arrependi", { dm: bru.userId });
A.ws.send(JSON.stringify({
  type: "send", to: bru.userId, envelope: envX, clientRef: "x1", para: [bru.userId, ana.userId],
}));
const qx = await waitFor(A.inbox, "queued");
const recX = await waitFor(B2.inbox, "msg");
check(!!recX, "mensagem entregue antes da exclusão");

// Um estranho não consegue apagar o que não é dele.
const C0 = await connect(cah0);
C0.ws.send(JSON.stringify({ type: "apagar", ref: "x1" }));
await new Promise((r) => setTimeout(r, 400));
await checkRedis(async () => (await redis.exists(`m:${recX.id}`)) === 1, "quem não enviou não consegue apagar");
C0.ws.close();

A.ws.send(JSON.stringify({ type: "apagar", ref: "x1" }));
const sumiuX = await waitFor(B2.inbox, "sumiu", 3000, (m) => m.id === recX.id);
check(sumiuX?.motivo === "apagada", "destinatário é avisado da exclusão");
await checkRedis(async () => (await redis.exists(`m:${recX.id}`)) === 0, "todas as cópias somem do Redis");
await checkRedis(async () => {
  const vivas = await Promise.all(qx.ids.map((id) => redis.exists(`m:${id}`)));
  return vivas.every((v) => v === 0);
}, "inclusive a cópia do próprio remetente");

console.log("\n== exclusão depois de recarregar (só pelo id) ==");
// Depois de um F5 a aba de quem enviou não guarda mais a referência local:
// o único identificador que sobra é o id de uma das cópias.
const { envelope: envR } = await seal(ana, [pubBru, eu(ana)], "apagar sem ref", { dm: bru.userId });
A.ws.send(JSON.stringify({
  type: "send", to: bru.userId, envelope: envR, clientRef: "z1", para: [bru.userId, ana.userId],
}));
const qz = await waitFor(A.inbox, "queued");
const recZ = await waitFor(B2.inbox, "msg");

// Um estranho não apaga a mensagem de outro nem sabendo o id dela.
const C1 = await connect(cah0);
C1.ws.send(JSON.stringify({ type: "apagar", id: recZ.id }));
await new Promise((r) => setTimeout(r, 400));
await checkRedis(async () => (await redis.exists(`m:${recZ.id}`)) === 1, "id alheio não autoriza exclusão");
C1.ws.close();

// O dono apaga passando só o id, sem a referência.
A.ws.send(JSON.stringify({ type: "apagar", id: qz.ids[0] }));
const sumiuZ = await waitFor(B2.inbox, "sumiu", 3000, (m) => m.id === recZ.id);
check(sumiuZ?.motivo === "apagada", "quem enviou apaga usando só o id da cópia");
await checkRedis(async () => {
  const vivas = await Promise.all(qz.ids.map((id) => redis.exists(`m:${id}`)));
  return vivas.every((v) => v === 0);
}, "todas as cópias somem mesmo sem a referência local");

console.log("\n== canal geral ==");
const cah = await mkIdentity(`cah${suf}`);
await register(cah);
const canal = await (await fetch(`${BASE}/api/canal`)).json();
const ids = canal.membros.map((m) => m.userId);
check(canal.canal === "#geral", "canal geral existe e se anuncia");
check([ana, bru, cah].every((u) => ids.includes(u.userId)), "todo mundo que registrou está no elenco");

const C3 = await connect(cah);
await new Promise((r) => setTimeout(r, 300));
C3.inbox.length = 0;
const membros = [
  { userId: bru.userId, ecdh: bru.ecdhPub },
  { userId: cah.userId, ecdh: cah.ecdhPub },
];
const recado = "aviso geral: manutenção às 22h";
const { envelope: envG } = await seal(ana, [...membros, eu(ana)], recado, { canal: "#geral" });
A.ws.send(JSON.stringify({
  type: "send", to: "#geral", envelope: envG, clientRef: "g1", ttlMs: 60_000,
  para: [...membros.map((m) => m.userId), ana.userId],
}));
const qg = await waitFor(A.inbox, "queued");
check(qg.destinatarios === 2 && qg.ids.length === 3, "fan-out criou uma cópia por membro, mais a do remetente");

const gb = await waitFor(B2.inbox, "msg");
const gc = await waitFor(C3.inbox, "msg");
const ab = await open(bru, pubAna, gb.envelope);
const ac = await open(cah, pubAna, gc.envelope);
check(ab.text === recado && ac.text === recado, "os dois membros decifraram a mesma mensagem de grupo");

await checkRedis(async () => {
  const rawG = await redis.getBuffer(`m:${qg.ids[0]}`);
  return rawG === null || !rawG.toString("utf8").includes("manutenção");
}, "conteúdo do grupo não aparece em claro no Redis");

const forasteiro = await mkIdentity(`fora${suf}`);
let vazou = false;
try { await open(forasteiro, pubAna, gb.envelope); vazou = true; } catch {}
check(!vazou, "quem não está no envelope não abre a mensagem de grupo");

B2.ws.send(JSON.stringify({ type: "read", id: gb.id }));
const lidaG = await waitFor(A.inbox, "lida", 4000, (m) => m.ref === "g1");
check(lidaG?.por === bru.userId, "confirmação de leitura do grupo volta costurada ao item do remetente");
await checkRedis(async () => (await redis.exists(`m:${gb.id}`)) === 1, "a cópia lida continua viva até o prazo");
await checkRedis(async () => (await redis.exists(`m:${gc.id}`)) === 1, "a cópia de quem não leu também continua viva");

console.log("\n== voz cifrada com o módulo real do navegador ==");
const audio = { mime: "audio/webm;codecs=opus", duracaoMs: 2000,
  bytes: new Uint8Array(300_000).fill(73) };
const envVoz = await BrowserCrypto.sealAudio(ana, [...membros, eu(ana)], audio, { canal: "#geral", dm: null });
A.ws.send(JSON.stringify({ type: "send", to: "#geral", envelope: envVoz, clientRef: "voz1",
  para: [bru.userId, cah.userId, ana.userId], ttlMs: 60_000, queimar: true }));
const qv = await waitFor(A.inbox, "queued", 4000, (m) => m.ref === "voz1");
check(qv?.ids.length === 3, "servidor aceita o envelope maior de voz para o grupo");
if (qv) {
  const vb = await waitFor(B2.inbox, "msg", 4000, (m) => qv.ids.includes(m.id));
  const vc = await waitFor(C3.inbox, "msg", 4000, (m) => qv.ids.includes(m.id));
  const va = await waitFor(A.inbox, "msg", 4000, (m) => qv.ids.includes(m.id));
  for (const [who, delivery] of [[ana, va], [bru, vb], [cah, vc]]) {
    const opened = await BrowserCrypto.open(who, pubAna, delivery.envelope);
    check(Buffer.from(opened.audio.bytes).equals(Buffer.from(audio.bytes)), `${who.userId} decifra os bytes originais de voz`);
  }
  await checkRedis(async () => {
    const stored = await redis.getBuffer(`m:${vb.id}`);
    return stored && !stored.includes(Buffer.from(audio.bytes)) && !stored.includes(Buffer.from("audio/webm"));
  }, "áudio e codec não aparecem em claro no Redis");
  await checkRedis(async () => (await redis.exists(`m:${vb.id}`)) === 1, "receber voz não queima antes da reprodução");
  const again = await connect(bru);
  const restored = await waitFor(again.inbox, "msg", 4000, (m) => m.id === vb.id);
  check(!!restored && Buffer.from((await BrowserCrypto.open(bru, pubAna, restored.envelope)).audio.bytes).equals(Buffer.from(audio.bytes)),
    "reconexão restaura áudio ainda não ouvido e não expirado");
  again.ws.close();
  B2.ws.send(JSON.stringify({ type: "read", id: vb.id }));
  check(!!await waitFor(B2.inbox, "sumiu", 4000, (m) => m.id === vb.id), "iniciar reprodução queima a cópia recebida");
  await checkRedis(async () => (await redis.exists(`m:${vb.id}`)) === 0, "cópia ouvida removida do Redis");
  await checkRedis(async () => (await redis.exists(`m:${va.id}`)) === 1, "cópia do remetente aguarda todos ouvirem, como no texto");
  await checkRedis(async () => (await redis.exists(`m:${vc.id}`)) === 1, "membro que ainda não ouviu mantém sua cópia");
  A.ws.send(JSON.stringify({ type: "apagar", ref: "voz1" }));
  await waitFor(C3.inbox, "sumiu", 4000, (m) => m.id === vc.id);
  await checkRedis(async () => (await redis.exists(`m:${vc.id}`)) === 0, "exclusão remove a cópia de voz restante");
  await checkRedis(async () => (await redis.exists(`m:${va.id}`)) === 0, "exclusão também remove a cópia do remetente");
}

const envVozDm = await BrowserCrypto.sealAudio(ana, [pubBru, eu(ana)], audio, { canal: "dm", dm: bru.userId });
for (const [ref, burn] of [["voz-dm", true], ["voz-prazo", false]]) {
  A.ws.send(JSON.stringify({ type: "send", to: bru.userId, envelope: envVozDm, clientRef: ref,
    para: [bru.userId, ana.userId], ttlMs: burn ? 60_000 : curto, queimar: burn }));
  const q = await waitFor(A.inbox, "queued", 4000, (m) => m.ref === ref);
  check(!!q, "voz em conversa direta aceita");
  if (!q) continue;
  const delivery = await waitFor(B2.inbox, "msg", 4000, (m) => q.ids.includes(m.id));
  check(!!(await BrowserCrypto.open(bru, pubAna, delivery.envelope)).audio, "voz direta decifra");
  if (burn) B2.ws.send(JSON.stringify({ type: "read", id: delivery.id }));
  if (burn || curto <= 5000) {
    await waitFor(A.inbox, "gone", curto + 4000, (m) => m.ref === ref && m.to === ana.userId);
    await checkRedis(async () => (await Promise.all(q.ids.map((id) => redis.exists(`m:${id}`)))).every((v) => v === 0),
      burn ? "voz direta queima dos dois lados ao ouvir" : "voz expira sem reprodução");
  }
}

const oversized = Buffer.alloc(A.ready.maxEnvelopeBytes + 1).toString("base64");
A.ws.send(JSON.stringify({ type: "send", to: bru.userId, envelope: oversized, clientRef: "voz-grande" }));
const rejectedVoice = await waitFor(A.inbox, "error", 4000, (m) => m.ref === "voz-grande");
check(rejectedVoice?.reason === "envelope_too_large", "servidor continua recusando envelopes acima do limite");

B2.ws.close(); C3.ws.close();
A.ws.close(); if (temRedis) redis.disconnect();
console.log(falhas === 0 ? "\nTODOS OS TESTES PASSARAM\n" : `\n${falhas} FALHA(S)\n`);
process.exit(falhas === 0 ? 0 : 1);
