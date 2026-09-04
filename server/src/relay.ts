import { WebSocketServer, WebSocket } from "ws";
import { randomBytes } from "node:crypto";
import type { Server } from "node:http";
import { clampTtl, env } from "./env.js";
import * as keys from "./keys.js";
import {
  apagarMensagem, chan, pending, put, redis, restante, roster, sub, take,
} from "./store.js";
import { avisar as avisarPush } from "./push.js";

/** Identificador do canal aberto a todos. Não é um usuário. */
export const CANAL_GERAL = "#geral";

type Conn = { ws: WebSocket; userId: string | null; nonce: Buffer };

/**
 * Metadado de roteamento (quem mandou para quem) vive SÓ aqui, na heap, e só
 * enquanto a mensagem existe. Não vai para o Redis: um dump do Redis não
 * revela o grafo social, apenas blobs sem dono.
 *
 * Um `Envio` é a mensagem como o remetente a vê; cada `Route` é uma das
 * cópias entregues. O `ref` costura as duas coisas na tela dele.
 */
type Envio = {
  from: string;
  ref: string;
  /** Some assim que for lida, sem esperar o prazo. Escolha do remetente. */
  queimar: boolean;
  /** Destinatários de verdade — a cópia do próprio remetente não conta. */
  alvos: number;
  lidos: Set<string>;
  ids: Set<string>;
};
type Route = { envio: Envio; to: string; expiraEm: number; timer: NodeJS.Timeout };

const routes = new Map<string, Route>();
const envios = new Map<string, Envio>();

const chaveEnvio = (from: string, ref: string) => `${from}\u0000${ref}`;

/** Remove uma cópia do Redis e da heap. Não avisa ninguém — quem chama decide. */
async function sumir(id: string) {
  const r = routes.get(id);
  if (!r) return;
  clearTimeout(r.timer);
  routes.delete(id);
  r.envio.ids.delete(id);
  if (r.envio.ids.size === 0) envios.delete(chaveEnvio(r.envio.from, r.envio.ref));
  await apagarMensagem(r.to, id);
}

const online = new Map<string, Set<Conn>>();

function send(ws: WebSocket, msg: unknown) {
  if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(msg));
}

function notify(userId: string, msg: unknown) {
  for (const c of online.get(userId) ?? []) send(c.ws, msg);
}

/** Fim de uma cópia, por qualquer motivo. Avisa remetente e destinatário. */
async function encerrar(id: string, motivo: "prazo" | "lida" | "apagada") {
  const r = routes.get(id);
  if (!r) return;
  const { envio, to } = r;
  await sumir(id);
  notify(envio.from, { type: "gone", id, ref: envio.ref, to, motivo });
  // Quem recebeu precisa tirar da tela também — vale para queima e exclusão.
  if (motivo !== "prazo" && to !== envio.from) notify(to, { type: "sumiu", id, motivo });
}

/**
 * Avisa todo mundo que o elenco mudou. Sem isto, quem já está conectado fica
 * com uma lista velha e simplesmente não vê quem entrou depois — nem
 * consegue conferir a chave de alguém que acabou de chegar.
 */
export function avisarElenco() {
  for (const conns of online.values()) {
    for (const c of conns) send(c.ws, { type: "elenco" });
  }
}

export function attachRelay(server: Server) {
  const wss = new WebSocketServer({
    server,
    path: "/ws",
    maxPayload: env.maxEnvelopeBytes * 4, // envelope de grupo carrega uma chave por membro
  });

  // Entrega entre instâncias: o canal carrega apenas o id, nunca o conteúdo.
  sub.on("message", async (channel, id) => {
    const userId = channel.slice(2);
    if (online.has(userId)) await deliver(userId, id);
  });

  wss.on("connection", (ws) => {
    const conn: Conn = { ws, userId: null, nonce: randomBytes(32) };
    send(ws, { type: "challenge", nonce: conn.nonce.toString("base64") });

    ws.on("message", async (data) => {
      let msg: any;
      try {
        msg = JSON.parse(String(data));
      } catch {
        return;
      }

      if (!conn.userId) return void (await autenticar(conn, msg));
      if (msg.type === "send") return void (await enviar(conn, msg));
      if (msg.type === "read") return void (await ler(conn, msg));
      if (msg.type === "apagar") return void (await apagar(conn, msg));
    });

    ws.on("close", async () => {
      if (!conn.userId) return;
      const set = online.get(conn.userId);
      set?.delete(conn);
      if (set && set.size === 0) {
        online.delete(conn.userId);
        await sub.unsubscribe(chan(conn.userId));
      }
    });
  });

  return wss;
}

async function autenticar(conn: Conn, msg: any) {
  if (msg.type !== "auth") return;
  const identity = await keys.get(String(msg.userId ?? ""));
  if (!identity) return send(conn.ws, { type: "denied", reason: "unknown_user" });

  const sig = Buffer.from(String(msg.signature ?? ""), "base64");
  if (!(await keys.verifyChallenge(identity, conn.nonce, sig))) {
    return send(conn.ws, { type: "denied", reason: "bad_signature" });
  }

  conn.userId = identity.userId;
  let set = online.get(conn.userId);
  if (!set) online.set(conn.userId, (set = new Set()));
  set.add(conn);
  if (set.size === 1) await sub.subscribe(chan(conn.userId));

  send(conn.ws, {
    type: "ready",
    userId: conn.userId,
    maxEnvelopeBytes: env.maxEnvelopeBytes,
    canalGeral: CANAL_GERAL,
    ttl: {
      padrao: env.msgTtl,
      min: env.msgTtlMin,
      max: env.msgTtlMax,
      opcoes: env.ttlOptions,
    },
  });

  for (const id of await pending(conn.userId)) await deliver(conn.userId, id);
}

async function enviar(conn: Conn, msg: any) {
  const from = conn.userId!;
  const to = String(msg.to ?? "");
  const envelope = Buffer.from(String(msg.envelope ?? ""), "base64");
  const ref = String(msg.clientRef ?? "");
  if (!to || envelope.length === 0) return;
  if (envelope.length > env.maxEnvelopeBytes) {
    return send(conn.ws, { type: "error", ref, reason: "envelope_too_large" });
  }

  // O prazo é do remetente, mas o teto é da instalação. Vale da criação:
  // ler não encurta, deixar sem ler não prolonga.
  const ttlMs = clampTtl(msg.ttlMs);
  const expiraEm = Date.now() + ttlMs;

  // O cliente diz para quem ENVELOPOU a chave da mensagem, e essa lista
  // inclui ele próprio. Entregar a quem não está nela só geraria cópias
  // indecifráveis — e é assim que um membro com chave suspeita fica de fora
  // sem o servidor precisar saber por quê.
  //
  // O fan-out é do SERVIDOR, mas as chaves já vieram prontas do cliente: o
  // servidor continua sem conseguir abrir coisa alguma.
  const elenco = new Set(await roster());
  if (to === CANAL_GERAL && !elenco.has(from)) {
    return send(conn.ws, { type: "error", ref, reason: "not_in_group" });
  }
  const pedidos: string[] =
    Array.isArray(msg.para) && msg.para.length > 0
      ? msg.para.map(String)
      : to === CANAL_GERAL ? [...elenco] : [to, from];

  // Sala geral: só membros do elenco. DM: destinatários do envelope,
  // mesmo quem nunca entrou no grupo.
  const alvos = [...new Set(pedidos)].filter((u) =>
    to === CANAL_GERAL ? elenco.has(u) : true,
  );
  if (alvos.length === 0) return send(conn.ws, { type: "error", ref, reason: "sem_destinatarios" });

  const envio: Envio = {
    from,
    ref,
    queimar: msg.queimar === true,
    alvos: alvos.filter((u) => u !== from).length,
    lidos: new Set(),
    ids: new Set(),
  };
  envios.set(chaveEnvio(from, ref), envio);

  // Guardar tudo primeiro, avisar o remetente, e só então publicar. A ordem
  // importa: a cópia do próprio remetente volta por este mesmo socket, e ele
  // precisa já conhecer os ids para não desenhar a mensagem duas vezes.
  const entregas: Array<[string, string]> = [];
  for (const alvo of alvos) {
    const id = await put(alvo, envelope, ttlMs);
    entregas.push([alvo, id]);
    envio.ids.add(id);
    routes.set(id, {
      envio,
      to: alvo,
      expiraEm,
      // Espelha o TTL do Redis: quando o payload expira, o remetente fica
      // sabendo e o metadado some da heap.
      timer: setTimeout(() => void encerrar(id, "prazo"), ttlMs).unref(),
    });
  }

  send(conn.ws, {
    type: "queued",
    ref,
    ids: entregas.map(([, id]) => id),
    // A própria cópia do remetente não conta como destinatário na tela dele.
    destinatarios: envio.alvos,
    queimar: envio.queimar,
    ttlMs,
    expiraEm,
  });

  for (const [alvo, id] of entregas) {
    await redis.publish(chan(alvo), id);
    // Push mesmo com WS online: no celular a aba em background ainda
    // precisa do alerta do sistema. A cópia do próprio remetente não conta.
    if (alvo !== from) void avisarPush(alvo);
  }
}

/**
 * Confirmação de leitura. Por padrão não destrói nada: a mensagem vive até o
 * prazo, e o id continua na caixa para que um F5 reveja o que não expirou.
 *
 * Se o remetente pediu queima ao ler, é aqui que a cópia morre — e quando
 * todos os destinatários tiverem lido, a cópia dele morre junto: não faz
 * sentido a mensagem sobreviver só na tela de quem a mandou.
 */
async function ler(conn: Conn, msg: any) {
  const id = String(msg.id ?? "");
  const route = routes.get(id);
  if (!route || route.to !== conn.userId) return;

  const { envio } = route;
  notify(envio.from, { type: "lida", id, ref: envio.ref, por: conn.userId });
  if (!envio.queimar) return;

  envio.lidos.add(conn.userId);
  await encerrar(id, "lida");

  if (envio.lidos.size >= envio.alvos) {
    for (const outro of [...envio.ids]) {
      if (routes.get(outro)?.to === envio.from) await encerrar(outro, "lida");
    }
  }
}

/**
 * Exclusão pelo remetente: some para todo mundo, agora. Só quem enviou pode
 * pedir — o `from` vem da conexão autenticada, nunca do payload.
 *
 * Quem já leu, já leu: isto tira a mensagem das telas e do Redis, não da
 * memória de quem a viu.
 */
async function apagar(conn: Conn, msg: any) {
  // Duas formas de apontar a mensagem: a referência local de quem enviou
  // (que só existe na aba onde ela foi escrita) ou o id de uma das cópias.
  // A segunda é a que sobra depois de um F5, quando a aba já não guarda a
  // referência — sem ela, excluir uma mensagem antiga falharia em silêncio.
  const porRef = msg.ref ? envios.get(chaveEnvio(conn.userId!, String(msg.ref))) : undefined;
  const porId = msg.id ? routes.get(String(msg.id))?.envio : undefined;
  const envio = porRef ?? porId;

  // Pelo id, qualquer um poderia apontar a mensagem de outra pessoa: a posse
  // é conferida aqui, contra o remetente da conexão autenticada.
  if (!envio || envio.from !== conn.userId) return;

  for (const id of [...envio.ids]) await encerrar(id, "apagada");
}

async function deliver(userId: string, id: string) {
  const envelope = await take(id);
  if (!envelope) return; // já expirou

  // O prazo restante vem do próprio Redis: é a fonte da verdade, e continua
  // certo mesmo se a entrega acontecer horas depois do envio.
  const resta = await restante(id);
  if (resta === null) return;

  const route = routes.get(id);
  notify(userId, {
    type: "msg",
    id,
    envelope: envelope.toString("base64"),
    expiraEm: Date.now() + resta,
    // Quem recebe precisa saber que esta some ao ser lida, antes de ler.
    queimar: route?.envio.queimar === true,
  });

  if (route) notify(route.envio.from, { type: "delivered", id, ref: route.envio.ref, to: userId });
}
