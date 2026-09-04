import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { env } from "./env.js";
import * as keys from "./keys.js";
import { joinRoster, roster } from "./store.js";
import { avisarElenco, CANAL_GERAL } from "./relay.js";
import * as push from "./push.js";
import { randomBytes } from "node:crypto";

// Em desenvolvimento os estáticos ficam em ../../web (raiz do repo);
// na imagem Docker eles são copiados para ../web, ao lado de src/.
const webDir = [
  fileURLToPath(new URL("../web/", import.meta.url)),
  fileURLToPath(new URL("../../web/", import.meta.url)),
].find((d) => existsSync(join(d, "index.html")))!;

const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".webmanifest": "application/manifest+json",
};

// Sem CDN, sem inline: todo o código do cliente vem daqui e só daqui.
// Isso é o mínimo para que valha a pena falar em E2EE num app web.
const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data: blob:",
  "media-src blob:",
  "frame-src blob:",
  "connect-src 'self' ws: wss:",
  "worker-src 'self'",
  "manifest-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join("; ");

/** Desafios curtos para autenticar inscrição de push por HTTP. */
const desafios = new Map<string, { userId: string; expira: number }>();

function limparDesafios() {
  const agora = Date.now();
  for (const [nonce, d] of desafios) {
    if (d.expira < agora) desafios.delete(nonce);
  }
}
function json(res: ServerResponse, status: number, body: unknown) {
  const data = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
  });
  res.end(data);
}

async function body(req: IncomingMessage): Promise<any> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const c of req) {
    size += (c as Buffer).length;
    if (size > 16 * 1024) throw new Error("payload grande demais");
    chunks.push(c as Buffer);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
}

export function createHttpServer() {
  return createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");

    try {
      if (req.method === "POST" && url.pathname === "/api/identity") {
        const b = await body(req);
        const userId = String(b.userId ?? "").trim();
        if (!/^[a-z0-9][a-z0-9._-]{1,31}$/i.test(userId)) {
          return json(res, 400, { error: "invalid_user_id" });
        }
        const result = await keys.register(
          { userId, ecdh: b.ecdh, ecdsa: b.ecdsa },
          (req.headers["x-rotation-token"] as string) ?? null,
          env.rotationToken,
        );
        if (!result.ok) {
          // 409: existe uma identidade anterior e ela não bate.
          return json(res, 409, { error: result.reason, current: result.current });
        }
        // Registrar-se é entrar no canal geral. Não há grupo a criar.
        await joinRoster(userId);
        // Quem já está conectado precisa saber, ou nunca verá esta pessoa.
        avisarElenco();
        return json(res, 200, { identity: result.identity, rotated: result.rotated });
      }

      // Elenco do canal geral, com as chaves públicas de cada membro: o
      // cliente precisa delas para envelopar a chave da mensagem uma vez
      // por pessoa. O servidor não participa dessa parte.
      if (req.method === "GET" && url.pathname === "/api/canal") {
        const membros = await roster();
        const identities = (await Promise.all(membros.map(keys.get))).filter(Boolean);
        return json(res, 200, { canal: CANAL_GERAL, membros: identities });
      }

      if (req.method === "GET" && url.pathname.startsWith("/api/identity/")) {
        const userId = decodeURIComponent(url.pathname.slice("/api/identity/".length));
        const identity = await keys.get(userId);
        if (!identity) return json(res, 404, { error: "unknown_user" });
        return json(res, 200, { identity });
      }

      // --- Web Push --------------------------------------------------------
      if (req.method === "GET" && url.pathname === "/api/push/vapid") {
        if (!push.pushDisponivel()) return json(res, 503, { error: "push_disabled" });
        return json(res, 200, { publicKey: push.vapidPublicKey() });
      }

      if (req.method === "POST" && url.pathname === "/api/push/challenge") {
        limparDesafios();
        const b = await body(req);
        const userId = String(b.userId ?? "").trim();
        const identity = await keys.get(userId);
        if (!identity) return json(res, 404, { error: "unknown_user" });
        const nonce = randomBytes(32).toString("base64");
        desafios.set(nonce, { userId, expira: Date.now() + 120_000 });
        return json(res, 200, { nonce });
      }

      if (req.method === "POST" && url.pathname === "/api/push/subscribe") {
        if (!push.pushDisponivel()) return json(res, 503, { error: "push_disabled" });
        const b = await body(req);
        const userId = String(b.userId ?? "").trim();
        const nonce = String(b.nonce ?? "");
        const desafio = desafios.get(nonce);
        desafios.delete(nonce);
        if (!desafio || desafio.userId !== userId || desafio.expira < Date.now()) {
          return json(res, 401, { error: "bad_challenge" });
        }
        const identity = await keys.get(userId);
        if (!identity) return json(res, 404, { error: "unknown_user" });
        const sig = Buffer.from(String(b.signature ?? ""), "base64");
        if (!(await keys.verifyChallenge(identity, Buffer.from(nonce, "base64"), sig))) {
          return json(res, 401, { error: "bad_signature" });
        }
        if (!(await push.salvarInscricao(userId, b.subscription))) {
          return json(res, 400, { error: "invalid_subscription" });
        }
        return json(res, 200, { ok: true });
      }

      if (req.method === "POST" && url.pathname === "/api/push/unsubscribe") {
        const b = await body(req);
        const userId = String(b.userId ?? "").trim();
        const nonce = String(b.nonce ?? "");
        const desafio = desafios.get(nonce);
        desafios.delete(nonce);
        if (!desafio || desafio.userId !== userId || desafio.expira < Date.now()) {
          return json(res, 401, { error: "bad_challenge" });
        }
        const identity = await keys.get(userId);
        if (!identity) return json(res, 404, { error: "unknown_user" });
        const sig = Buffer.from(String(b.signature ?? ""), "base64");
        if (!(await keys.verifyChallenge(identity, Buffer.from(nonce, "base64"), sig))) {
          return json(res, 401, { error: "bad_signature" });
        }
        const endpoint = String(b.endpoint ?? "");
        if (endpoint) await push.removerInscricao(userId, endpoint);
        else await push.limparInscricoes(userId);
        return json(res, 200, { ok: true });
      }

      if (req.method === "GET") {
        const rel = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
        const path = join(webDir, normalize(rel));
        if (!path.startsWith(webDir)) return json(res, 403, { error: "forbidden" });
        const file = await readFile(path);
        // sw.js NUNCA pode ir pro cache HTTP: senão o Chrome fica horas com
        // um worker velho e o push "parece quebrado".
        const eSw = rel === "sw.js";
        const estatico = rel.endsWith(".webmanifest") || rel.startsWith("icon-");
        res.writeHead(200, {
          "content-type": MIME[extname(path)] ?? "application/octet-stream",
          "content-security-policy": CSP,
          "referrer-policy": "no-referrer",
          "permissions-policy": "microphone=(self), camera=()",
          "x-content-type-options": "nosniff",
          "cache-control": eSw ? "no-store" : estatico ? "public, max-age=3600" : "no-store",
          ...(eSw ? { "service-worker-allowed": "/" } : {}),
        });
        return res.end(file);
      }

      json(res, 404, { error: "not_found" });
    } catch {
      // Sem detalhe de erro para o cliente e sem stack trace no log:
      // mensagens de erro são um canal de vazamento clássico.
      json(res, 400, { error: "bad_request" });
    }
  });
}
