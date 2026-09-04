import { test } from "node:test";
import assert from "node:assert/strict";
import * as C from "../../web/crypto.js";

async function identity(userId) {
  const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  return { userId, ecdhPriv: pair.privateKey, ecdhPub: await crypto.subtle.exportKey("jwk", pair.publicKey) };
}
const ana = await identity("ana"), bia = await identity("bia"), outsider = await identity("fora");
const recipients = [C.eu(ana), C.eu(bia)];
const context = { canal: "dm", dm: "bia" };
const voice = (size = 4096) => ({ mime: "audio/webm;codecs=opus", duracaoMs: 1500, bytes: new Uint8Array(size).fill(81) });
const decode = (env) => JSON.parse(Buffer.from(env, "base64").toString());
const encode = (env) => Buffer.from(JSON.stringify(env)).toString("base64");

test("texto v2 continua compatível", async () => {
  const envelope = await C.seal(ana, recipients, "mensagem anterior çã", context);
  assert.equal(decode(envelope).v, 2);
  assert.equal((await C.open(bia, C.eu(ana), envelope)).texto, "mensagem anterior çã");
});
test("voz real usa o módulo do navegador e abre para remetente e destinatário", async () => {
  const audio = voice(C.AUDIO_MAX_BYTES);
  const envelope = await C.sealAudio(ana, recipients, audio, context);
  assert.ok(Buffer.from(envelope, "base64").length < 1024 * 1024);
  for (const who of [ana, bia]) {
    const result = await C.open(who, C.eu(ana), envelope);
    assert.deepEqual(result.audio, audio);
  }
  await assert.rejects(C.open(outsider, C.eu(ana), envelope));
  await assert.rejects(C.open(bia, C.eu(outsider), envelope));
});
test("padding de voz é fixo; codec e duração não ficam no cabeçalho", async () => {
  const small = decode(await C.sealAudio(ana, recipients, voice(1), context));
  const large = decode(await C.sealAudio(ana, recipients, voice(C.AUDIO_MAX_BYTES), context));
  assert.equal(small.ct.length, large.ct.length);
  assert.equal(JSON.stringify(small).includes("audio/webm"), false);
  assert.equal("duracaoMs" in small, false);
});
test("voz autentica ciphertext e cabeçalho de roteamento", async () => {
  const envelope = await C.sealAudio(ana, recipients, voice(), context);
  for (const field of ["ct", "canal", "dm", "from", "v"]) {
    const modified = decode(envelope);
    modified[field] = field === "v" ? 2 : field === "ct" ? (modified.ct[0] === "A" ? "B" : "A") + modified.ct.slice(1) : "alterado";
    await assert.rejects(C.open(bia, C.eu(ana), encode(modified)));
  }
});
test("voz em grupo abre somente para os destinatários envelopados", async () => {
  const audio = voice();
  const envelope = await C.sealAudio(ana, recipients, audio, { canal: "#geral", dm: null });
  assert.deepEqual((await C.open(bia, C.eu(ana), envelope)).audio, audio);
  await assert.rejects(C.open(outsider, C.eu(ana), envelope));
});
test("entrada de voz rejeita tipos, tamanhos e durações inválidas", async () => {
  for (const audio of [voice(0), voice(C.AUDIO_MAX_BYTES + 1), { ...voice(), mime: "text/html" },
    { ...voice(), duracaoMs: 0 }, { ...voice(), duracaoMs: NaN }, { ...voice(), duracaoMs: C.AUDIO_MAX_MS + 1 }]) {
    await assert.rejects(C.sealAudio(ana, recipients, audio, context));
  }
});
