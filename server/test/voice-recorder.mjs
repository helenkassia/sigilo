import { test } from "node:test";
import assert from "node:assert/strict";
import { criarGravador, liberarPlayer } from "../../web/voice.js";
import { AUDIO_MAX_BYTES, AUDIO_MAX_MS } from "../../web/crypto.js";

const flush = () => new Promise((r) => setImmediate(r));
function setup(t) {
  const track = { stopped: false, stop() { this.stopped = true; }, addEventListener() {} };
  const stream = { getTracks: () => [track], getAudioTracks: () => [track] };
  const frames = [], errors = [];
  let recorder;
  class FakeRecorder {
    static isTypeSupported(type) { return type.startsWith("audio/webm"); }
    constructor(stream, opts) { this.mimeType = opts.mimeType; this.state = "inactive"; recorder = this; }
    start() { this.state = "recording"; }
    stop() {
      this.state = "inactive";
      queueMicrotask(() => { this.ondataavailable?.({ data: new Blob([new Uint8Array(128).fill(37)]) }); this.onstop?.(); });
    }
  }
  for (const [obj, key, value] of [[globalThis, "MediaRecorder", FakeRecorder],
    [navigator, "mediaDevices", { getUserMedia: async () => stream }]]) {
    const original = Object.getOwnPropertyDescriptor(obj, key);
    Object.defineProperty(obj, key, { value, writable: true, configurable: true });
    t.after(() => original ? Object.defineProperty(obj, key, original) : delete obj[key]);
  }
  const ctl = criarGravador((s) => frames.push(s), (s) => errors.push(s));
  t.after(() => ctl.cancelar());
  return { ctl, stream, track, frames, errors, get recorder() { return recorder; } };
}
test("gravar, parar e descartar desliga microfone e zera bytes", async (t) => {
  const s = setup(t);
  await s.ctl.iniciar();
  assert.equal(s.frames.at(-1).phase, "recording");
  s.ctl.parar();
  await flush();
  assert.equal(s.track.stopped, true);
  const ready = s.frames.at(-1);
  assert.equal(ready.phase, "ready");
  assert.equal(ready.audio.bytes.length, 128);
  assert.equal(ready.audio.bytes[0], 37);
  s.ctl.cancelar();
  assert.equal(s.frames.at(-1).phase, "idle");
  assert.ok(ready.audio.bytes.every((b) => b === 0));
});
test("cancelamento durante permissão fecha stream que chegar atrasado", async (t) => {
  const s = setup(t);
  let accept;
  navigator.mediaDevices.getUserMedia = () => new Promise((r) => { accept = r; });
  const pending = s.ctl.iniciar();
  s.ctl.cancelar();
  accept(s.stream);
  await pending;
  assert.equal(s.track.stopped, true);
  assert.equal(s.frames.at(-1).phase, "idle");
  assert.equal(s.recorder, undefined);
});
test("permissão negada não deixa gravador preso", async (t) => {
  const s = setup(t);
  navigator.mediaDevices.getUserMedia = async () => { throw new DOMException("denied", "NotAllowedError"); };
  await s.ctl.iniciar();
  assert.equal(s.frames.at(-1).phase, "idle");
  assert.match(s.errors[0], /não autorizado/);
});
test("limite de bytes descarta gravação sem disponibilizar envio", async (t) => {
  const s = setup(t);
  await s.ctl.iniciar();
  s.recorder.ondataavailable({ data: new Blob([new Uint8Array(AUDIO_MAX_BYTES + 1)]) });
  await flush();
  assert.equal(s.track.stopped, true);
  assert.equal(s.frames.at(-1).phase, "idle");
  assert.equal(s.frames.some((f) => f.phase === "ready"), false);
  assert.match(s.errors[0], /excedeu/);
});
test("limite de 2 minutos para automaticamente", async (t) => {
  const s = setup(t);
  t.mock.timers.enable({ apis: ["setTimeout", "setInterval"] });
  await s.ctl.iniciar();
  t.mock.timers.tick(AUDIO_MAX_MS);
  await flush();
  assert.equal(s.recorder.state, "inactive");
  assert.equal(s.track.stopped, true);
  assert.equal(s.frames.at(-1).phase, "ready");
});
test("duplo clique não cria duas capturas; cancelar impede callback tardio", async (t) => {
  const s = setup(t);
  let calls = 0;
  navigator.mediaDevices.getUserMedia = async () => { calls++; return s.stream; };
  await Promise.all([s.ctl.iniciar(), s.ctl.iniciar()]);
  assert.equal(calls, 1);
  s.ctl.parar();
  s.ctl.cancelar();
  await flush();
  assert.equal(s.frames.at(-1).phase, "idle");
  assert.equal(s.frames.some((f) => f.phase === "ready"), false);
});
test("limpeza do player pausa reprodução, remove src e revoga URL", (t) => {
  const revoked = [];
  t.mock.method(URL, "revokeObjectURL", (url) => revoked.push(url));
  const player = { src: "blob:teste", pause() { this.paused = true; }, getAttribute() { return this.src; },
    removeAttribute() { this.src = null; }, load() { this.loaded = true; } };
  liberarPlayer(player);
  assert.equal(player.paused, true);
  assert.equal(player.src, null);
  assert.equal(player.loaded, true);
  assert.deepEqual(revoked, ["blob:teste"]);
});
