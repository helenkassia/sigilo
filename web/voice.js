import { AUDIO_MAX_BYTES, AUDIO_MAX_MS, AUDIO_TYPES, validarAudio } from "./crypto.js";

/** Uma gravação por vez; nenhum dado é persistido. Cancelar invalida awaits. */
export function criarGravador(onState, onError) {
  let current = null;
  const emit = (phase, extra = {}) => onState({ phase, ...extra });
  const release = (session) => {
    clearTimeout(session.deadline);
    clearInterval(session.ticker);
    for (const track of session.stream?.getTracks() ?? []) track.stop();
  };
  function cancelar() {
    const session = current;
    current = null;
    if (session) {
      if (session.recorder?.state !== "inactive" && session.recorder) session.recorder.stop();
      release(session);
      session.chunks.length = 0;
      session.audio?.bytes.fill(0);
    }
    emit("idle");
  }
  function falhar(session, message) {
    if (current !== session) return;
    cancelar();
    onError(message);
  }
  function parar() {
    const session = current;
    if (!session || session.recorder?.state !== "recording") return;
    session.elapsedMs = Math.min(AUDIO_MAX_MS, Math.max(1, performance.now() - session.started));
    emit("stopping");
    session.recorder.stop();
    release(session);
  }
  async function iniciar() {
    if (current) return;
    if (!navigator.mediaDevices?.getUserMedia || typeof MediaRecorder === "undefined") {
      return onError("Este navegador não oferece gravação de voz. Use um navegador atualizado em HTTPS.");
    }
    const mime = AUDIO_TYPES.find((type) => MediaRecorder.isTypeSupported(type));
    if (!mime) return onError("Este navegador não oferece um formato de áudio compatível.");
    const session = { chunks: [], size: 0 };
    current = session;
    emit("requesting");
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
      if (current !== session) {
        stream.getTracks().forEach((track) => track.stop());
        return;
      }
      session.stream = stream;
      const recorder = new MediaRecorder(stream, { mimeType: mime, audioBitsPerSecond: 32_000 });
      session.recorder = recorder;
      recorder.ondataavailable = ({ data }) => {
        if (current !== session || !data.size) return;
        session.size += data.size;
        if (session.size > AUDIO_MAX_BYTES) {
          return falhar(session, "O áudio excedeu 512 KiB e foi descartado. Grave uma mensagem mais curta.");
        }
        session.chunks.push(data);
      };
      recorder.onerror = () => falhar(session, "Não foi possível concluir a gravação. O áudio foi descartado.");
      recorder.onstop = async () => {
        release(session);
        if (current !== session) return;
        try {
          const blob = new Blob(session.chunks, { type: recorder.mimeType || mime });
          session.chunks.length = 0;
          const audio = {
            mime: blob.type,
            duracaoMs: session.elapsedMs ?? Math.min(AUDIO_MAX_MS, Math.max(1, performance.now() - session.started)),
            bytes: new Uint8Array(await blob.arrayBuffer()),
          };
          if (current !== session) { audio.bytes.fill(0); return; }
          validarAudio(audio);
          session.audio = audio;
          emit("ready", { audio });
        } catch {
          falhar(session, "A gravação ficou vazia ou incompatível. Tente novamente.");
        }
      };
      for (const track of stream.getAudioTracks()) track.addEventListener("ended", parar);
      session.started = performance.now();
      recorder.start(250);
      emit("recording", { elapsedMs: 0 });
      session.deadline = setTimeout(parar, AUDIO_MAX_MS);
      session.ticker = setInterval(() => {
        if (current === session && recorder.state === "recording") {
          const elapsedMs = performance.now() - session.started;
          if (elapsedMs >= AUDIO_MAX_MS) parar();
          else emit("recording", { elapsedMs });
        }
      }, 250);
    } catch (error) {
      falhar(session, error.name === "NotAllowedError"
        ? "Microfone não autorizado. Permita o acesso nas configurações deste site para gravar."
        : "Não foi possível acessar o microfone. Verifique o dispositivo e tente novamente.");
    }
  }
  return { iniciar, parar, cancelar };
}

export function liberarPlayer(player) {
  if (!player) return;
  player.pause();
  const url = player.getAttribute("src");
  player.removeAttribute("src");
  player.load();
  if (url?.startsWith("blob:")) URL.revokeObjectURL(url);
}
