// ---------------------------------------------------------------------------
// Sigilo :: avisos e barreiras leves de privacidade
//
// O navegador não consegue impedir captura, gravação ou “salvar como”.
// Aqui: lembrar com tom educativo, reduzir acidentes e queimar a sessão
// quando a pessoa pedir (botão ou Esc Esc Esc).
// ---------------------------------------------------------------------------

const $ = (s) => document.querySelector(s);

const AVISO_CONTEXTO =
  "Menu de contexto, arrastar e salvar tiram o conteúdo do Sigilo. Prefira não registrar o que aparece aqui.";
const AVISO_CAPTURAR =
  "Captura de tela ou impressão saem do Sigilo. O que for registrado fica fora da proteção da conversa.";

/**
 * @param {{
 *   onAviso: (texto: string) => void,
 *   onSobre: () => void,
 *   onOcultar: () => void,
 *   onVisivel: () => void,
 *   onQueimar: () => void | Promise<void>,
 *   temRegistros: () => boolean,
 * }} hooks
 */
export function iniciarPrivacidade(hooks) {
  const overlay = $("#overlay-sigilo");
  const fab = $("#btn-queimar-sessao");
  const faixaSobre = $("#btn-faixa-sobre");
  const linha = $("#linha");
  let blurTimer = 0;
  let flashTimer = 0;
  let escTimes = [];
  let queimando = false;

  function emConversa() {
    return document.body.dataset.tela === "conversa" && !document.body.classList.contains("sessao-limpa");
  }

  function temRegistros() {
    if (typeof hooks.temRegistros === "function") return !!hooks.temRegistros();
    return !!document.querySelector("#linha .msg");
  }

  function mostrarOverlay(forcado = false) {
    if (!overlay || (!emConversa() && !forcado)) return;
    document.body.classList.add("sigilo-oculto");
    overlay.hidden = false;
    overlay.setAttribute("aria-hidden", "false");
    hooks.onOcultar?.();
  }

  function ocultarOverlay() {
    if (!overlay) return;
    document.body.classList.remove("sigilo-oculto");
    overlay.hidden = true;
    overlay.setAttribute("aria-hidden", "true");
  }

  function avaliarFoco() {
    if (!emConversa()) {
      ocultarOverlay();
      return;
    }
    // Diálogos do próprio app não escondem a conversa — a pessoa ainda
    // está no Sigilo. Só aba/janela fora de foco.
    const fora =
      document.visibilityState !== "visible" || !document.hasFocus();
    if (fora) mostrarOverlay();
    else {
      ocultarOverlay();
      hooks.onVisivel?.();
    }
  }

  function agendarAvaliacao(ms = 80) {
    clearTimeout(blurTimer);
    blurTimer = setTimeout(avaliarFoco, ms);
  }

  function flashOverlay() {
    if (!emConversa()) return;
    mostrarOverlay(true);
    clearTimeout(flashTimer);
    flashTimer = setTimeout(() => {
      if (document.visibilityState === "visible" && document.hasFocus()) ocultarOverlay();
    }, 1600);
  }

  function alvoSensivel(el) {
    return !!el?.closest?.("#linha, #lightbox, #anexo, #anexo-img, #lightbox-img, .midia, .msg");
  }

  document.addEventListener("contextmenu", (e) => {
    if (!emConversa() || !alvoSensivel(e.target)) return;
    e.preventDefault();
    hooks.onAviso?.(AVISO_CONTEXTO);
  });

  document.addEventListener("dragstart", (e) => {
    if (!emConversa() || !alvoSensivel(e.target)) return;
    e.preventDefault();
    hooks.onAviso?.(AVISO_CONTEXTO);
  });

  document.addEventListener("keydown", (e) => {
    if (queimando) return;

    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "p") {
      if (!emConversa()) return;
      e.preventDefault();
      hooks.onAviso?.(AVISO_CAPTURAR);
      flashOverlay();
      return;
    }

    if (e.key === "PrintScreen") {
      if (!emConversa()) return;
      hooks.onAviso?.(AVISO_CAPTURAR);
      flashOverlay();
      return;
    }

    if (e.key !== "Escape") return;
    if (document.querySelector("dialog[open]")) return;
    if (!emConversa() || !temRegistros()) return;

    const agora = Date.now();
    escTimes = escTimes.filter((t) => agora - t < 800);
    escTimes.push(agora);
    if (escTimes.length >= 3) {
      escTimes = [];
      e.preventDefault();
      void queimarAgora();
    }
  });

  document.addEventListener("visibilitychange", () => agendarAvaliacao(0));
  window.addEventListener("blur", () => agendarAvaliacao());
  window.addEventListener("focus", () => agendarAvaliacao());

  faixaSobre?.addEventListener("click", () => hooks.onSobre?.());
  fab?.addEventListener("click", () => void queimarAgora());

  async function queimarAgora() {
    if (queimando) return;
    queimando = true;
    document.body.classList.add("sessao-limpa");
    if (fab) fab.hidden = true;
    ocultarOverlay();
    try {
      await hooks.onQueimar?.();
    } catch {
      // Mesmo com falha parcial, tira a sessão da tela.
      try { sessionStorage.removeItem("sigilo.eu"); } catch {}
      location.replace(location.pathname + location.search);
    }
  }

  function sincronizarFab() {
    if (!fab) return;
    // Só aparece com conversa aberta e algum registro vivo na sessão.
    fab.hidden = !emConversa() || !temRegistros();
  }

  const observer = new MutationObserver(sincronizarFab);
  observer.observe(document.body, { attributes: true, attributeFilter: ["data-tela", "class"] });
  if (linha) observer.observe(linha, { childList: true, subtree: true });
  sincronizarFab();

  return { avaliarFoco, queimarAgora, sincronizarFab };
}
