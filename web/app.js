import * as C from "./crypto.js";
import { criarGravador, liberarPlayer } from "./voice.js";
import { prepararArquivo, arquivoDoTransfer, liberarUrl, liberarMidia } from "./file.js";
import { icone, iniciais, abrirDialogo, fecharDialogo, conversaVisivel } from "./ui.js";
import * as Push from "./push.js";
import { iniciarPrivacidade } from "./privacy.js";

const $ = (s) => document.querySelector(s);

// O navegador só expõe WebCrypto em contexto seguro (HTTPS ou localhost).
// Sem ele não há como cifrar nada — e um chat que promete E2EE e entrega
// texto puro é pior que nenhum chat. Então paramos aqui, visivelmente.
if (!window.isSecureContext || !crypto?.subtle) {
  document.querySelector("#inseguro").hidden = false;
  document.querySelector("#form-entrar")?.setAttribute("hidden", "");
  throw new Error("contexto inseguro");
}

const GERAL = "#geral";

const state = {
  identity: null,
  ws: null,
  conectado: false,
  maxEnvelopeBytes: 64 * 1024,
  /** { tipo: "geral" | "dm", peer?: identidade verificada } */
  canal: null,
  membros: [],
  suspeitos: [],
  novos: [],
  ttl: { padrao: 86400000, opcoes: [86400000] },
  ttlEscolhido: null,
  /**
   * Mensagens vivas, por conversa. Só em memória — nada de localStorage,
   * nada de IndexedDB. O que reaparece depois de um F5 vem do servidor, e
   * só vem o que ainda não expirou.
   */
  historico: new Map(),
  /** ref do envio -> agregado de entregas/leituras, para o canal geral. */
  refs: new Map(),
  /** Mensagens que chegaram antes de a tela estar pronta. */
  fila: [],
  /**
   * Envelopes que não abriram porque a chave fixada do remetente está
   * velha. Guardamos para reprocessar assim que a pessoa for reverificada —
   * a mensagem ainda está viva no servidor, só faltava confiança.
   */
  travadas: new Map(),
  /** Verificações em andamento: a trava é uma só, uma de cada vez. */
  verificando: new Set(),
  /**
   * Conversas diretas conhecidas nesta sessão: userId -> { peer, ultimaEm }.
   * Some junto com a sessão, como todo o resto — é uma lista do que está
   * vivo agora, não um histórico.
   */
  conversas: new Map(),
  /** Não lidas por conversa, zeradas quando você abre. */
  naoLidas: new Map(),
  /**
   * Mensagens que chegaram mas que você ainda NÃO viu: canal -> ids.
   * Confirmar leitura de algo que está numa conversa fechada seria mentir —
   * e, numa mensagem de queima, destruiria o texto antes de alguém ler.
   */
  porLer: new Map(),
};

const chaveCanal = (canal) => (canal.tipo === "geral" ? GERAL : canal.peer.userId);
const doCanal = (k) => state.historico.get(k) ?? state.historico.set(k, []).get(k);

// --- Entrada ---------------------------------------------------------------

/**
 * Nome que a pessoa digita -> identificador que o servidor aceita.
 * "João Silva" vira "joao.silva". Ninguém deveria precisar decorar a regra:
 * a gente mostra o resultado antes de enviar.
 */
function normalizarId(texto) {
  return texto
    .normalize("NFD").replace(/[̀-ͯ]/g, "")
    .toLowerCase()
    .replace(/\s+/g, ".")
    .replace(/[^a-z0-9._-]/g, "")
    .replace(/\.{2,}/g, ".")
    .replace(/^[._-]+|[._-]+$/g, "")
    .slice(0, 32);
}

const MOTIVOS = {
  invalid_user_id:
    "Identificador inválido. Use ao menos 2 caracteres — letras sem acento, números, ponto, hífen ou sublinhado.",
  key_change_requires_approval:
    "Já existe uma chave registrada para este identificador. Ou alguém já o usou, ou este é um dispositivo novo — rotação exige token entregue fora de banda.",
};

let rotationToken = null;
$("#campo-rotacao").addEventListener("input", (e) => (rotationToken = e.target.value.trim() || null));

$("#campo-eu").addEventListener("input", (e) => {
  const previa = normalizarId(e.target.value);
  const dica = $("#previa-id");
  dica.hidden = !e.target.value.trim() || previa === e.target.value.trim();
  dica.textContent = previa.length >= 2
    ? `você vai entrar como: ${previa}`
    : "identificador curto demais — use ao menos 2 caracteres";
});

/**
 * Entrar é escolher QUAL identidade deste dispositivo usar. Cada nome tem seu
 * próprio par de chaves guardado aqui; um nome diferente é outra pessoa, para
 * todos os efeitos — inclusive para saber quais mensagens são suas.
 */
let entrando = false;

async function entrar(userId) {
  // Dois "entrar" ao mesmo tempo (o automático da sessão e um clique, por
  // exemplo) registrariam duas identidades e abririam duas conexões.
  if (entrando) return;
  entrando = true;
  const botao = $("#form-entrar button[type=submit]");
  botao.disabled = true;
  botao.textContent = "Preparando seu espaço…";
  try {
    await realmenteEntrar(userId);
  } catch {
    aviso("Não foi possível entrar. Verifique a conexão e tente novamente.");
  } finally {
    entrando = false;
    botao.disabled = false;
    botao.innerHTML = `Entrar no Sigilo ${icone("arrow")}`;
  }
}

async function realmenteEntrar(userId) {
  state.identity = await C.loadIdentity(userId);

  const res = await fetch("/api/identity", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(rotationToken ? { "x-rotation-token": rotationToken } : {}),
    },
    body: JSON.stringify({ userId, ecdh: state.identity.ecdhPub, ecdsa: state.identity.ecdsaPub }),
  });

  if (res.status === 409) {
    $("#rotacao").hidden = false;
    return aviso(MOTIVOS.key_change_requires_approval);
  }
  if (!res.ok) {
    const { error } = await res.json().catch(() => ({}));
    return aviso(MOTIVOS[error] ?? `Falha ao registrar identidade (${error ?? res.status}).`);
  }

  $("#minha-fp").textContent = await C.fingerprint(state.identity.ecdhPub, state.identity.ecdsaPub);
  $("#eu-nome").textContent = userId;
  $("#eu-avatar").textContent = iniciais(userId);
  // Lembra a identidade só enquanto esta aba viver: um F5 mantém você,
  // fechar a aba esquece. Nada disso vai para o disco.
  try { sessionStorage.setItem("sigilo.eu", userId); } catch {}
  mostrar("conversa");
  status("Conectando…", "neutro");
  conectar();
  void sincronizarPush();
}

$("#form-entrar").addEventListener("submit", (e) => {
  e.preventDefault();
  const userId = normalizarId($("#campo-eu").value);
  if (userId.length < 2) return aviso(MOTIVOS.invalid_user_id);
  entrar(userId);
});

// Recarregar não deve custar a identidade — nem as mensagens ainda vivas,
// que o servidor reentrega assim que a conexão volta.
try {
  const anterior = sessionStorage.getItem("sigilo.eu");
  if (anterior) entrar(anterior);
} catch {}

$("#sair").addEventListener("click", async () => {
  if (state.identity) {
    try { await Push.desativarPush(state.identity); } catch {}
  }
  try { sessionStorage.removeItem("sigilo.eu"); } catch {}
  location.reload();
});

/** Queima vestígios da sessão na hora: memória, blobs, WS e sessionStorage. */
async function limparSessao() {
  document.body.classList.add("sessao-limpa");
  try { gravador.cancelar(); } catch {}
  try { descartarAnexo(); } catch {}
  for (const lista of state.historico.values()) {
    for (const msg of lista) liberarMensagem(msg);
  }
  state.historico.clear();
  state.refs.clear();
  state.fila.length = 0;
  state.travadas.clear();
  state.verificando.clear();
  state.conversas.clear();
  state.naoLidas.clear();
  state.porLer.clear();
  state.canal = null;
  state.membros = [];
  state.suspeitos = [];
  state.novos = [];
  state.conectado = false;
  if (state.ws) {
    state.ws.onmessage = null;
    state.ws.onclose = null;
    try { state.ws.close(); } catch {}
    state.ws = null;
  }
  const id = state.identity;
  state.identity = null;
  if (id) {
    try { await Push.desativarPush(id); } catch {}
  }
  try { sessionStorage.removeItem("sigilo.eu"); } catch {}
  location.replace(location.pathname + location.search);
}

// --- Push / PWA ------------------------------------------------------------

Push.registrarServiceWorker().catch(() => {});

async function sincronizarPush() {
  const opt = $("#push-opt");
  const nota = $("#push-nota");
  const campo = $("#campo-push");
  const btnTeste = $("#btn-testar-push");
  if (!opt || !campo) return;

  const st = await Push.estadoPush(state.identity);
  if (!st.disponivel) {
    opt.hidden = true;
    nota.hidden = true;
    if (btnTeste) btnTeste.hidden = true;
    return;
  }
  opt.hidden = false;
  nota.hidden = false;
  campo.checked = st.inscrito && st.permissao === "granted";
  if (btnTeste) btnTeste.hidden = !campo.checked;
}

$("#campo-push")?.addEventListener("change", async (e) => {
  const campo = e.target;
  if (!state.identity) {
    campo.checked = false;
    return;
  }
  campo.disabled = true;
  try {
    if (campo.checked) {
      await Push.ativarPush(state.identity);
      try { await Push.testarAvisoLocal(); } catch {}
      aviso("Avisos ativados. Se não apareceu um teste agora, libere notificações do Chrome no macOS.");
    } else {
      await Push.desativarPush(state.identity);
    }
  } catch (err) {
    campo.checked = false;
    const motivo = String(err?.message ?? err);
    if (motivo === "denied") aviso("Permissão de notificação negada neste navegador.");
    else if (motivo === "unsupported") aviso("Este navegador não oferece avisos em segundo plano.");
    else aviso("Não foi possível configurar os avisos.");
  } finally {
    campo.disabled = false;
    void sincronizarPush();
  }
});

$("#btn-testar-push")?.addEventListener("click", async () => {
  const btn = $("#btn-testar-push");
  if (btn) btn.disabled = true;
  try {
    await Push.testarAvisoLocal();
    aviso("Pedido de aviso enviado. Se não apareceu um banner, abra Ajustes → Notificações → Google Chrome e ligue os alertas.");
  } catch (err) {
    const motivo = String(err?.message ?? err);
    if (motivo === "denied") aviso("Permissão negada. No cadeado da URL do Chrome, permita notificações para este site.");
    else aviso("Falha ao testar aviso: " + motivo);
  } finally {
    if (btn) btn.disabled = false;
  }
});

// --- Conexão ---------------------------------------------------------------

function conectar() {
  // Trocar de identidade sem fechar a conexão anterior deixaria duas sessões
  // vivas na mesma aba, cada uma desenhando as mensagens que recebe.
  if (state.ws) {
    state.ws.onmessage = null;
    state.ws.onclose = null;
    state.ws.close();
  }

  const ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws`);
  state.ws = ws;

  ws.onmessage = async (ev) => {
    const m = JSON.parse(ev.data);

    if (m.type === "challenge") {
      // Provamos posse da chave privada assinando o desafio. Sem isto,
      // qualquer um se conectaria como qualquer um.
      return ws.send(JSON.stringify({
        type: "auth",
        userId: state.identity.userId,
        signature: await C.signChallenge(state.identity, m.nonce),
      }));
    }

    if (m.type === "ready") {
      state.conectado = true;
      state.maxEnvelopeBytes = m.maxEnvelopeBytes ?? 64 * 1024;
      state.ttl = m.ttl;
      montarSeletorTtl(m.ttl);
      status("conectado", "ok");
      await abrirGeral();
      // O servidor manda o que ainda está vivo logo depois do ready; só
      // processamos depois que a tela existe.
      const fila = state.fila.splice(0);
      for (const pendente of fila) await receber(pendente);
      return;
    }

    if (m.type === "denied") return status(`recusado: ${m.reason}`, "erro");
    // Alguém entrou (ou trocou de chave): a lista na tela ficou velha.
    if (m.type === "elenco") return void carregarElenco();
    if (m.type === "error") {
      if (m.ref) removerMensagem(m.ref);
      return aviso(m.reason === "envelope_too_large" ? "Mensagem recusada: excede o limite desta instalação." : m.reason);
    }
    if (m.type === "msg") return state.canal ? receber(m) : state.fila.push(m);

    if (m.type === "queued") {
      const item = state.refs.get(m.ref);
      if (!item) return;
      item.total = m.destinatarios;
      item.ids = m.ids;
      item.msg.expiraEm = m.expiraEm;
      pintarMeta(item.msg);
      return;
    }

    if (m.type === "delivered") {
      const item = state.refs.get(m.ref);
      if (item) { item.entregues++; pintarMeta(item.msg); }
      return;
    }

    if (m.type === "lida") {
      const item = state.refs.get(m.ref);
      if (item) { item.lidas++; pintarMeta(item.msg); }
      return;
    }

    if (m.type === "gone") {
      const item = state.refs.get(m.ref);
      if (m.to !== state.identity.userId) {
        // Cópia de outra pessoa: só atualiza o rodapé, se ainda estiver aqui.
        if (item) { item.expiradas++; pintarMeta(item.msg); }
        return;
      }
      // A cópia que acabou é a SUA. Depois de um F5 esta aba já não tem a
      // referência do envio, então procuramos também pelo id da cópia.
      const msg = item?.msg ?? acharMensagem(m.ref, m.id);
      if (!msg) return;
      // Queimou porque foi lida: o texto vai embora mas fica a lápide — você
      // precisa saber que chegou. Expirou ou você apagou: some inteira.
      if (m.motivo === "lida") virarLapide(msg);
      else removerMensagem(msg.ref, msg.id);
      return;
    }

    if (m.type === "sumiu") {
      // Apagada pelo remetente: some da sua tela agora.
      if (m.motivo === "apagada") return removerMensagem(m.id);
      // Queimada ao ser lida: o servidor já esqueceu, mas tirar da tela no
      // mesmo instante deixaria você sem ler a mensagem. Ela fica até você
      // sair — que é exatamente o que o rodapé dela promete.
      return marcarQueimada(m.id);
    }
  };

  ws.onclose = () => {
    state.conectado = false;
    gravador.cancelar();
    status("desconectado", "erro");
  };
}

// --- Canal geral -----------------------------------------------------------

async function carregarElenco() {
  const res = await fetch("/api/canal");
  if (!res.ok) return aviso("Não foi possível carregar o canal.");
  const { membros } = await res.json();

  state.membros = [];
  state.suspeitos = [];
  state.novos = [];

  for (const m of membros) {
    if (m.userId === state.identity.userId) continue;
    const check = await C.checkPin(m);

    if (check.status === "CHANGED") {
      // Excluído do envio. Não dá para saber daqui se trocou de aparelho
      // ou se alguém assumiu a identidade — e o custo de errar é alto.
      state.suspeitos.push(m);
      continue;
    }
    if (check.status === "new") {
      // Fixamos para detectar mudança daqui em diante, mas isso NÃO é
      // conferir: a marca só muda quando um humano comparar os números.
      await C.pins.set(m.userId, { ...m, conferido: false });
    }
    if (!check.conferido) state.novos.push(m);
    state.membros.push(m);
  }
  await pintarElenco();
}

async function pintarElenco() {
  const ul = $("#elenco");
  ul.textContent = "";
  for (const m of [...state.membros, ...state.suspeitos]) {
    const suspeito = state.suspeitos.includes(m);
    const novo = state.novos.includes(m);
    const li = document.createElement("li");
    li.className = suspeito ? "membro alarme" : novo ? "membro novo" : "membro";
    li.innerHTML = `<span class="avatar" aria-hidden="true"></span><span class="membro-info"><span class="quem"></span><span class="marca-estado"></span></span><span class="fp"></span>`;
    li.querySelector(".avatar").textContent = iniciais(m.userId);
    li.querySelector(".quem").textContent = m.userId;
    li.querySelector(".fp").textContent = await C.fingerprint(m.ecdh, m.ecdsa);
    li.querySelector(".marca-estado").textContent = suspeito
      ? "Chave alterada · conferir novamente"
      : novo ? "Identidade não verificada" : "Identidade verificada";

    // Todo membro é clicável: é assim que se sai de uma chave alterada, e
    // é assim que se confere alguém que ainda está só no "confiei de cara".
    li.tabIndex = 0;
    li.setAttribute("role", "button");
    const rever = async () => {
      const check = await C.checkPin(m);
      const fp = await C.fingerprint(m.ecdh, m.ecdsa);
      const ok = await verificar(m, check.status === "CHANGED" ? "CHANGED" : "new", fp);
      if (ok) await carregarElenco();
    };
    li.addEventListener("click", rever);
    li.addEventListener("keydown", (e) => (e.key === "Enter" || e.key === " ") && rever());
    ul.append(li);
  }
  const total = state.membros.length + state.suspeitos.length + 1;
  $("#contagem").textContent = `${total} ${total === 1 ? "pessoa" : "pessoas"}`;
  if (state.canal?.tipo === "geral") $("#sub-canal").textContent = `${total} ${total === 1 ? "pessoa" : "pessoas"} · espaço compartilhado`;
  $("#pessoas-alerta").hidden = state.suspeitos.length === 0 && state.novos.length === 0;
  atualizarAlertaChaves();
  $("#alerta-elenco").hidden = state.suspeitos.length === 0 && state.novos.length === 0;
  $("#alerta-elenco").textContent = [
    state.suspeitos.length
      ? `${state.suspeitos.length} com chave alterada — não recebem suas mensagens. Toque no nome para reverificar.`
      : "",
    state.novos.length ? `${state.novos.length} ainda não verificados por você` : "",
  ].filter(Boolean).join(" · ");
}

async function abrirGeral() {
  gravador.cancelar();
  await carregarElenco();
  if (state.canal) enterrarQueimadas(chaveCanal(state.canal));
  state.canal = { tipo: "geral" };
  state.naoLidas.delete(GERAL);
  $("#titulo-canal").textContent = "Sala geral";
  const total = state.membros.length + state.suspeitos.length + 1;
  $("#sub-canal").textContent = `${total} ${total === 1 ? "pessoa" : "pessoas"} · espaço compartilhado`;
  $("#canal-avatar").innerHTML = icone("people");
  $("#btn-pessoas").hidden = false;
  $("#painel-elenco").hidden = false;
  $("#form-msg").hidden = false;
  fecharNavegacao();
  atualizarAlertaChaves();
  pintarCanal();
  pintarConversas();
  confirmarLeituras(GERAL);
}

$("#btn-geral").addEventListener("click", abrirGeral);
$("#btn-recarregar").addEventListener("click", carregarElenco);

// --- Conversa 1:1 ----------------------------------------------------------

/**
 * Pede a conferência humana da impressão digital e devolve true se a pessoa
 * confirmou. É o único ponto do sistema onde a confiança é criada — nenhum
 * código pode fazer isso sozinho, por isso ele fica isolado aqui.
 *
 * Resolve para false se a pessoa fechar sem confirmar: recusar é uma
 * resposta válida, e deve ser a mais fácil de dar.
 */
function verificar(remote, status, fp) {
  return new Promise((resolve) => {
    const trava = $("#trava");
    const mudou = status === "CHANGED";
    trava.dataset.nivel = mudou ? "alarme" : "novo";
    $("#trava-titulo").textContent = mudou
      ? `A chave de ${remote.userId} mudou`
      : `É mesmo ${remote.userId}?`;
    $("#trava-texto").textContent = mudou
      ? "Isto acontece quando a pessoa troca de dispositivo, reinstala ou limpa o navegador — e também quando alguém se coloca no meio da conversa. Não dá para distinguir daqui. Confirme os números com ela por outro canal antes de continuar."
      : "Compare estes números com os que aparecem na tela dela, pessoalmente ou por um canal que você já confia. Não use este chat para conferir.";
    $("#trava-fp").textContent = fp;
    abrirDialogo("trava");

    const fechar = (ok) => {
      fecharDialogo("trava");
      $("#trava-ok").onclick = null;
      $("#trava-nao").onclick = null;
      trava.oncancel = null;
      resolve(ok);
    };
    $("#trava-ok").onclick = async () => {
      // Só aqui alguém vira "conferido": uma pessoa olhou os números e disse
      // que batem. Nenhum caminho automático escreve essa marca.
      $("#trava-ok").disabled = true;
      try {
        await C.pins.set(remote.userId, { ...remote, conferido: true });
        fechar(true);
      } catch { aviso("Não foi possível salvar a conferência. Tente novamente."); }
      finally { $("#trava-ok").disabled = false; }
    };
    $("#trava-nao").onclick = () => fechar(false);
    trava.oncancel = (e) => { e.preventDefault(); fechar(false); };
  });
}

$("#form-par").addEventListener("submit", async (e) => {
  e.preventDefault();
  const botao = $("#form-par button[type=submit]");
  if (botao.disabled) return;
  const id = normalizarId($("#campo-par").value);
  const erro = (texto) => { $("#erro-contato").textContent = texto; $("#erro-contato").hidden = false; };
  if (id.length < 2) return erro("Digite um identificador com pelo menos 2 caracteres.");
  if (id === state.identity.userId) return erro("Esse é o seu identificador. Procure outra pessoa.");
  botao.disabled = true;
  $("#erro-contato").hidden = true;
  try {
    const res = await fetch(`/api/identity/${encodeURIComponent(id)}`);
    if (!res.ok) return erro("Não encontramos essa pessoa. Confira o identificador com ela.");
    const remote = (await res.json()).identity;
    const check = await C.checkPin(remote);
    const fp = await C.fingerprint(remote.ecdh, remote.ecdsa);
    // Fechar durante a busca cancela o fluxo, sem abrir outro diálogo depois.
    if (!$("#nova-conversa").open) return;
    fecharDialogo("nova-conversa");
    if (check.status === "match" && check.conferido) return abrirDm(remote);
    if (await verificar(remote, check.status === "CHANGED" ? "CHANGED" : "new", fp)) abrirDm(remote);
  } catch { erro("Não foi possível buscar agora. Tente novamente."); }
  finally { botao.disabled = false; }
});

function abrirDm(remote) {
  if (state.canal) enterrarQueimadas(chaveCanal(state.canal));
  state.canal = { tipo: "dm", peer: remote };
  $("#titulo-canal").textContent = remote.userId;
  $("#sub-canal").textContent = "Conversa direta · só entre vocês";
  $("#canal-avatar").textContent = iniciais(remote.userId);
  $("#btn-pessoas").hidden = true;
  $("#painel-elenco").hidden = true;
  $("#form-msg").hidden = false;
  $("#campo-par").value = "";
  fecharNavegacao();
  atualizarAlertaChaves();
  state.naoLidas.delete(remote.userId);
  registrarConversa(remote);
  pintarCanal();
  confirmarLeituras(remote.userId);
}

// --- Envio -----------------------------------------------------------------

$("#form-msg").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!state.canal || voz.phase !== "idle" || enviando) return;
  if (anexo) {
    await enviarAnexoPendente();
    return;
  }
  const texto = $("#campo-msg").value;
  if (!texto.trim()) return;
  enviando = true;
  try {
    await enviarConteudo({ texto });
    if ($("#campo-msg").value === texto) { $("#campo-msg").value = ""; $("#campo-msg").rows = 1; }
  } catch (error) { aviso(error.message); }
  finally { enviando = false; }
});

let enviando = false;
let voz = { phase: "idle" };
/** Rascunho de anexo em memória; bytes zerados ao descartar. */
let anexo = null;
let anexoPreviaUrl = null;

function compositorOcupado() {
  return voz.phase !== "idle" || !!anexo || enviando;
}

function atualizarBotoesCompositor() {
  const idleVoz = voz.phase === "idle";
  const livre = idleVoz && !anexo;
  $("#btn-gravar").disabled = !livre;
  $("#btn-anexar").disabled = !livre;
  $("#btn-enviar-texto").disabled = !idleVoz;
  $("#campo-msg").placeholder = anexo
    ? "Legenda opcional…"
    : "Escreva uma mensagem…";
}

const gravador = criarGravador((next) => {
  const anterior = voz;
  voz = next;
  const idle = next.phase === "idle";
  $("#voz").dataset.fase = next.phase;
  $("#voz").hidden = idle;
  $("#btn-parar").hidden = next.phase !== "recording";
  $("#btn-enviar-voz").hidden = next.phase !== "ready";
  $("#voz-previa").hidden = next.phase !== "ready";
  $("#voz-status").textContent = next.phase === "requesting" ? "Aguardando permissão do microfone…" :
    next.phase === "recording" ? `Gravando · ${duracao(next.elapsedMs)} / 2m` :
    next.phase === "stopping" ? "Finalizando gravação…" :
    next.phase === "ready" ? `Áudio pronto · ${duracao(next.audio.duracaoMs)} · ainda não enviado` : "";
  if (anterior.phase === "ready" || idle) liberarPlayer($("#voz-previa"));
  if (next.phase === "ready") {
    $("#voz-previa").src = URL.createObjectURL(new Blob([next.audio.bytes], { type: next.audio.mime }));
  }
  atualizarBotoesCompositor();
}, aviso);

function descartarAnexo() {
  liberarUrl(anexoPreviaUrl);
  anexoPreviaUrl = null;
  anexo?.bytes.fill(0);
  anexo = null;
  $("#anexo").hidden = true;
  $("#anexo-img").hidden = true;
  $("#anexo-pdf").hidden = true;
  liberarMidia($("#anexo-img"));
  $("#campo-arquivo").value = "";
  atualizarBotoesCompositor();
}

function mostrarAnexo(arquivo) {
  liberarUrl(anexoPreviaUrl);
  anexoPreviaUrl = null;
  anexo?.bytes.fill(0);
  anexo = arquivo;
  $("#anexo").hidden = false;
  $("#anexo-status").textContent = arquivo.tipo === "pdf"
    ? `PDF pronto · ${arquivo.tamanhoTexto} · ainda não enviado`
    : `Imagem pronta · ${arquivo.tamanhoTexto} · ainda não enviada`;
  if (arquivo.tipo === "pdf") {
    $("#anexo-img").hidden = true;
    liberarMidia($("#anexo-img"));
    $("#anexo-pdf").hidden = false;
    $("#anexo-nome").textContent = arquivo.nome || "documento.pdf";
    $("#anexo-tamanho").textContent = arquivo.tamanhoTexto;
  } else {
    $("#anexo-pdf").hidden = true;
    $("#anexo-img").hidden = false;
    anexoPreviaUrl = URL.createObjectURL(new Blob([arquivo.bytes], { type: arquivo.mime }));
    $("#anexo-img").src = anexoPreviaUrl;
    $("#anexo-img").alt = arquivo.nome || "Prévia da imagem";
  }
  if (voz.phase !== "idle") gravador.cancelar();
  atualizarBotoesCompositor();
}

async function carregarAnexo(entrada) {
  if (!state.conectado) return aviso("Aguarde a conexão antes de anexar.");
  if (voz.phase !== "idle") return aviso("Finalize ou descarte a gravação antes de anexar.");
  if (enviando) return;
  try {
    const arquivo = await prepararArquivo(entrada, { texto: $("#campo-msg").value });
    if (state.canal?.tipo === "geral" && arquivo.bytes.length > 1024 * 1024) {
      aviso("Arquivo grande na sala geral: cada pessoa recebe uma cópia cifrada. Prefira TTL curto.");
    }
    mostrarAnexo(arquivo);
  } catch (error) {
    aviso(error.message);
  } finally {
    $("#campo-arquivo").value = "";
  }
}

async function enviarAnexoPendente() {
  if (!anexo || enviando) return;
  const rascunho = anexo;
  const texto = $("#campo-msg").value;
  const arquivo = {
    tipo: rascunho.tipo,
    mime: rascunho.mime,
    nome: rascunho.nome,
    texto,
    bytes: rascunho.bytes.slice(),
  };
  enviando = true;
  $("#btn-enviar-anexo").disabled = true;
  try {
    await enviarConteudo({ texto, arquivo }, () => anexo === rascunho);
    if (anexo === rascunho) descartarAnexo();
    if ($("#campo-msg").value === texto) { $("#campo-msg").value = ""; $("#campo-msg").rows = 1; }
  } catch (error) {
    arquivo.bytes.fill(0);
    aviso(error.message);
  } finally {
    enviando = false;
    $("#btn-enviar-anexo").disabled = false;
  }
}

$("#btn-anexar").addEventListener("click", () => {
  if (!state.conectado || compositorOcupado()) return aviso(state.conectado ? "Finalize ou descarte o rascunho atual antes de anexar." : "Aguarde a conexão antes de anexar.");
  $("#campo-arquivo").click();
});
$("#campo-arquivo").addEventListener("change", () => {
  const file = $("#campo-arquivo").files?.[0];
  if (file) carregarAnexo(file);
});
$("#btn-descartar-anexo").addEventListener("click", descartarAnexo);
$("#btn-enviar-anexo").addEventListener("click", () => enviarAnexoPendente());

$("#campo-msg").addEventListener("paste", (event) => {
  const file = arquivoDoTransfer(event.clipboardData);
  if (!file) return;
  event.preventDefault();
  carregarAnexo(file);
});

const formMsg = $("#form-msg");
formMsg.addEventListener("dragenter", (event) => {
  if (![...event.dataTransfer.types].includes("Files")) return;
  event.preventDefault();
  formMsg.classList.add("arrastando");
});
formMsg.addEventListener("dragover", (event) => {
  if (![...event.dataTransfer.types].includes("Files")) return;
  event.preventDefault();
  event.dataTransfer.dropEffect = "copy";
  formMsg.classList.add("arrastando");
});
formMsg.addEventListener("dragleave", (event) => {
  if (event.target === formMsg || !formMsg.contains(event.relatedTarget)) formMsg.classList.remove("arrastando");
});
formMsg.addEventListener("drop", (event) => {
  formMsg.classList.remove("arrastando");
  const file = arquivoDoTransfer(event.dataTransfer);
  if (!file) return;
  event.preventDefault();
  carregarAnexo(file);
});

$("#btn-gravar").addEventListener("click", () => {
  if (!state.conectado || enviando || anexo) return aviso(anexo ? "Descarte o anexo antes de gravar." : "Aguarde a conexão antes de gravar.");
  gravador.iniciar();
});
$("#btn-parar").addEventListener("click", gravador.parar);
$("#btn-descartar").addEventListener("click", gravador.cancelar);
$("#btn-enviar-voz").addEventListener("click", async () => {
  if (voz.phase !== "ready" || enviando) return;
  const rascunho = voz;
  // A cópia enviada tem vida própria; descartar o rascunho zera seus bytes.
  const audio = { ...voz.audio, bytes: voz.audio.bytes.slice() };
  enviando = true;
  $("#btn-enviar-voz").disabled = true;
  try {
    await enviarConteudo({ texto: "", audio }, () => voz === rascunho);
    if (voz === rascunho) gravador.cancelar();
  } catch (error) {
    audio.bytes.fill(0);
    aviso(error.message);
  } finally {
    enviando = false;
    $("#btn-enviar-voz").disabled = false;
  }
});

/** Áudio e PDF só confirmam leitura após interação deliberada. */
function precisaAbrir(msg) {
  return msg.tipo === "audio" || msg.tipo === "pdf";
}

async function enviarConteudo({ texto, audio, arquivo }, aindaValido = () => true) {
  if (!state.canal || !state.conectado || state.ws?.readyState !== WebSocket.OPEN) {
    throw new Error("Sem conexão. A mensagem não foi enviada.");
  }
  const destino = state.canal;
  if (destino.tipo === "dm" && state.suspeitos.some((p) => p.userId === destino.peer.userId)) {
    throw new Error("A chave desta pessoa mudou. Confira a identidade antes de enviar.");
  }

  const ref = `ref-${crypto.randomUUID()}`;
  const ttlMs = state.ttlEscolhido ?? state.ttl.padrao;
  const geral = destino.tipo === "geral";
  const canal = chaveCanal(destino);

  const queimar = $("#campo-queimar").checked;
  const tipo = arquivo ? arquivo.tipo : audio ? "audio" : "texto";
  const msg = {
    id: ref,
    ref,
    canal,
    lado: "enviada",
    quem: state.identity.userId,
    texto: arquivo ? (arquivo.texto || "") : texto,
    audio,
    arquivo,
    tipo,
    queimar,
    criadaEm: Date.now(),
    expiraEm: Date.now() + ttlMs, // provisório até o servidor confirmar
  };
  // Você entra na própria lista: sem uma cópia sua, sua mensagem sumiria da
  // sua tela no primeiro recarregamento e continuaria viva para os outros.
  const outros = geral ? [...state.membros] : [destino.peer];
  if (geral && outros.length === 0) {
    throw new Error("Ninguém mais no canal — não há para quem enviar.");
  }
  // Também protege DMs já abertas quando o pin mudou desde a abertura.
  for (const peer of outros) {
    if ((await C.checkPin(peer)).status !== "match") throw new Error("Confira novamente a chave do destinatário antes de enviar.");
  }
  const destinatarios = [...outros, C.eu(state.identity)];

  const context = {
    canal: geral ? GERAL : "dm",
    dm: geral ? null : destino.peer.userId,
  };
  const envelope = arquivo
    ? await C.sealFile(state.identity, destinatarios, arquivo, context)
    : audio
      ? await C.sealAudio(state.identity, destinatarios, audio, context)
      : await C.seal(state.identity, destinatarios, texto, context);
  const tamanho = envelope.length * 3 / 4 - (envelope.endsWith("==") ? 2 : envelope.endsWith("=") ? 1 : 0);
  if (tamanho > state.maxEnvelopeBytes) {
    throw new Error("Mensagem excede o limite desta instalação. Peça ao administrador para aumentar MAX_ENVELOPE_BYTES.");
  }
  if (state.canal !== destino || !aindaValido()) throw new Error("Envio cancelado: a conversa ou o rascunho mudou.");
  if (!state.conectado || state.ws?.readyState !== WebSocket.OPEN) throw new Error("Conexão perdida. A mensagem não foi enviada.");

  doCanal(canal).push(msg);
  state.refs.set(ref, { msg, total: outros.length, entregues: 0, lidas: 0, ids: [] });
  try { state.ws.send(JSON.stringify({
    type: "send",
    to: geral ? GERAL : destino.peer.userId,
    envelope,
    clientRef: ref,
    // Só recebe quem entrou no envelope. Membros com chave alterada ficam de
    // fora aqui, no cliente — o servidor não decide isso.
    para: destinatarios.map((d) => d.userId),
    ttlMs,
    queimar,
  })); } catch (error) { removerMensagem(ref); throw error; }
  if (!geral) registrarConversa(destino.peer);
  pintarCanal();
}

// --- Recepção --------------------------------------------------------------

async function receber(m) {
  try {
    const { from, canal: tipoCanal, dm } = C.cabecalho(m.envelope);
    const meu = from === state.identity.userId;

    // Para abrir, precisamos da chave pública de QUEM ENVIOU — que pode ser
    // você mesmo, quando o servidor devolve a sua própria cópia.
    const remetente = meu ? C.eu(state.identity) : await C.pins.get(from);
    if (!remetente) return travar(from, m);

    let texto, audio, arquivo;
    try {
      ({ texto, audio, arquivo } = await C.open(state.identity, remetente, m.envelope));
    } catch {
      // Quase sempre é isto: a chave fixada para essa pessoa não é mais a
      // que ela usa. Em vez de mandar o usuário procurar o caminho, a gente
      // abre a conferência aqui e reprocessa a mensagem se ele confirmar.
      return travar(from, m);
    }

    // Numa conversa direta, o "canal" é o outro lado — que muda conforme
    // quem está olhando.
    const canal = tipoCanal === GERAL ? GERAL : (meu ? dm : from);
    const lista = doCanal(canal);
    if (lista.some((x) => x.id === m.id)) {
      audio?.bytes.fill(0);
      arquivo?.bytes.fill(0);
      return;
    } // já está na tela

    // A cópia da mensagem que você acabou de mandar não deve aparecer duas
    // vezes: o item otimista já está lá, só precisa adotar o id real.
    if (meu) {
      const otimista = [...state.refs.values()].find((i) => i.ids?.includes(m.id));
      if (otimista) {
        audio?.bytes.fill(0);
        arquivo?.bytes.fill(0);
        otimista.msg.id = m.id;
        otimista.msg.expiraEm = m.expiraEm;
        pintarMeta(otimista.msg);
        return;
      }
    }

    const tipo = arquivo ? arquivo.tipo : audio ? "audio" : "texto";
    lista.push({
      id: m.id, canal, quem: from, texto, audio, arquivo, tipo,
      expiraEm: m.expiraEm, criadaEm: Date.now(), queimar: m.queimar === true,
      lado: meu ? "enviada" : "recebida",
    });

    // Conversa direta que ainda não estava na barra lateral aparece agora —
    // inclusive depois de um F5, quando o servidor reentrega o que vive.
    if (canal !== GERAL) {
      const peer = meu ? await C.pins.get(dm) : remetente;
      if (peer) registrarConversa(peer, Date.now());
    }
    if (!meu) marcarNaoLida(canal);

    pintarCanal();

    // Aviso local se a aba estiver em segundo plano (não depende do FCM).
    if (!meu) void Push.avisarLocalSeOculto();

    // A confirmação só sai quando a mensagem estiver de fato à sua frente.
    // Sua própria cópia não conta como leitura de ninguém.
    // Áudio e PDF esperam interação deliberada (play / abrir).
    if (!meu && !precisaAbrir({ tipo })) agendarLeitura(canal, m.id);
  } catch {
    aviso("Não foi possível processar uma mensagem recebida.");
  }
}

/**
 * Guarda a confirmação de leitura para quando a mensagem estiver visível de
 * verdade: conversa aberta e aba em primeiro plano. "Lida" precisa querer
 * dizer que alguém leu.
 */
function agendarLeitura(canal, id) {
  const pendentes = state.porLer.get(canal) ?? new Set();
  pendentes.add(id);
  state.porLer.set(canal, pendentes);
  confirmarLeituras(canal);
}

function confirmarLeituras(canal) {
  if (!state.canal || chaveCanal(state.canal) !== canal) return;
  if (!conversaVisivel()) return;
  if (!state.conectado || state.ws?.readyState !== WebSocket.OPEN) return;

  const pendentes = state.porLer.get(canal);
  if (!pendentes?.size) return;
  state.porLer.delete(canal);
  for (const id of pendentes) state.ws.send(JSON.stringify({ type: "read", id }));
}

// Voltar para a aba conta como olhar: o que estava à espera é confirmado.
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState !== "visible") {
    if (["requesting", "recording", "stopping"].includes(voz.phase)) gravador.cancelar();
    for (const player of document.querySelectorAll("audio")) player.pause();
  }
  if (state.canal) confirmarLeituras(chaveCanal(state.canal));
});

function liberarMensagem(msg) {
  liberarPlayer(msg.player);
  msg.player = null;
  liberarMidia(msg.midiaEl);
  msg.midiaEl = null;
  liberarUrl(msg.blobUrl);
  msg.blobUrl = null;
  msg.audio?.bytes.fill(0);
  msg.audio = null;
  msg.arquivo?.bytes.fill(0);
  msg.arquivo = null;
  msg.texto = "";
  state.porLer.get(msg.canal)?.delete(msg.id);
}

window.addEventListener("pagehide", () => {
  gravador.cancelar();
  descartarAnexo();
  for (const lista of state.historico.values()) for (const msg of lista) liberarMensagem(msg);
});
window.addEventListener("pageshow", (event) => { if (event.persisted) location.reload(); });

/** Encontra uma mensagem por qualquer uma das chaves que a identificam. */
function acharMensagem(...chaves) {
  const alvos = chaves.filter(Boolean);
  for (const lista of state.historico.values()) {
    for (const msg of lista) {
      if (alvos.some((c) => msg.id === c || msg.ref === c)) return msg;
    }
  }
  return null;
}

/** Tira uma mensagem da tela e da memória, por id ou por ref do envio. */
function removerMensagem(...chaves) {
  const alvos = chaves.filter(Boolean);
  for (const [canal, lista] of state.historico) {
    const restantes = lista.filter((msg) => {
      if (!alvos.some((c) => msg.id === c || msg.ref === c)) return true;
      liberarMensagem(msg);
      msg.el?.classList.add("sumindo");
      setTimeout(() => msg.el?.remove(), 400);
      state.refs.delete(msg.ref ?? msg.id);
      return false;
    });
    if (restantes.length !== lista.length) state.historico.set(canal, restantes);
  }
}

/**
 * O texto some, o registro de que houve uma mensagem fica. Sem isto, uma
 * mensagem de queima simplesmente evapora da tela de quem escreveu, e ela
 * não tem como saber se chegou a ser lida ou se expirou no vazio.
 */
function virarLapide(msg) {
  msg.lapide = true;
  liberarMensagem(msg);
  msg.el?.remove();
  msg.el = null;
  pintarCanal();
}

/**
 * A cópia no servidor já foi destruída; o que resta é esta tela. A mensagem
 * fica legível até você trocar de conversa ou recarregar — depois disso não
 * existe em lugar nenhum.
 */
function marcarQueimada(id) {
  for (const lista of state.historico.values()) {
    const msg = lista.find((x) => x.id === id);
    if (!msg) continue;
    msg.queimada = true;
    // A confirmação pode chegar depois de sair da conversa (ou noutra aba).
    if (!state.canal || chaveCanal(state.canal) !== msg.canal || (precisaAbrir(msg) && !msg.ouvida)) {
      virarLapide(msg);
      return;
    }
    pintarMeta(msg);
    return;
  }
}

/** Excluir é um pedido ao servidor: ele apaga todas as cópias e avisa todos. */
function excluir(msg) {
  // Manda as duas chaves: a referência local existe só na aba onde a
  // mensagem foi escrita, e o id é o que sobra depois de recarregar.
  state.ws.send(JSON.stringify({ type: "apagar", ref: msg.ref, id: msg.id }));
  removerMensagem(msg.ref, msg.id);
}

/**
 * Uma mensagem chegou de alguém em quem ainda não confiamos (ou cuja chave
 * mudou). Guardamos o envelope e levamos a pessoa direto à conferência.
 * Nada é decidido automaticamente: sem confirmação humana, a mensagem fica
 * travada até expirar sozinha.
 */
async function travar(quem, m) {
  const fila = state.travadas.get(quem) ?? [];
  if (!fila.some((x) => x.id === m.id)) fila.push(m);
  state.travadas.set(quem, fila);

  if (state.verificando.has(quem)) return;
  state.verificando.add(quem);
  try {
    const res = await fetch(`/api/identity/${encodeURIComponent(quem)}`);
    if (!res.ok) return aviso(`Mensagem de ${quem}, que não está mais registrado.`);
    const remote = (await res.json()).identity;

    const check = await C.checkPin(remote);
    const fp = await C.fingerprint(remote.ecdh, remote.ecdsa);
    aviso(
      check.status === "CHANGED"
        ? `${quem} está com uma chave diferente da que você fixou. Confira antes de ler.`
        : `Primeira mensagem de ${quem}. Confira a impressão digital antes de ler.`,
    );

    const ok = await verificar(remote, check.status === "CHANGED" ? "CHANGED" : "new", fp);
    if (!ok) return;

    await carregarElenco();
    const pendentes = state.travadas.get(quem) ?? [];
    state.travadas.delete(quem);
    for (const pendente of pendentes) await receber(pendente);
  } finally {
    state.verificando.delete(quem);
  }
}

/**
 * Registra (ou atualiza) uma conversa direta na barra lateral. `peer` é a
 * identidade fixada da outra pessoa — a mesma que usamos para cifrar.
 */
function registrarConversa(peer, quando = Date.now()) {
  const atual = state.conversas.get(peer.userId);
  state.conversas.set(peer.userId, {
    peer,
    ultimaEm: Math.max(quando, atual?.ultimaEm ?? 0),
  });
  pintarConversas();
}

function marcarNaoLida(canal) {
  const aberto = state.canal ? chaveCanal(state.canal) : null;
  if (canal === aberto && conversaVisivel()) return;
  state.naoLidas.set(canal, (state.naoLidas.get(canal) ?? 0) + 1);
  pintarConversas();
}

function pintarConversas() {
  const aberto = state.canal ? chaveCanal(state.canal) : null;

  const badgeGeral = $("#nao-lidas-geral");
  const geralNaoLidas = state.naoLidas.get(GERAL) ?? 0;
  badgeGeral.hidden = geralNaoLidas === 0;
  badgeGeral.textContent = String(geralNaoLidas);

  const ul = $("#conversas");
  ul.textContent = "";
  const lista = [...state.conversas.values()].sort((a, b) => b.ultimaEm - a.ultimaEm);
  $("#conversas-vazias").hidden = lista.length !== 0;
  $("#btn-geral").setAttribute("aria-current", String(aberto === GERAL));

  for (const { peer, ultimaEm } of lista) {
    const naoLidas = state.naoLidas.get(peer.userId) ?? 0;
    const li = document.createElement("li");
    li.className = "conversa";
    li.tabIndex = 0;
    li.setAttribute("role", "button");
    if (peer.userId === aberto) li.setAttribute("aria-current", "true");
    li.innerHTML = `<span class="avatar" aria-hidden="true"></span><span class="conversa-info"><span class="quem"></span><span class="resumo">Conversa privada</span></span><span class="direita"></span>`;
    li.querySelector(".avatar").textContent = iniciais(peer.userId);
    li.querySelector(".quem").textContent = peer.userId;

    const direita = li.querySelector(".direita");
    if (naoLidas > 0) {
      const b = document.createElement("span");
      b.className = "nao-lidas";
      b.textContent = String(naoLidas);
      direita.append(b);
    } else if (ultimaEm) {
      const q = document.createElement("span");
      q.className = "quando";
      q.textContent = horario(ultimaEm);
      direita.append(q);
    }

    const abrir = () => abrirDm(peer);
    li.addEventListener("click", abrir);
    li.addEventListener("keydown", (e) => (e.key === "Enter" || e.key === " ") && abrir());
    ul.append(li);
  }
}

const horario = (ms) =>
  new Date(ms).toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" });

// --- Tela ------------------------------------------------------------------

function montarSeletorTtl(ttl) {
  const sel = $("#campo-ttl");
  sel.textContent = "";
  for (const ms of ttl.opcoes) {
    const o = document.createElement("option");
    o.value = String(ms);
    o.textContent = prazoLegivel(ms);
    o.selected = ms === ttl.padrao;
    sel.append(o);
  }
  state.ttlEscolhido = ttl.padrao;
  sel.onchange = () => {
    state.ttlEscolhido = Number(sel.value);
    explicarEnvio();
  };
  $("#campo-queimar").onchange = explicarEnvio;
  explicarEnvio();
}

/** Uma frase que diz, em português, o que vai acontecer com a mensagem. */
function explicarEnvio() {
  const prazo = prazoLegivel(state.ttlEscolhido ?? state.ttl.padrao);
  $("#explica-envio").textContent = $("#campo-queimar").checked
    ? `Apaga do servidor ao ler, ouvir ou abrir o PDF. Sai daqui ao sair da conversa. Prazo máximo: ${prazo}.`
    : `Com ou sem leitura, o prazo é ${prazo}.`;
}

function prazoLegivel(ms) {
  if (ms % 86400000 === 0) return `${ms / 86400000} ${ms === 86400000 ? "dia" : "dias"}`;
  if (ms % 3600000 === 0) return `${ms / 3600000} ${ms === 3600000 ? "hora" : "horas"}`;
  if (ms % 60000 === 0) return `${ms / 60000} min`;
  return `${Math.round(ms / 1000)} s`;
}

/**
 * "30s", "5m", "1h", "2d" para valores redondos; "4m50s" para uma contagem
 * em andamento. O mesmo texto serve para configurar e para ver o tempo correr.
 */
function duracao(ms) {
  const s = Math.round(ms / 1000);
  if (s >= 86400) return `${Math.floor(s / 86400)}d${s % 86400 >= 3600 ? Math.floor((s % 86400) / 3600) + "h" : ""}`;
  if (s >= 3600) return `${Math.floor(s / 3600)}h${s % 3600 >= 60 ? Math.floor((s % 3600) / 60) + "m" : ""}`;
  if (s >= 60) return `${Math.floor(s / 60)}m${s % 60 ? (s % 60) + "s" : ""}`;
  return `${s}s`;
}

/**
 * Ao sair da conversa, o TEXTO de uma mensagem queimada vai embora — é o que
 * o rodapé dela promete. No lugar fica a lápide, igual à de quem enviou:
 * sumir sem deixar nada faria a conversa parecer que nunca aconteceu, e
 * quem leu tem o mesmo direito de saber que houve uma mensagem ali.
 *
 * A lápide vive nesta aba e só nela. Recarregar leva tudo — no servidor
 * nunca houve nada para levar.
 */
function enterrarQueimadas(canalKey) {
  gravador.cancelar();
  descartarAnexo();
  for (const msg of state.historico.get(canalKey) ?? []) {
    // Trocar de conversa interrompe o player e revoga o URL temporário.
    liberarPlayer(msg.player);
    msg.player = null;
    liberarMidia(msg.midiaEl);
    msg.midiaEl = null;
    liberarUrl(msg.blobUrl);
    msg.blobUrl = null;
    msg.el?.remove();
    msg.el = null;
    if (!msg.queimada) continue;
    msg.queimada = false;
    msg.lapide = true;
    liberarMensagem(msg);
  }
}

/** Redesenha a conversa aberta a partir do que ainda está vivo. */
function pintarCanal() {
  if (!state.canal) return;
  const linha = $("#linha");
  const noFim = linha.scrollHeight - linha.scrollTop - linha.clientHeight < 60;

  const elementos = [selo()];

  const mensagens = doCanal(chaveCanal(state.canal));
  if (mensagens.length === 0) elementos.push(vazio());

  let anterior = null;
  for (const msg of mensagens) {
    // Reusar o nó mantém a reprodução quando chega outra mensagem.
    if (msg.el) {
      elementos.push(msg.el);
      pintarMeta(msg);
      anterior = msg;
      continue;
    }
    const li = document.createElement("li");
    li.className = `msg ${msg.lado}`;
    if (msg.queimar) li.classList.add("queima");
    if (msg.queimada) li.classList.add("queimada");
    if (msg.lapide) li.classList.add("lapide");
    // Mensagens seguidas da mesma pessoa se agrupam: menos repetição de nome,
    // leitura mais rápida.
    const emenda = anterior && anterior.quem === msg.quem && anterior.lado === msg.lado;
    if (emenda) li.classList.add("emenda");

    li.innerHTML = `
      <span class="quem"></span>
      <p class="corpo"></p>
      <span class="meta"></span>
      <span class="acoes"></span>`;
    const autor = li.querySelector(".quem");
    autor.textContent = msg.quem;
    autor.hidden = msg.lado !== "recebida" || emenda;
    li.querySelector(".corpo").textContent = msg.lapide
      ? msg.tipo === "audio" ? "áudio reproduzido e removido daqui"
        : msg.tipo === "pdf" ? "PDF aberto e removido daqui"
        : msg.tipo === "imagem" ? "imagem visualizada e destruída"
        : "mensagem visualizada e destruída"
      : (msg.arquivo || msg.audio) ? "" : msg.texto;
    if (msg.audio && !msg.lapide) {
      const corpo = li.querySelector(".corpo");
      const legenda = document.createElement("span");
      legenda.className = "voz-legenda";
      legenda.textContent = `Mensagem de voz · ${duracao(msg.audio.duracaoMs)}`;
      const player = document.createElement("audio");
      player.controls = true;
      player.preload = "metadata";
      player.setAttribute("aria-label", `Mensagem de voz de ${msg.quem}`);
      player.src = URL.createObjectURL(new Blob([msg.audio.bytes], { type: msg.audio.mime }));
      player.addEventListener("play", () => {
        for (const outro of document.querySelectorAll("audio")) if (outro !== player) outro.pause();
        if ((!msg.queimada && Date.now() >= msg.expiraEm) || !state.conectado) {
          player.pause();
          aviso("Áudio expirado ou sem conexão. A reprodução foi interrompida.");
        }
      });
      player.addEventListener("playing", () => {
        if (player.paused || !state.canal || chaveCanal(state.canal) !== msg.canal ||
            !conversaVisivel() || !state.conectado) { player.pause(); return; }
        if (msg.lado !== "recebida" || msg.ouvida) return;
        msg.ouvida = true;
        agendarLeitura(msg.canal, msg.id);
      });
      player.addEventListener("error", () => aviso("Este navegador não conseguiu reproduzir o áudio. Tente um navegador compatível com o formato enviado."));
      msg.player = player;
      corpo.append(legenda, player);
    }
    if (msg.arquivo && !msg.lapide) montarAnexoNaBolha(msg, li.querySelector(".corpo"));

    if (msg.lado === "enviada" && !msg.lapide) {
      const botao = document.createElement("button");
      botao.type = "button";
      botao.className = "acao";
      botao.textContent = "excluir";
      botao.title = "Apaga para todo mundo, agora";
      botao.addEventListener("click", () => excluir(msg));
      li.querySelector(".acoes").append(botao);
    }

    elementos.push(li);
    msg.el = li;
    pintarMeta(msg);
    anterior = msg;
  }

  const desejados = new Set(elementos);
  for (const el of [...linha.children]) if (!desejados.has(el)) el.remove();
  elementos.forEach((el, index) => {
    if (linha.children[index] !== el) linha.insertBefore(el, linha.children[index] ?? null);
  });
  for (const msg of mensagens) pintarMeta(msg);

  if (noFim) linha.scrollTop = mensagens.length ? linha.scrollHeight : 0;
}

function vazio() {
  const li = document.createElement("li");
  li.className = "vazio";
  li.innerHTML = `<span class="vazio-icone">${icone("chat")}</span><h2></h2><p></p>`;
  li.querySelector("h2").textContent = state.canal?.tipo === "geral" ? "A conversa começa com um oi." : "Um espaço só de vocês.";
  li.querySelector("p").textContent = state.canal?.tipo === "geral"
    ? "Compartilhe uma ideia, mande um áudio ou anexe uma imagem. Todo mundo da sala pode participar."
    : "Nenhuma mensagem por aqui agora. Que tal começar uma nova conversa?";
  return li;
}

function confirmarAberturaArquivo(msg) {
  if (msg.lado !== "recebida" || msg.ouvida) return;
  if (!state.canal || chaveCanal(state.canal) !== msg.canal || !conversaVisivel() || !state.conectado) return;
  msg.ouvida = true;
  agendarLeitura(msg.canal, msg.id);
}

function montarAnexoNaBolha(msg, corpo) {
  const wrap = document.createElement("div");
  wrap.className = "midia";
  const url = URL.createObjectURL(new Blob([msg.arquivo.bytes], { type: msg.arquivo.mime }));
  msg.blobUrl = url;

  if (msg.arquivo.tipo === "imagem") {
    const img = document.createElement("img");
    img.className = "midia-img";
    img.src = url;
    img.alt = msg.arquivo.nome || `Imagem de ${msg.quem}`;
    img.addEventListener("click", () => abrirLightbox(url, img.alt));
    msg.midiaEl = img;
    wrap.append(img);
  } else {
    const box = document.createElement("div");
    box.className = "midia-pdf";
    const frame = document.createElement("iframe");
    frame.title = msg.arquivo.nome || `PDF de ${msg.quem}`;
    frame.setAttribute("sandbox", "allow-same-origin");
    frame.loading = "lazy";
    const acoes = document.createElement("div");
    acoes.className = "midia-acoes";
    const abrir = document.createElement("button");
    abrir.type = "button";
    abrir.className = "secundario";
    abrir.innerHTML = `${icone("expand")} Abrir PDF`;
    const revelar = () => {
      if ((!msg.queimada && Date.now() >= msg.expiraEm) || !state.conectado) {
        aviso("PDF expirado ou sem conexão.");
        return;
      }
      if (!frame.src) frame.src = url;
      confirmarAberturaArquivo(msg);
    };
    abrir.addEventListener("click", () => {
      revelar();
      const win = window.open(url, "_blank", "noopener,noreferrer");
      if (!win) aviso("O navegador bloqueou a nova aba. Use o preview abaixo.");
    });
    const ver = document.createElement("button");
    ver.type = "button";
    ver.className = "discreto";
    ver.textContent = "Ver aqui";
    ver.addEventListener("click", revelar);
    // Preview embutido só após intenção — evita marcar leitura só por scroll.
    acoes.append(abrir, ver);
    const nome = document.createElement("span");
    nome.className = "voz-legenda";
    nome.textContent = msg.arquivo.nome || "documento.pdf";
    box.append(nome, acoes, frame);
    msg.midiaEl = frame;
    wrap.append(box);
  }

  if (msg.texto) {
    const legenda = document.createElement("span");
    legenda.className = "midia-legenda";
    legenda.textContent = msg.texto;
    wrap.append(legenda);
  }
  corpo.append(wrap);
}

function abrirLightbox(url, alt) {
  const img = $("#lightbox-img");
  img.src = url;
  img.alt = alt || "";
  abrirDialogo("lightbox");
}

$("#btn-fechar-lightbox").addEventListener("click", () => {
  const img = $("#lightbox-img");
  img.removeAttribute("src");
  img.alt = "";
  fecharDialogo("lightbox");
});
$("#lightbox").addEventListener("close", () => {
  const img = $("#lightbox-img");
  img.removeAttribute("src");
  img.alt = "";
});

function pintarMeta(msg) {
  if (!msg.el?.isConnected) return;
  const resta = Math.max(0, msg.expiraEm - Date.now());
  const item = state.refs.get(msg.ref ?? msg.id);
  const verboLer = msg.tipo === "audio" ? "iniciaram reprodução"
    : msg.tipo === "pdf" ? "abriram" : "leram";
  const verboLida = msg.tipo === "audio" ? "reprodução iniciada"
    : msg.tipo === "pdf" ? "aberto" : "lida";

  const partes = [horario(msg.criadaEm ?? Date.now())];
  if (msg.lapide) {
    if (msg.tipo === "audio") {
      partes.push("reprodução iniciada · áudio removido daqui");
      msg.el.querySelector(".meta").textContent = partes.join(" · ");
      return;
    }
    if (msg.tipo === "pdf") {
      partes.push("aberto · PDF removido daqui");
      msg.el.querySelector(".meta").textContent = partes.join(" · ");
      return;
    }
    if (msg.lado === "recebida") {
      partes.push(`você leu · ${msg.tipo === "imagem" ? "a imagem" : "o texto"} não existe mais`);
    } else {
      const quantos = item && item.total > 1 ? `por ${item.lidas} de ${item.total} ` : "";
      partes.push(`lida ${quantos}· ${msg.tipo === "imagem" ? "a imagem" : "o texto"} não existe mais`.replace("  ", " "));
    }
    msg.el.querySelector(".meta").textContent = partes.join(" · ");
    return;
  }
  if (msg.queimada) {
    // Já não existe no servidor: nada de contagem regressiva aqui.
    partes.push(precisaAbrir(msg)
      ? "removido do servidor · disponível aqui até sair ou expirar"
      : "destruída — visível só até você sair desta conversa");
    msg.el.querySelector(".meta").textContent = partes.join(" · ");
    msg.el.classList.add("queimada");
    return;
  }
  if (msg.queimar) {
    if (msg.tipo === "audio") partes.push("queima ao começar a ouvir · sai daqui ao sair");
    else if (msg.tipo === "pdf") partes.push("queima ao abrir · sai daqui ao sair");
    else partes.push(msg.lado === "enviada" ? "some ao ser lida" : "some quando você sair");
  }
  partes.push(`${duracao(resta)} restantes`);
  if (item && item.total > 1) partes.push(`${item.lidas}/${item.total} ${verboLer}`);
  else if (item && item.lidas) partes.push(verboLida);

  msg.el.querySelector(".meta").textContent = partes.join(" · ");
}

/**
 * Um relógio só para a tela inteira. Cada mensagem some no seu instante,
 * lida ou não — é o servidor que manda, e aqui a gente só acompanha.
 */
setInterval(() => {
  const agora = Date.now();
  for (const [canal, lista] of state.historico) {
    const vivas = lista.filter((msg) => {
      // Queimada e lápide ficam até a pessoa sair — o prazo já não as rege.
      if (msg.lapide || (msg.queimada && !precisaAbrir(msg))) return true;
      if (msg.expiraEm > agora) return true;
      liberarMensagem(msg);
      msg.el?.classList.add("sumindo");
      setTimeout(() => msg.el?.remove(), 600);
      state.refs.delete(msg.ref ?? msg.id);
      return false;
    });
    if (vivas.length !== lista.length) state.historico.set(canal, vivas);
    for (const msg of vivas) pintarMeta(msg);
  }
}, 1000);

/**
 * O selo de criptografia que abre a conversa. Diz a verdade inteira em duas
 * linhas: o que protege, e que o resto está a um toque de distância. A
 * segunda parte importa tanto quanto a primeira — um aviso que só promete
 * faz a pessoa confiar em coisas que o sistema não garante.
 */
function selo() {
  const li = document.createElement("li");
  li.className = "selo";
  li.tabIndex = 0;
  li.setAttribute("role", "button");

  const geral = state.canal?.tipo === "geral";
  li.innerHTML = `${icone("lock")}<span class="selo-texto"></span>`;
  li.querySelector(".selo-texto").textContent = geral
    ? "Ponta a ponta · Todos na sala recebem · Saiba mais"
    : "Ponta a ponta · Só os participantes recebem · Saiba mais";

  const abrir = () => abrirDialogo("sobre");
  li.addEventListener("click", abrir);
  li.addEventListener("keydown", (e) => (e.key === "Enter" || e.key === " ") && abrir());
  return li;
}

$("#sobre-ok").addEventListener("click", () => fecharDialogo("sobre"));
for (const id of ["btn-privacidade", "btn-seguranca"]) $("#" + id).addEventListener("click", () => abrirDialogo("sobre"));

function mostrar(tela) {
  document.body.dataset.tela = tela;
  for (const s of document.querySelectorAll("main[data-tela]")) s.hidden = s.dataset.tela !== tela;
}
function status(texto, tipo) {
  $("#status").textContent = texto.charAt(0).toUpperCase() + texto.slice(1);
  $("#status").dataset.tipo = tipo;
}
let avisoTimer;
function aviso(texto) {
  const el = $("#aviso");
  $("#aviso-texto").textContent = texto;
  el.hidden = false;
  clearTimeout(avisoTimer);
  avisoTimer = setTimeout(() => (el.hidden = true), 10000);
}

// --- Navegação e acessibilidade --------------------------------------------

$("#btn-fechar-aviso").addEventListener("click", () => { $("#aviso").hidden = true; clearTimeout(avisoTimer); });
for (const id of ["btn-nova", "btn-nova-grande"]) {
  $("#" + id).addEventListener("click", () => {
    $("#erro-contato").hidden = true;
    abrirDialogo("nova-conversa");
    $("#campo-par").focus();
  });
}
$("#btn-fechar-nova").addEventListener("click", () => fecharDialogo("nova-conversa"));
$("#campo-msg").addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey && !event.isComposing) {
    event.preventDefault();
    $("#form-msg").requestSubmit();
  }
});
$("#campo-msg").addEventListener("input", () => {
  // Fallback para navegadores sem field-sizing; nenhum conteúdo sai da aba.
  if (!CSS.supports("field-sizing", "content")) $("#campo-msg").rows = Math.min(4, $("#campo-msg").value.split("\n").length);
});

function fecharNavegacao() {
  $("#app").dataset.nav = "closed";
  $("#app").dataset.info = "closed";
  $("#btn-menu").setAttribute("aria-expanded", "false");
  $("#btn-pessoas").setAttribute("aria-expanded", "false");
}
function retomarConversa() {
  if (!state.canal) return;
  if (conversaVisivel()) { state.naoLidas.delete(chaveCanal(state.canal)); pintarConversas(); }
  pintarCanal();
  confirmarLeituras(chaveCanal(state.canal));
}
$("#btn-menu").addEventListener("click", () => {
  if (state.canal) enterrarQueimadas(chaveCanal(state.canal));
  $("#app").dataset.nav = "open";
  $("#app").dataset.info = "closed";
  $("#btn-menu").setAttribute("aria-expanded", "true");
  $("#btn-fechar-nav").focus();
});
$("#btn-fechar-nav").addEventListener("click", () => { fecharNavegacao(); retomarConversa(); $("#btn-menu").focus(); });
function mostrarPessoas(aberto) {
  if (aberto && state.canal && matchMedia("(max-width: 960px)").matches) enterrarQueimadas(chaveCanal(state.canal));
  $("#app").dataset.info = aberto ? "open" : "closed";
  $("#app").dataset.nav = "closed";
  $("#btn-menu").setAttribute("aria-expanded", "false");
  $("#btn-pessoas").setAttribute("aria-expanded", String(aberto));
  if (aberto) $("#btn-fechar-pessoas").focus();
  else { retomarConversa(); $("#btn-pessoas").focus(); }
}
$("#btn-pessoas").addEventListener("click", () => mostrarPessoas($("#app").dataset.info !== "open"));
$("#btn-fechar-pessoas").addEventListener("click", () => mostrarPessoas(false));
function atualizarAlertaChaves() {
  const suspeitos = state.canal?.tipo === "dm"
    ? state.suspeitos.filter((p) => p.userId === state.canal.peer.userId) : state.suspeitos;
  $("#alerta-chaves").hidden = !suspeitos.length;
  $("#alerta-chaves-texto").textContent = state.canal?.tipo === "dm"
    ? "A chave deste contato mudou. Confira a identidade antes de enviar."
    : `${suspeitos.length} ${suspeitos.length === 1 ? "pessoa com chave alterada não recebe" : "pessoas com chaves alteradas não recebem"} suas mensagens.`;
}
$("#btn-revisar-chaves").addEventListener("click", async () => {
  if (state.canal?.tipo !== "dm") return mostrarPessoas(true);
  const remote = state.suspeitos.find((p) => p.userId === state.canal.peer.userId);
  if (!remote) return;
  const fp = await C.fingerprint(remote.ecdh, remote.ecdsa);
  if (await verificar(remote, "CHANGED", fp)) { await carregarElenco(); abrirDm(remote); }
});
document.addEventListener("sigilo:ocultar", () => {
  if (["requesting", "recording", "stopping"].includes(voz.phase)) gravador.cancelar();
  for (const player of document.querySelectorAll("audio")) player.pause();
});
document.addEventListener("sigilo:visibilidade", retomarConversa);
for (const breakpoint of ["(max-width: 700px)", "(max-width: 960px)"]) {
  matchMedia(breakpoint).addEventListener("change", () => {
    if (!conversaVisivel()) document.dispatchEvent(new Event("sigilo:ocultar"));
    retomarConversa();
  });
}

iniciarPrivacidade({
  onAviso: (texto) => aviso(texto),
  onSobre: () => abrirDialogo("sobre"),
  onOcultar: () => document.dispatchEvent(new Event("sigilo:ocultar")),
  onVisivel: () => {
    if (state.canal) {
      confirmarLeituras(chaveCanal(state.canal));
      retomarConversa();
    }
  },
  onQueimar: limparSessao,
  temRegistros: () => {
    for (const lista of state.historico.values()) {
      if (lista.length > 0) return true;
    }
    return false;
  },
});
