// Componentes de apresentação locais. Sem fontes, ícones ou scripts externos.
export const icone = (nome) => `<svg class="icon" aria-hidden="true"><use href="icons.svg#${nome}"/></svg>`;
export function iniciais(nome) {
  const partes = nome.split(/[._\s-]+/).filter(Boolean);
  return (partes.length > 1 ? partes[0][0] + partes.at(-1)[0] : nome.slice(0, 2)).toUpperCase();
}
export function conversaVisivel() {
  return document.visibilityState === "visible" &&
    !!document.querySelector(".painel")?.getClientRects().length &&
    !document.querySelector("dialog[open]");
}
export function abrirDialogo(id) {
  document.dispatchEvent(new Event("sigilo:ocultar"));
  const dialog = document.getElementById(id);
  dialog.hidden = false;
  if (!dialog.open) dialog.showModal();
}
export function fecharDialogo(id) {
  const dialog = document.getElementById(id);
  dialog.close();
  dialog.hidden = true;
}
for (const dialog of document.querySelectorAll("dialog")) {
  dialog.addEventListener("close", () => {
    dialog.hidden = true;
    document.dispatchEvent(new Event("sigilo:visibilidade"));
  });
}
