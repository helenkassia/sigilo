import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const surface = { visible: true, dialog: false, visibilityState: "visible" };
globalThis.document = {
  get visibilityState() { return surface.visibilityState; },
  querySelectorAll: () => [],
  querySelector: (selector) => selector === ".painel"
    ? { getClientRects: () => surface.visible ? [{}] : [] }
    : surface.dialog ? {} : null,
};
const { iniciais, conversaVisivel } = await import("../../web/ui.js");

test("avatares derivam apenas do identificador local", () => {
  assert.equal(iniciais("ana.silva"), "AS");
  assert.equal(iniciais("bianca"), "BI");
  assert.equal(iniciais("a_b-c"), "AC");
});
test("leitura exige conversa visível, aba ativa e nenhum diálogo", () => {
  for (const [visible, dialog, visibilityState, expected] of [
    [true, false, "visible", true], [false, false, "visible", false],
    [true, true, "visible", false], [true, false, "hidden", false],
  ]) {
    Object.assign(surface, { visible, dialog, visibilityState });
    assert.equal(conversaVisivel(), expected);
  }
});
test("todos os controles usados pelo aplicativo existem no novo HTML", async () => {
  const html = await readFile(new URL("../../web/index.html", import.meta.url), "utf8");
  const app = await readFile(new URL("../../web/app.js", import.meta.url), "utf8");
  const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map((m) => m[1]);
  assert.equal(new Set(ids).size, ids.length, "IDs não se repetem");
  for (const [, id] of app.matchAll(/\$\("#([\w-]+)"\)/g)) assert.ok(ids.includes(id), id);
  assert.match(html, /<textarea[^>]+id="campo-msg"/);
  for (const id of ["trava", "nova-conversa", "sobre"]) assert.match(html, new RegExp(`<dialog[^>]+id="${id}"`));
});
test("a apresentação não adiciona dependências remotas", async () => {
  for (const file of ["index.html", "styles.css", "ui.js", "icons.svg"]) {
    const content = await readFile(new URL(`../../web/${file}`, import.meta.url), "utf8");
    assert.doesNotMatch(content, /(?:src|href)="https?:\/\//, file);
    assert.doesNotMatch(content, /@import|url\(\s*["']?https?:/i, file);
  }
});
