// ---------------------------------------------------------------------------
// Sigilo :: anexos (imagem / PDF) em memória
//
// Lê o arquivo no browser, valida MIME + magic bytes, comprime imagem se
// passar do limite, e nunca grava em disco da aplicação. O blob resultante
// só vive até o envio ou o descarte.
// ---------------------------------------------------------------------------

import {
  FILE_MAX_BYTES,
  FILE_TYPES,
  IMAGE_TYPES,
  PDF_TYPE,
  detectarMimeArquivo,
  validarArquivo,
} from "./crypto.js";

const LADO_MAX = 2048;
const QUALIDADE = 0.85;

export function liberarUrl(url) {
  if (typeof url === "string" && url.startsWith("blob:")) URL.revokeObjectURL(url);
}

export function liberarMidia(el) {
  if (!el) return;
  const url = el.getAttribute("src");
  el.removeAttribute("src");
  if (el.tagName === "IFRAME") el.removeAttribute("srcdoc");
  liberarUrl(url);
}

function tamanhoLegivel(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(bytes < 10 * 1024 ? 1 : 0)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

async function lerBytes(blob) {
  return new Uint8Array(await blob.arrayBuffer());
}

function canvasParaBlob(canvas, mime, qualidade) {
  return new Promise((resolve, reject) => {
    canvas.toBlob((blob) => (blob ? resolve(blob) : reject(new Error("Falha ao comprimir a imagem."))), mime, qualidade);
  });
}

async function comprimirImagem(bytes, mime) {
  if (mime === "image/gif") return { bytes, mime };
  const blob = new Blob([bytes], { type: mime });
  const bitmap = await createImageBitmap(blob);
  try {
    let { width, height } = bitmap;
    const maior = Math.max(width, height);
    if (maior > LADO_MAX) {
      const escala = LADO_MAX / maior;
      width = Math.max(1, Math.round(width * escala));
      height = Math.max(1, Math.round(height * escala));
    }
    const canvas = document.createElement("canvas");
    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext("2d", { alpha: mime === "image/png" });
    if (!ctx) throw new Error("Não foi possível processar esta imagem.");
    ctx.drawImage(bitmap, 0, 0, width, height);

    const candidatos = mime === "image/png"
      ? [["image/png"], ["image/webp", QUALIDADE], ["image/jpeg", QUALIDADE]]
      : mime === "image/webp"
        ? [["image/webp", QUALIDADE], ["image/jpeg", QUALIDADE]]
        : [["image/jpeg", QUALIDADE], ["image/webp", QUALIDADE]];

    let melhor = { bytes, mime };
    for (const [tipo, q] of candidatos) {
      try {
        const out = await canvasParaBlob(canvas, tipo, q);
        const next = new Uint8Array(await out.arrayBuffer());
        if (next.length < melhor.bytes.length) melhor = { bytes: next, mime: tipo };
        if (melhor.bytes.length <= FILE_MAX_BYTES) break;
      } catch { /* codec indisponível neste browser */ }
    }
    return melhor;
  } finally {
    bitmap.close?.();
  }
}

/**
 * Converte File/Blob em anexo validado pronto para sealFile.
 * @returns {{ tipo:"imagem"|"pdf", mime:string, nome:string, texto:string, bytes:Uint8Array, tamanhoTexto:string }}
 */
export async function prepararArquivo(entrada, { texto = "", nome } = {}) {
  if (!entrada || !(entrada instanceof Blob)) {
    throw new Error("Nenhum arquivo selecionado.");
  }
  if (entrada.size > FILE_MAX_BYTES * 3) {
    throw new Error("Arquivo grande demais. Use imagem ou PDF de até 4 MiB.");
  }

  let bytes = await lerBytes(entrada);
  let mime = detectarMimeArquivo(bytes);
  if (!mime) {
    throw new Error("Formato não suportado. Use JPEG, PNG, WebP, GIF ou PDF.");
  }
  if (!FILE_TYPES.includes(mime)) {
    throw new Error("Formato não suportado. Use JPEG, PNG, WebP, GIF ou PDF.");
  }

  if (IMAGE_TYPES.includes(mime) && bytes.length > FILE_MAX_BYTES) {
    const comprimido = await comprimirImagem(bytes, mime);
    bytes.fill(0);
    bytes = comprimido.bytes;
    mime = comprimido.mime;
  }

  if (bytes.length > FILE_MAX_BYTES) {
    bytes.fill(0);
    throw new Error(`Arquivo acima de 4 MiB mesmo após compressão (${tamanhoLegivel(entrada.size)}).`);
  }

  const arquivo = {
    tipo: mime === PDF_TYPE ? "pdf" : "imagem",
    mime,
    nome: (nome ?? entrada.name ?? (mime === PDF_TYPE ? "documento.pdf" : "imagem")).toString().slice(0, 200),
    texto: typeof texto === "string" ? texto : "",
    bytes,
  };
  validarArquivo(arquivo);
  return { ...arquivo, tamanhoTexto: tamanhoLegivel(bytes.length) };
}

/** Extrai o primeiro arquivo útil de um DataTransfer (paste/drop). */
export function arquivoDoTransfer(dt) {
  if (!dt) return null;
  if (dt.files?.length) {
    for (const file of dt.files) {
      if (FILE_TYPES.includes(file.type) || /\.(jpe?g|png|webp|gif|pdf)$/i.test(file.name || "")) {
        return file;
      }
    }
  }
  if (dt.items) {
    for (const item of dt.items) {
      if (item.kind === "file" && (FILE_TYPES.includes(item.type) || item.type.startsWith("image/"))) {
        const file = item.getAsFile();
        if (file) return file;
      }
    }
  }
  return null;
}
