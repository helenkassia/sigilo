/**
 * Duração em unidades humanas: "45s", "10m", "2h", "1d".
 * Um número puro é lido como segundos — a unidade mais provável de ser
 * digitada errado é a implícita, então ela precisa ser a menos surpreendente.
 */
const UNIDADE: Record<string, number> = { s: 1_000, m: 60_000, h: 3_600_000, d: 86_400_000 };

export function parseDuration(texto: string): number {
  const m = /^\s*(\d+(?:\.\d+)?)\s*([smhd])?\s*$/i.exec(texto);
  if (!m) throw new Error(`duração inválida: ${texto} (use 30s, 10m, 2h, 1d)`);
  return Math.round(Number(m[1]) * UNIDADE[(m[2] ?? "s").toLowerCase()]!);
}

export function formatDuration(ms: number): string {
  for (const [u, f] of [["d", 86_400_000], ["h", 3_600_000], ["m", 60_000], ["s", 1_000]] as const) {
    if (ms % f === 0 && ms >= f) return `${ms / f}${u}`;
  }
  return `${ms}ms`;
}
