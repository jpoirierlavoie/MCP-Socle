export const UNSUPPORTED_PROTOCOL_VERSION = -32022;

export const PREMIERE_MODERNE = "2026-07-28";

export function estModerne(version: string): boolean {
  return version >= PREMIERE_MODERNE;
}

export function erreurVersion(
  demandee: string,
  servies: readonly string[],
): { code: number; message: string; data: { supported: string[]; requested: string } } {
  return {
    code: UNSUPPORTED_PROTOCOL_VERSION,
    message: "Unsupported protocol version",
    data: { supported: [...servies], requested: demandee },
  };
}

export function negocier(
  demandee: string,
  servies: readonly string[],
): { version: string } | { erreur: ReturnType<typeof erreurVersion> } {
  if (servies.includes(demandee)) return { version: demandee };
  return { erreur: erreurVersion(demandee, servies) };
}

export function versionAbsenteAdmise(methode: string, sertAvant2025_06_18: boolean): boolean {
  if (methode === "initialize") return true;
  return sertAvant2025_06_18;
}

export const VERSION_SANS_ENTETE = "2025-03-26";

export function negocierInitialize(demandee: unknown, servies: readonly string[]): string {
  if (typeof demandee === "string" && servies.includes(demandee)) {
    return demandee;
  }
  const heritee = servies.find((v) => !estModerne(v));
  if (heritee !== undefined) return heritee;
  if (servies.length === 0) {
    throw new Error("Au moins une version MCP doit être déclarée.");
  }
  return servies[servies.length - 1]!;
}
