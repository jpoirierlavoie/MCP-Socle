const PREFIXE = "io.modelcontextprotocol/";

export const CLEF_VERSION = `${PREFIXE}protocolVersion`;
export const CLEF_CLIENT = `${PREFIXE}clientInfo`;
export const CLEF_CAPACITES = `${PREFIXE}clientCapabilities`;
export const CLEF_SERVEUR = `${PREFIXE}serverInfo`;

export interface InfoClient {
  name?: string;
  version?: string;
}

export interface MetaRequete {
  protocolVersion?: string;
  clientInfo?: InfoClient;
  clientCapabilities?: Record<string, unknown>;
}

function estObjetSimple(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function lireMeta(params?: Record<string, unknown>): MetaRequete {
  if (!estObjetSimple(params)) return {};
  const meta = params._meta;
  if (!estObjetSimple(meta)) return {};

  const clientRaw = meta[CLEF_CLIENT];
  let clientInfo: InfoClient | undefined;
  if (estObjetSimple(clientRaw)) {
    clientInfo = {
      ...(typeof clientRaw.name === "string" ? { name: clientRaw.name } : {}),
      ...(typeof clientRaw.version === "string" ? { version: clientRaw.version } : {}),
    };
  }

  const capRaw = meta[CLEF_CAPACITES];
  return {
    protocolVersion:
      typeof meta[CLEF_VERSION] === "string" ? (meta[CLEF_VERSION] as string) : undefined,
    clientInfo,
    clientCapabilities: estObjetSimple(capRaw) ? capRaw : undefined,
  };
}

export function clientLisible(info?: InfoClient): string | undefined {
  if (!info || typeof info.name !== "string" || info.name.length === 0) return undefined;
  return typeof info.version === "string" && info.version.length > 0
    ? `${info.name}/${info.version}`
    : info.name;
}

export function avecServerInfo<T extends Record<string, unknown>>(
  resultat: T,
  serverInfo: { name: string; title?: string; version: string },
): T & { _meta: Record<string, unknown> } {
  const meta = estObjetSimple(resultat._meta) ? resultat._meta : {};
  return { ...resultat, _meta: { ...meta, [CLEF_SERVEUR]: serverInfo } };
}

export type PorteeCache = "public" | "private";

export const RESULTATS_CACHABLES = [
  "server/discover",
  "tools/list",
  "prompts/list",
  "resources/list",
  "resources/templates/list",
  "resources/read",
] as const;

export function avecCache<T extends Record<string, unknown>>(
  resultat: T,
  ttlMs: number,
  cacheScope: PorteeCache,
): T & { ttlMs: number; cacheScope: PorteeCache } {
  if (!Number.isInteger(ttlMs) || ttlMs < 0) {
    throw new Error(`ttlMs doit être un entier >= 0 (reçu : ${ttlMs}).`);
  }
  return { ...resultat, ttlMs, cacheScope };
}

export function complet<T extends Record<string, unknown>>(
  resultat: T,
): T & { resultType: "complete" } {
  return { ...resultat, resultType: "complete" };
}

export interface OptionsHabillage {
  moderne: boolean;
  ttlMs?: number;
  cacheScope?: PorteeCache;
  serverInfo?: { name: string; title?: string; version: string };
}

export function habillerResultat<T extends Record<string, unknown>>(
  brut: T,
  options: OptionsHabillage,
): Record<string, unknown> {
  if (!options.moderne) return brut;
  let r: Record<string, unknown> = complet(brut);
  if (options.ttlMs !== undefined) {
    r = avecCache(r, options.ttlMs, options.cacheScope ?? "public");
  }
  if (options.serverInfo !== undefined) {
    r = avecServerInfo(r, options.serverInfo);
  }
  return r;
}
