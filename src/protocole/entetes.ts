import { CLEF_VERSION } from "./meta";

export const HEADER_MISMATCH = -32020;

const NOM_ATTENDU: Record<string, "name" | "uri"> = {
  "tools/call": "name",
  "resources/read": "uri",
  "prompts/get": "name",
};

export function decoderSentinelle(valeur: string): string | null {
  if (!valeur.startsWith("=?base64?") || !valeur.endsWith("?=")) return valeur;
  const charge = valeur.slice("=?base64?".length, -"?=".length);
  try {
    const octets = Uint8Array.from(atob(charge), (c) => c.charCodeAt(0));
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(octets);
  } catch {
    return null;
  }
}

export interface CorpsAValider {
  method: string;
  params?: Record<string, unknown>;
  versionMeta?: unknown;
}

export interface OptionsValidationEntetes {
  exigerVersionMeta?: boolean;
}

export function validerEntetes(
  entetes: Headers,
  corps: CorpsAValider,
  options?: OptionsValidationEntetes,
): string | null {
  const version = entetes.get("MCP-Protocol-Version");
  if (version === null) {
    return "En-tête « MCP-Protocol-Version » manquant.";
  }
  if (corps.versionMeta !== undefined) {
    if (typeof corps.versionMeta !== "string") {
      return "La version annoncée dans « _meta » doit être une chaîne de caractères.";
    }
    if (corps.versionMeta !== version) {
      return `« MCP-Protocol-Version » (${version}) ne correspond pas à la version du corps (${corps.versionMeta}).`;
    }
  }
  const params = corps.params;
  let versionMetaPresente = typeof corps.versionMeta === "string";
  if (params !== undefined && Object.hasOwn(params, "_meta") && params._meta !== undefined) {
    const meta = params._meta;
    if (typeof meta !== "object" || meta === null || Array.isArray(meta)) {
      return "« params._meta » doit être un objet.";
    }
    const metaRec = meta as Record<string, unknown>;
    if (Object.hasOwn(metaRec, CLEF_VERSION) && metaRec[CLEF_VERSION] !== undefined) {
      const v = metaRec[CLEF_VERSION];
      if (typeof v !== "string") {
        return `« params._meta["${CLEF_VERSION}"] » doit être une chaîne de caractères.`;
      }
      if (v !== version) {
        return `« MCP-Protocol-Version » (${version}) ne correspond pas à la version du corps (${v}).`;
      }
      versionMetaPresente = true;
    }
  }
  if (options?.exigerVersionMeta && !versionMetaPresente) {
    return `« _meta["${CLEF_VERSION}"] » manquant pour ${corps.method}.`;
  }

  const methode = entetes.get("Mcp-Method");
  if (methode === null) return "En-tête « Mcp-Method » manquant.";
  if (methode !== corps.method) {
    return `« Mcp-Method » (${methode}) ne correspond pas à la méthode du corps (${corps.method}).`;
  }

  const champ = Object.hasOwn(NOM_ATTENDU, corps.method) ? NOM_ATTENDU[corps.method] : undefined;
  if (champ === undefined) return null;

  const brut = entetes.get("Mcp-Name");
  if (brut === null) return `En-tête « Mcp-Name » manquant pour ${corps.method}.`;

  const decode = decoderSentinelle(brut);
  if (decode === null) return "« Mcp-Name » porte une sentinelle base64 illisible.";

  const attendu = corps.params?.[champ];
  if (typeof attendu !== "string") {
    return `« params.${champ} » est absent du corps, alors que « Mcp-Name » est présent.`;
  }
  if (decode !== attendu) {
    return `« Mcp-Name » (${decode}) ne correspond pas à « params.${champ} » (${attendu}).`;
  }

  return null;
}
