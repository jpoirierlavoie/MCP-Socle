/**
 * En-têtes de requête de `2026-07-28`, et leur validation contre le CORPS.
 *
 * POURQUOI CETTE VALIDATION EXISTE, et pourquoi elle n'est pas une formalité. Le transport
 * recopie dans des en-têtes HTTP certains champs du corps JSON-RPC, pour qu'un
 * intermédiaire — répartiteur, passerelle, WAF — puisse router et mesurer sans analyser le
 * corps. La vulnérabilité est immédiate si les deux divergent : **l'intermédiaire décide sur
 * l'en-tête, le serveur exécute sur le corps.** D'où l'obligation de refuser tout écart.
 *
 * Corollaire pour ce dépôt, écrit à la §4.3 marche 11 : ne JAMAIS décider d'un quota ou
 * d'une classe d'outil sur `Mcp-Name` seul. L'en-tête sert à router ; le corps fait foi.
 */

import { CLEF_VERSION } from "./meta";

/** Faute de concordance en-tête ↔ corps. */
export const HEADER_MISMATCH = -32020;

/** Les méthodes pour lesquelles `Mcp-Name` est EXIGÉ, et le champ qu'il doit refléter. */
const NOM_ATTENDU: Record<string, "name" | "uri"> = {
  "tools/call": "name",
  "resources/read": "uri",
  "prompts/get": "name",
};

/**
 * Décode la sentinelle `=?base64?…?=`.
 *
 * Une valeur d'en-tête HTTP ne peut porter que de l'ASCII visible. Un nom d'outil ou un URI
 * qui sort de cet ensemble — accent, espace de bord, retour à la ligne — voyage donc encodé,
 * et **le serveur DOIT décoder avant de comparer**. Sans cela, tout nom accentué
 * divergerait de son corps et serait refusé.
 *
 * Rend la valeur telle quelle si elle ne porte pas la sentinelle. Rend `null` si elle la
 * porte mais que le contenu est illisible — un refus vaut mieux qu'une comparaison faite
 * sur une chaîne à moitié décodée.
 */
export function decoderSentinelle(valeur: string): string | null {
  if (!valeur.startsWith("=?base64?") || !valeur.endsWith("?=")) return valeur;
  const charge = valeur.slice("=?base64?".length, -"?=".length);
  try {
    // `atob` rend une chaîne d'octets ; il faut la relire en UTF-8, sinon « é » revient en
    // deux caractères et la comparaison échoue sur un nom pourtant correct.
    const octets = Uint8Array.from(atob(charge), (c) => c.charCodeAt(0));
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(octets);
  } catch {
    return null;
  }
}

/** Ce que l'appelant doit fournir pour que la validation soit possible. */
export interface CorpsAValider {
  method: string;
  params?: Record<string, unknown>;
  /** Version annoncée dans `_meta`, si elle y est. Accepte `unknown` pour rejeter les non-chaînes. */
  versionMeta?: unknown;
}

export interface OptionsValidationEntetes {
  /** Exige la présence de `_meta["io.modelcontextprotocol/protocolVersion"]` sous forme de chaîne. */
  exigerVersionMeta?: boolean;
}

/**
 * Valide les en-têtes contre le corps.
 *
 * Rend `null` si tout concorde, sinon le message de refus — que l'appelant emballe en
 * `400` + `-32020`.
 *
 * ⚠ N'APPELER QUE SOUS UNE RÉVISION MODERNE. Les révisions antérieures n'exigent ni
 *   `Mcp-Method` ni `Mcp-Name` ; les réclamer là-bas refuserait des clients conformes.
 */
export function validerEntetes(
  entetes: Headers,
  corps: CorpsAValider,
  options?: OptionsValidationEntetes,
): string | null {
  // ── MCP-Protocol-Version ──────────────────────────────────────────────────────────────
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

  // ── Mcp-Method ────────────────────────────────────────────────────────────────────────
  const methode = entetes.get("Mcp-Method");
  if (methode === null) return "En-tête « Mcp-Method » manquant.";
  if (methode !== corps.method) {
    return `« Mcp-Method » (${methode}) ne correspond pas à la méthode du corps (${corps.method}).`;
  }

  // ── Mcp-Name ──────────────────────────────────────────────────────────────────────────
  const champ = Object.hasOwn(NOM_ATTENDU, corps.method) ? NOM_ATTENDU[corps.method] : undefined;
  if (champ === undefined) return null; // cette méthode n'exige pas de nom

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
