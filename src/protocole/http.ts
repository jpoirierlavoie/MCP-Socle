/**
 * Chaîne intergicielle HTTP : origines, CORS, pré-vol, débit.
 *
 * Repris de `MCP-Jurisprudence` (`src/index.ts`), généralisé pour servir les deux dépôts.
 */

import { sansBarresFinales } from "../identite/porteur";

const JSON_HEADERS = { "Content-Type": "application/json; charset=utf-8" };
const NO_STORE_HEADERS = { "Cache-Control": "no-store" };

/**
 * Origines de navigateur admises par défaut.
 *
 * DEUX EXIGENCES DISTINCTES SE REJOIGNENT ICI, et il faut les servir toutes les deux :
 *
 *   1. **CORS.** `claude.ai` et Gemini web sont des applications de NAVIGATEUR. Sans pré-vol
 *      accepté et sans `Access-Control-Allow-Origin`, le navigateur refuse la requête — et
 *      le connecteur se solde par « impossible de joindre le serveur », alors que le même
 *      point d'entrée répond parfaitement à un client serveur.
 *   2. **Défense contre le RÉ-ATTACHEMENT DNS**, exigée par la spécification MCP : une
 *      origine de navigateur non reconnue est REFUSÉE. Une origine ABSENTE (appel serveur
 *      à serveur) reste admise — un navigateur en pose toujours une.
 */
export const ORIGINES_PAR_DEFAUT = [
  "https://claude.ai",
  "https://claude.com",
  "https://gemini.google.com",
  "https://aistudio.google.com",
  "https://chatgpt.com",
  "https://chat.openai.com",
  "https://platform.openai.com",
] as const;

/** Origines admises : les défauts, plus celles d'une liste séparée par des virgules. */
export function originesAdmises(supplementaires?: string): string[] {
  const sup = (supplementaires ?? "")
    .split(",")
    .map((o) => sansBarresFinales(o.trim()))
    .filter((o) => o.length > 0);
  return [...new Set([...ORIGINES_PAR_DEFAUT, ...sup])];
}

/** Origine à refléter, ou `null` si elle est absente ou refusée. */
export function origineAutorisee(request: Request, admises: readonly string[]): string | null {
  const o = request.headers.get("Origin");
  if (!o) return null; // serveur à serveur : pas de CORS à négocier
  return admises.includes(o) ? o : null;
}

/** Une origine de NAVIGATEUR présente mais non reconnue doit être refusée. */
export function origineRefusee(request: Request, admises: readonly string[]): boolean {
  const o = request.headers.get("Origin");
  return o !== null && !admises.includes(o);
}

/**
 * En-têtes CORS d'une réponse effective.
 *
 * `Vary: Origin` est OBLIGATOIRE : sans lui, un cache intermédiaire pourrait resservir à
 * une origine la réponse calculée pour une autre.
 */
export function corsHeaders(origin: string | null): Record<string, string> {
  if (!origin) return {};
  return {
    "Access-Control-Allow-Origin": origin,
    Vary: "Origin",
    // Le client LIT ces en-têtes ; sans exposition explicite ils lui sont invisibles.
    "Access-Control-Expose-Headers": "WWW-Authenticate, MCP-Protocol-Version, Retry-After",
  };
}

export function jsonResponse(body: unknown, status = 200, origin: string | null = null): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...JSON_HEADERS, ...NO_STORE_HEADERS, ...corsHeaders(origin) },
  });
}

const ENTETES_PREVOL_BASE = [
  "Content-Type",
  "Authorization",
  "MCP-Protocol-Version",
  "Mcp-Method",
  "Mcp-Name",
  "Mcp-Session-Id",
  "Last-Event-ID",
  "Accept",
] as const;

const MOTIF_NOM_ENTETE_HTTP = /^[A-Za-z0-9-]+$/;

/**
 * Réponse au pré-vol CORS.
 *
 * ⚠ LE PRÉ-VOL EST TRAITÉ AVANT TOUTE VÉRIFICATION DU SECRET, et c'est obligatoire : un
 *   navigateur émet `OPTIONS` SANS en-tête d'authentification et sans corps. Exiger le
 *   secret ici ferait échouer le pré-vol, donc la requête réelle, donc le connecteur —
 *   sans que rien n'ait été authentifié pour autant. Le pré-vol ne divulgue rien : il ne
 *   fait qu'annoncer ce que le serveur accepte.
 *
 * ⚠ LE PRÉ-VOL N'EST JAMAIS LIMITÉ EN DÉBIT. Un `429` sur un pré-vol ne remonte au
 *   navigateur que comme un échec CORS opaque : le connecteur casserait sans que le motif
 *   soit lisible nulle part.
 */
export function preflight(origin: string, entetesSupplementaires?: readonly string[]): Response {
  const extras = (entetesSupplementaires ?? [])
    .map((e) => e.trim())
    .filter((e) => e.length > 0 && e.length <= 64 && MOTIF_NOM_ENTETE_HTTP.test(e));
  const allowHeaders = [...new Set([...ENTETES_PREVOL_BASE, ...extras])].join(", ");
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": allowHeaders,
      "Access-Control-Max-Age": "86400",
      Vary: "Origin",
    },
  });
}

/** Ce qu'un limiteur d'arête Cloudflare expose au socle. */
export interface Limiteur {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

/**
 * Le débit est-il acceptable pour cette clé ?
 *
 * ⚠ ÉCHOUE OUVERT, et l'asymétrie avec l'authentification est délibérée. Une liaison
 *   absente ou en panne ne doit pas éteindre le service : le limiteur protège du COÛT
 *   d'une rafale, il ne garde pas une porte. L'authentification, elle, échoue FERMÉ.
 *   Confondre les deux donne soit un service qui s'éteint sur une panne d'infrastructure,
 *   soit une porte qui s'ouvre sur la même panne.
 *
 * Le limiteur d'arête est approximatif et par centre de données : propriété assumée. Il ne
 * sert pas à compter, il sert à ce qu'une boucle ne coûte rien.
 */
export async function debitAcceptable(
  limiteur: Limiteur | undefined,
  cle: string,
): Promise<boolean> {
  if (!limiteur) return true;
  try {
    const { success } = await limiteur.limit({ key: cle });
    return success;
  } catch {
    return true;
  }
}

/**
 * Lit un drapeau booléen issu d'une variable d'environnement Cloudflare Workers.
 *
 * Absence ou chaîne vide retombe sur `defaut`. Seuls `"true"` et `"false"` (insensibles
 * à la casse après rognage) basculent la valeur ; toute autre chaîne retombe sur `defaut`.
 */
export function drapeau(valeur: unknown, defaut = false): boolean {
  if (typeof valeur === "boolean") return valeur;
  if (typeof valeur !== "string") return defaut;
  const v = valeur.trim().toLowerCase();
  if (v === "true") return true;
  if (v === "false") return false;
  return defaut;
}

export interface OptionsSante {
  /** Si `false` (coupe-circuit), répond `404` (« Not found »). Défaut : `true`. */
  actif?: boolean;
  commit?: string;
  origin?: string | null;
}

/** Réponse HTTP du point de santé `/health`. */
export function reponseSante(options: OptionsSante = {}): Response {
  if (options.actif === false) {
    return new Response("Not found", { status: 404, headers: NO_STORE_HEADERS });
  }
  const commit =
    typeof options.commit === "string" && options.commit.length > 0 ? options.commit : "inconnu";
  return jsonResponse({ status: "ok", commit }, 200, options.origin ?? null);
}
