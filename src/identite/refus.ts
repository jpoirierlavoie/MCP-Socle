/**
 * La forme d'un refus.
 *
 * ⚠ CETTE DÉCISION EST ARBITRÉE PAR LE PRATICIEN, PAS PAR LE CODE. S8 retient le `404`
 *   pour UN seul motif tenable : ne pas servir d'oracle sur l'existence d'un compte. Le
 *   motif souvent invoqué — « le 401 déclenche une découverte OAuth qui se coince » —
 *   **n'est pas mesuré**, et l'inverse l'est : les deux incidents enregistrés (2026-07-23,
 *   2026-07-25) sont des **404** qui ont poussé le connecteur dans cette découverte, la
 *   seconde fois irréversiblement. Un client MCP lit un `404` comme « ce serveur exige une
 *   authentification », pas comme « rien ici ». Le `404` n'immunise donc de rien.
 *
 *   C'est un écart assumé et consigné à la spécification MCP, qui exige les métadonnées de
 *   ressource protégée et un `401`. D'où le drapeau : la bascule doit être une ligne de
 *   configuration, pas une réécriture, le jour où une mesure réelle tranchera.
 */

import { corsHeaders } from "../protocole/http";

const JSON_HEADERS = { "Content-Type": "application/json; charset=utf-8" };
const NO_STORE_HEADERS = { "Cache-Control": "no-store" };

export type FormeRefus = "404" | "401";

export type CodeErreurBearerOAuth = "invalid_token" | "insufficient_scope";

/**
 * Paramètres optionnels de découverte OAuth 2.1 / RFC 9728 pour un refus `401`.
 *
 * Ignorés lorsque `forme === "404"` (monture directe `/mcp` sans oracle). Sur la monture
 * dédiée OAuth (`/mcp/oauth`), `resourceMetadata` annonce la fiche RFC 9728 attendue par
 * Gemini App, Gemini Enterprise et les connecteurs OAuth `claude.ai`.
 */
export interface OptionsRefus401 {
  /** URL absolue HTTPS de la fiche `/.well-known/oauth-protected-resource/...` (RFC 9728). */
  resourceMetadata?: string;
  /** Portées requises, séparées par des espaces. */
  scope?: string;
  /** Code d'erreur RFC 6750 §3.1, uniquement si un porteur invalide ou insuffisant a été soumis. */
  error?: CodeErreurBearerOAuth;
  /** Description courte, exempte de tout secret ou contenu utilisateur. */
  errorDescription?: string;
}

function translittererAscii(brut: string): string {
  return brut
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/œ/g, "oe")
    .replace(/Œ/g, "OE")
    .replace(/æ/g, "ae")
    .replace(/Æ/g, "AE");
}

function valeurGuillemeteeSaine(brut: string): string {
  const normalise = translittererAscii(brut);
  let propre = "";
  for (let i = 0; i < normalise.length; i++) {
    const code = normalise.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) {
      propre += " ";
      continue;
    }
    // Strictement ASCII imprimable (RFC 6750 §3 / Fetch Headers), hors guillemet et antislash.
    if (code > 0x7e || code === 0x22 || code === 0x5c) continue;
    propre += normalise[i];
  }
  return propre.replace(/\s+/g, " ").trim().slice(0, 512);
}

function urlRessourceMetadataSaine(brut: string): string | null {
  const candidat = brut.trim();
  if (candidat.length === 0 || candidat.length > 512) return null;
  for (let i = 0; i < candidat.length; i++) {
    const code = candidat.charCodeAt(i);
    // Aucune espace, caractère de contrôle, guillemet ou antislash dans une URI RFC 9728.
    if (code <= 0x20 || code > 0x7e || code === 0x22 || code === 0x5c) return null;
  }
  try {
    const u = new URL(candidat);
    if (
      u.protocol !== "https:" ||
      u.username !== "" ||
      u.password !== "" ||
      u.hash !== "" ||
      u.search !== ""
    ) {
      return null;
    }
    return candidat;
  } catch {
    return null;
  }
}

/** Construit la valeur de l'en-tête `WWW-Authenticate` conforme à RFC 6750 et RFC 9728. */
export function construireEnteteBearer(options?: OptionsRefus401): string {
  if (!options) return "Bearer";
  const parametres: string[] = [];
  if (options.resourceMetadata) {
    const meta = urlRessourceMetadataSaine(options.resourceMetadata);
    if (meta !== null) parametres.push(`resource_metadata="${meta}"`);
  }
  if (options.scope) {
    const scope = valeurGuillemeteeSaine(options.scope.trim());
    if (scope.length > 0) parametres.push(`scope="${scope}"`);
  }
  const codeErreurValide =
    options.error === "invalid_token" || options.error === "insufficient_scope";
  if (codeErreurValide) {
    parametres.push(`error="${options.error}"`);
    if (options.errorDescription) {
      const desc = valeurGuillemeteeSaine(options.errorDescription.trim());
      if (desc.length > 0) parametres.push(`error_description="${desc}"`);
    }
  }
  return parametres.length > 0 ? `Bearer ${parametres.join(", ")}` : "Bearer";
}

/**
 * Refus d'authentification.
 *
 * ⚠ TOUS LES ÉCHECS SUR UNE MÊME MONTURE RENDENT LA MÊME RÉPONSE. Jeton inconnu, expiré,
 *   révoqué, titulaire suspendu : même statut, même corps, et — c'est la partie que le code
 *   ne peut pas garantir seul — le même DÉLAI. Un écart de temps entre « jeton inconnu » et
 *   « jeton connu mais titulaire suspendu » rouvre l'énumération que le statut ferme.
 */
export function refuser(
  forme: FormeRefus,
  origin: string | null = null,
  options401?: OptionsRefus401,
): Response {
  if (forme === "401") {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401,
      headers: {
        ...JSON_HEADERS,
        ...NO_STORE_HEADERS,
        "WWW-Authenticate": construireEnteteBearer(options401),
        ...corsHeaders(origin),
      },
    });
  }
  // Corps VIDE et aucun en-tête annonçant un point d'entrée MCP ; `no-store` empêche la mise
  // en cache négative de `404` par le CDN d'arête (Cloudflare) sans constituer un oracle.
  return new Response(null, {
    status: 404,
    headers: { ...NO_STORE_HEADERS, ...corsHeaders(origin) },
  });
}

/**
 * Origine de navigateur non reconnue : `403`, AVANT toute authentification.
 *
 * Sans en-têtes CORS : la réponse ne doit pas être lisible par la page qui l'a provoquée,
 * sans quoi le refus lui-même deviendrait un oracle.
 */
export function origineInterdite(): Response {
  return new Response(JSON.stringify({ error: "forbidden_origin" }), {
    status: 403,
    headers: { ...JSON_HEADERS, ...NO_STORE_HEADERS },
  });
}

/** Débit dépassé. `Retry-After` en secondes. */
export function tropDeRequetes(retryAfter: number, origin: string | null = null): Response {
  return new Response(JSON.stringify({ error: "rate_limited" }), {
    status: 429,
    headers: {
      ...JSON_HEADERS,
      ...NO_STORE_HEADERS,
      "Retry-After": String(retryAfter),
      ...corsHeaders(origin),
    },
  });
}

/**
 * Méthode non permise.
 *
 * ⚠ À NE SERVIR QU'APRÈS L'IDENTITÉ. `2026-07-28` recommande `405` sur `GET` et `DELETE`,
 *   mais un `405` servi AVANT l'authentification apprend à un anonyme que le point d'entrée
 *   existe : c'est exactement l'oracle que S8 refuse. Le connecteur claude.ai émet des
 *   `GET /mcp` sans aucun porteur ; ils doivent rester en refus d'authentification.
 *   Deuxième écart assumé, à côté de S8, avec son test.
 */
export function methodeNonPermise(origin: string | null = null): Response {
  return new Response(null, {
    status: 405,
    headers: { Allow: "POST, OPTIONS", ...NO_STORE_HEADERS, ...corsHeaders(origin) },
  });
}
