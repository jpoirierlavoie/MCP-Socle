/**
 * Primitives OAuth 2.1, métadonnées de ressource protégée (RFC 9728), métadonnées de serveur
 * d'autorisation (RFC 8414), PKCE `S256` (RFC 7636) et validation anti-SSRF des identifiants de
 * client par document de métadonnées (CIMD).
 *
 * Ces primitives alimentent la monture `/mcp/oauth` des connecteurs et le serveur d'autorisation
 * dédié (`acces.poirierlavoie.ca`), requis par Gemini App (`gemini.google.com`), Gemini Enterprise
 * (Vertex AI) et l'ouverture multilocataire de Claude Research (`claude.ai`).
 */

import { memeSecret, sansBarresFinales } from "./porteur";
import { PORTEE_UNIVERSELLE } from "./titulaire";

export const CHEMIN_RESSOURCE_PROTEGEE = "/.well-known/oauth-protected-resource";
export const CHEMIN_SERVEUR_AUTORISATION = "/.well-known/oauth-authorization-server";
export const METHODE_PKCE_S256 = "S256";

/** URIs de rappel officielles d'Anthropic pour les connecteurs distants Claude / Claude Research. */
export const URIS_REDIRECTION_CLAUDE = [
  "https://claude.ai/api/mcp/auth_callback",
  "https://claude.com/api/mcp/auth_callback",
] as const;

/** URIs de rappel connues de Google Cloud / Vertex AI / Antigravity pour connecteurs OAuth. */
export const URIS_REDIRECTION_GOOGLE_CONNUES = [
  "https://vertexaisearch.cloud.google.com/oauth-redirect",
  "https://vertexaisearch.cloud.google.com/console/oauth/default_oauth.html",
  "https://antigravity.google/oauth-callback",
] as const;

/** URI de rappel stable OpenAI / ChatGPT lorsque RFC 9207 `iss` est annoncé. */
export const URIS_REDIRECTION_OPENAI_CONNUES = [
  "https://chatgpt.com/connector_platform_oauth_redirect",
] as const;

export const CHEMINS_BOUCLE_LOCALE_PAR_DEFAUT = [
  "/callback",
  "/oauth/callback",
  "/oauth-callback",
  "/oauth2callback",
  "/auth/callback",
] as const;

function contientControleOuEspaceUrl(brut: string): boolean {
  for (let i = 0; i < brut.length; i++) {
    const code = brut.charCodeAt(i);
    if (code <= 0x20 || code === 0x7f) return true;
  }
  return false;
}

function extraireAutoriteBrute(uriBrute: string): string | null {
  const idx = uriBrute.indexOf("://");
  if (idx <= 0) return null;
  const reste = uriBrute.slice(idx + 3);
  const fin = reste.search(/[/?#\\]/);
  return fin >= 0 ? reste.slice(0, fin) : reste;
}

function aPortExpliciteDansAutorite(uriBrute: string): boolean {
  const autorite = extraireAutoriteBrute(uriBrute);
  if (!autorite) return false;
  const sansIdentifiants = autorite.includes("@")
    ? autorite.slice(autorite.lastIndexOf("@") + 1)
    : autorite;
  if (sansIdentifiants.startsWith("[")) {
    const finCrochet = sansIdentifiants.indexOf("]");
    return finCrochet >= 0 && sansIdentifiants.slice(finCrochet + 1).startsWith(":");
  }
  return sansIdentifiants.includes(":");
}

export interface OptionsRessourceProtegee {
  /** URL canonique HTTPS de la ressource MCP protégée (ex. `https://hote/mcp/oauth`). */
  resource: string;
  /** Serveurs d'autorisation habilités (ex. `["https://acces.poirierlavoie.ca"]`). */
  authorizationServers: readonly string[];
  /** Portées prises en charge par cette ressource. */
  scopesSupported?: readonly string[];
  /** URL publique de documentation de la ressource. */
  resourceDocumentation?: string;
}

export interface MetadonneesRessourceProtegee {
  resource: string;
  authorization_servers: string[];
  bearer_methods_supported: ["header"];
  scopes_supported?: string[];
  resource_documentation?: string;
}

function parserUrlHttpsPropre(brut: string, libelle: string): URL {
  if (typeof brut !== "string" || brut.length === 0 || contientControleOuEspaceUrl(brut)) {
    throw new Error(`URL « ${libelle} » invalide.`);
  }
  let u: URL;
  try {
    u = new URL(brut);
  } catch {
    throw new Error(`URL « ${libelle} » invalide.`);
  }
  if (u.protocol !== "https:" || u.username !== "" || u.password !== "" || u.hash !== "") {
    throw new Error(`URL « ${libelle} » doit être en HTTPS sans identifiants ni fragment.`);
  }
  if (u.search !== "") {
    throw new Error(`URL « ${libelle} » ne doit pas comporter de chaîne de requête.`);
  }
  return u;
}

/**
 * Calcule l'URL canonique RFC 9728 §3.1 du document de métadonnées d'une ressource protégée
 * (`https://<hote>/.well-known/oauth-protected-resource<chemin>`).
 */
export function urlMetadonneesRessource(resourceUrl: string): string {
  const u = parserUrlHttpsPropre(resourceUrl, "resource");
  const chemin = u.pathname === "/" ? "" : sansBarresFinales(u.pathname);
  return `${u.origin}${CHEMIN_RESSOURCE_PROTEGEE}${chemin}`;
}

/** Construit le document JSON RFC 9728 d'une ressource MCP protégée par OAuth 2.1. */
export function construireRessourceProtegee(
  options: OptionsRessourceProtegee,
): MetadonneesRessourceProtegee {
  const res = parserUrlHttpsPropre(options.resource, "resource");
  if (options.authorizationServers.length === 0) {
    throw new Error("Au moins un serveur d'autorisation est requis (RFC 9728).");
  }
  const serveurs = options.authorizationServers.map((s) =>
    sansBarresFinales(parserUrlHttpsPropre(s, "authorizationServer").toString()),
  );
  const doc: MetadonneesRessourceProtegee = {
    resource: res.pathname === "/" ? res.origin : `${res.origin}${sansBarresFinales(res.pathname)}`,
    authorization_servers: serveurs,
    bearer_methods_supported: ["header"],
  };
  if (options.scopesSupported && options.scopesSupported.length > 0) {
    doc.scopes_supported = [...options.scopesSupported];
  }
  if (options.resourceDocumentation) {
    doc.resource_documentation = parserUrlHttpsPropre(
      options.resourceDocumentation,
      "resourceDocumentation",
    ).toString();
  }
  return doc;
}

export interface OptionsServeurAutorisation {
  /** Émetteur canonique HTTPS sans chemin de requête (ex. `https://acces.poirierlavoie.ca`). */
  issuer: string;
  authorizationEndpoint?: string;
  tokenEndpoint?: string;
  revocationEndpoint?: string;
  registrationEndpoint?: string;
  scopesSupported?: readonly string[];
  grantTypesSupported?: readonly ("authorization_code" | "refresh_token")[];
  tokenEndpointAuthMethodsSupported?: readonly (
    | "none"
    | "client_secret_post"
    | "client_secret_basic"
  )[];
  clientIdMetadataDocumentSupported?: boolean;
  authorizationResponseIssParameterSupported?: boolean;
  serviceDocumentation?: string;
}

export interface MetadonneesServeurAutorisation {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  response_types_supported: ["code"];
  grant_types_supported: string[];
  code_challenge_methods_supported: ["S256"];
  token_endpoint_auth_methods_supported: string[];
  client_id_metadata_document_supported: boolean;
  authorization_response_iss_parameter_supported?: boolean;
  revocation_endpoint?: string;
  registration_endpoint?: string;
  scopes_supported?: string[];
  service_documentation?: string;
}

/** Construit le document JSON RFC 8414 / OAuth 2.1 du serveur d'autorisation. */
export function construireServeurAutorisation(
  options: OptionsServeurAutorisation,
): MetadonneesServeurAutorisation {
  const issuerUrl = parserUrlHttpsPropre(options.issuer, "issuer");
  const issuer =
    issuerUrl.pathname === "/"
      ? issuerUrl.origin
      : `${issuerUrl.origin}${sansBarresFinales(issuerUrl.pathname)}`;

  const authEndpoint = options.authorizationEndpoint
    ? parserUrlHttpsPropre(options.authorizationEndpoint, "authorizationEndpoint").toString()
    : `${issuer}/oauth/authorize`;
  const tokenEndpoint = options.tokenEndpoint
    ? parserUrlHttpsPropre(options.tokenEndpoint, "tokenEndpoint").toString()
    : `${issuer}/oauth/token`;

  const meta: MetadonneesServeurAutorisation = {
    issuer,
    authorization_endpoint: authEndpoint,
    token_endpoint: tokenEndpoint,
    response_types_supported: ["code"],
    grant_types_supported: options.grantTypesSupported
      ? [...options.grantTypesSupported]
      : ["authorization_code"],
    code_challenge_methods_supported: [METHODE_PKCE_S256],
    token_endpoint_auth_methods_supported: options.tokenEndpointAuthMethodsSupported
      ? [...options.tokenEndpointAuthMethodsSupported]
      : ["none", "client_secret_post", "client_secret_basic"],
    client_id_metadata_document_supported: options.clientIdMetadataDocumentSupported ?? true,
    ...(options.authorizationResponseIssParameterSupported !== undefined
      ? {
          authorization_response_iss_parameter_supported:
            options.authorizationResponseIssParameterSupported,
        }
      : {}),
  };

  if (options.revocationEndpoint) {
    meta.revocation_endpoint = parserUrlHttpsPropre(
      options.revocationEndpoint,
      "revocationEndpoint",
    ).toString();
  }
  if (options.registrationEndpoint) {
    meta.registration_endpoint = parserUrlHttpsPropre(
      options.registrationEndpoint,
      "registrationEndpoint",
    ).toString();
  }
  if (options.scopesSupported && options.scopesSupported.length > 0) {
    meta.scopes_supported = [...options.scopesSupported];
  }
  if (options.serviceDocumentation) {
    meta.service_documentation = parserUrlHttpsPropre(
      options.serviceDocumentation,
      "serviceDocumentation",
    ).toString();
  }

  return meta;
}

function repondreDocumentDecouverteOAuth(
  method: string,
  document: unknown,
  options: { cacheMaxAge?: number } = {},
): Response {
  if (method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
        "Access-Control-Allow-Headers": "Accept, Content-Type, MCP-Protocol-Version",
        "Access-Control-Max-Age": "86400",
      },
    });
  }
  if (method !== "GET" && method !== "HEAD") {
    return new Response(JSON.stringify({ error: "method_not_allowed" }), {
      status: 405,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        Allow: "GET, HEAD, OPTIONS",
        "Access-Control-Allow-Origin": "*",
      },
    });
  }
  const maxAge = options.cacheMaxAge ?? 600;
  const headers: Record<string, string> = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": `public, max-age=${maxAge}`,
    "X-Content-Type-Options": "nosniff",
    "Access-Control-Allow-Origin": "*",
  };
  return method === "HEAD"
    ? new Response(null, { status: 200, headers })
    : new Response(JSON.stringify(document), { status: 200, headers });
}

/** Sert une fiche RFC 9728 (`GET`, `HEAD`, `OPTIONS`, `405` ailleurs). */
export function repondreRessourceProtegee(
  method: string,
  meta: MetadonneesRessourceProtegee,
  options?: { cacheMaxAge?: number },
): Response {
  return repondreDocumentDecouverteOAuth(method, meta, options);
}

/** Sert une fiche RFC 8414 (`GET`, `HEAD`, `OPTIONS`, `405` ailleurs). */
export function repondreServeurAutorisation(
  method: string,
  meta: MetadonneesServeurAutorisation,
  options?: { cacheMaxAge?: number },
): Response {
  return repondreDocumentDecouverteOAuth(method, meta, options);
}

// ── PKCE S256 (RFC 7636 + OAuth 2.1) ────────────────────────────────────────────────────

const MOTIF_VERIFICATEUR_PKCE = /^[A-Za-z0-9._~-]{43,128}$/;
const MOTIF_DEFI_PKCE_S256 = /^[A-Za-z0-9_-]{43}$/;
const DEFI_PKCE_FACTICE = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/** Vérifie la conformité syntaxique stricte d'un `code_verifier` RFC 7636 §4.1 (43 à 128 car.). */
export function estVerificateurPkceValide(codeVerifier: string): boolean {
  return (
    codeVerifier.length >= 43 &&
    codeVerifier.length <= 128 &&
    MOTIF_VERIFICATEUR_PKCE.test(codeVerifier)
  );
}

/** Calcule le `code_challenge` PKCE `S256` (`BASE64URL(SHA-256(ASCII(code_verifier)))`). */
export async function calculerDefiPkceS256(codeVerifier: string): Promise<string> {
  if (!estVerificateurPkceValide(codeVerifier)) {
    throw new Error("code_verifier PKCE non conforme à RFC 7636 §4.1.");
  }
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(codeVerifier));
  const octets = new Uint8Array(digest);
  let binaire = "";
  for (const o of octets) binaire += String.fromCharCode(o);
  return btoa(binaire).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Vérifie à temps constant un couple `(code_verifier, code_challenge)` sous la seule méthode
 * autorisée `S256` (OAuth 2.1 interdit `plain`).
 */
export async function verifierDefiPkceS256(
  codeVerifier: string,
  codeChallengeAttendu: string,
  methode = METHODE_PKCE_S256,
): Promise<boolean> {
  if (
    methode !== METHODE_PKCE_S256 ||
    !estVerificateurPkceValide(codeVerifier) ||
    !MOTIF_DEFI_PKCE_S256.test(codeChallengeAttendu)
  ) {
    await memeSecret(DEFI_PKCE_FACTICE, DEFI_PKCE_FACTICE);
    return false;
  }
  const calcule = await calculerDefiPkceS256(codeVerifier);
  return await memeSecret(calcule, codeChallengeAttendu);
}

// ── Validation des URIs de redirection et CIMD (anti-SSRF) ──────────────────────────────

export interface OptionsValidationRedirection {
  /** Liste blanche d'URIs HTTPS exactes autorisées (ex. `URIS_REDIRECTION_CLAUDE` + Google/Vertex). */
  urisExactesAutorisees?: readonly string[];
  /** Autoriser les rappels de boucle locale RFC 8252 §7.3 (`127.0.0.1`, `[::1]`, `localhost`). */
  autoriserBoucleLocale?: boolean;
  /** Chemins exacts admis sur la boucle locale. Défaut : `CHEMINS_BOUCLE_LOCALE_PAR_DEFAUT`. */
  cheminsBoucleLocale?: readonly string[];
}

const MOTIF_TRAVERSEE_BRUTE = /(?:^|[\\/])(?:\.\.?|%2e(?:\.|%2e)?|\.%2e)(?:[\\/?#]|$)/i;
const MOTIF_SEPARATEUR_ENCODE = /%(?:2f|5c)/i;

function contientSegmentParent(uriBrute: string, pathname: string): boolean {
  const debutChemin = uriBrute.indexOf("://");
  const apresAutorite = debutChemin >= 0 ? uriBrute.indexOf("/", debutChemin + 3) : 0;
  if (apresAutorite >= 0) {
    const cheminBrut = uriBrute.slice(apresAutorite).split(/[?#]/, 1)[0] ?? "";
    if (
      cheminBrut.includes("\\") ||
      MOTIF_SEPARATEUR_ENCODE.test(cheminBrut) ||
      MOTIF_TRAVERSEE_BRUTE.test(cheminBrut)
    ) {
      return true;
    }
  }
  const segments = pathname.split("/");
  for (const seg of segments) {
    if (seg === "." || seg === "..") return true;
    try {
      const decode = decodeURIComponent(seg);
      if (decode === "." || decode === ".." || decode.includes("/") || decode.includes("\\")) {
        return true;
      }
      for (let i = 0; i < decode.length; i++) {
        const code = decode.charCodeAt(i);
        if (code < 0x20 || code === 0x7f) return true;
      }
    } catch {
      return true;
    }
  }
  return false;
}

function estHoteBoucleLocale(hostname: string): boolean {
  return hostname === "127.0.0.1" || hostname === "[::1]" || hostname === "localhost";
}

/**
 * Vérifie qu'une `redirect_uri` OAuth 2.1 est sûre et correspond soit par égalité stricte
 * caractère pour caractère à une URI HTTPS enregistrée (OAuth 2.1 §4.1.3), soit à une boucle
 * locale RFC 8252 explicitement permise.
 */
export function estUriRedirectionAutorisee(
  uri: string,
  options: OptionsValidationRedirection = {},
): boolean {
  if (
    typeof uri !== "string" ||
    uri.length === 0 ||
    uri.length > 512 ||
    contientControleOuEspaceUrl(uri)
  ) {
    return false;
  }
  let u: URL;
  try {
    u = new URL(uri);
  } catch {
    return false;
  }
  if (u.username !== "" || u.password !== "" || u.hash !== "") return false;
  if (contientSegmentParent(uri, u.pathname)) return false;

  const exactes = options.urisExactesAutorisees ?? URIS_REDIRECTION_CLAUDE;
  if (u.protocol === "https:") {
    return exactes.includes(uri);
  }

  if (u.protocol === "http:" && options.autoriserBoucleLocale === true) {
    if (!estHoteBoucleLocale(u.hostname)) return false;
    const autorite = extraireAutoriteBrute(uri);
    if (!autorite) return false;
    const hoteBrut = autorite.startsWith("[")
      ? autorite.slice(0, autorite.indexOf("]") + 1)
      : (autorite.split(":", 1)[0] ?? "");
    if (!estHoteBoucleLocale(hoteBrut)) return false;
    const suffixePort = autorite.slice(hoteBrut.length);
    if (suffixePort !== "") {
      if (!/^:[1-9]\d{0,4}$/.test(suffixePort)) return false;
      const numPort = Number(suffixePort.slice(1));
      if (numPort < 1 || numPort > 65_535 || numPort === 80) return false;
    }
    if (u.search !== "") return false;
    const chemins = options.cheminsBoucleLocale ?? CHEMINS_BOUCLE_LOCALE_PAR_DEFAUT;
    return chemins.includes(u.pathname);
  }

  return false;
}

const MOTIF_IPV4_CANONIQUE = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const SUFFIXES_HOTE_INTERDITS_CIMD = [
  ".localhost",
  ".local",
  ".internal",
  ".arpa",
  ".onion",
  ".invalid",
  ".localdomain",
  ".lan",
  ".corp",
  ".intranet",
] as const;

function estHoteInterditPourCimd(hostname: string): boolean {
  const h = hostname.toLowerCase();
  // Un point final FQDN (`localhost.`, `127.0.0.1.`, `interne.local.`) contournerait les
  // comparaisons de suffixes s'il n'était rejeté d'emblée.
  if (h.endsWith(".")) {
    return true;
  }
  if (
    h === "localhost" ||
    !h.includes(".") ||
    SUFFIXES_HOTE_INTERDITS_CIMD.some((s) => h.endsWith(s))
  ) {
    return true;
  }
  // WHATWG `new URL()` normalise toute adresse IPv6 entre crochets et toute adresse IPv4
  // (décimale, octale ou hexadécimale) en notation décimale pointée canonique : refuser tout
  // littéral IP élimine d'un bloc les contournements SSRF (`127.0.0.1`, `169.254.169.254`,
  // `[::1]`, `[::ffff:127.0.0.1]`, identifiants de zone `%25`, etc.).
  if (h.startsWith("[") || h.endsWith("]") || MOTIF_IPV4_CANONIQUE.test(h)) {
    return true;
  }
  return false;
}

/**
 * Valide un identifiant de client par document de métadonnées (CIMD) avant toute résolution
 * distante par le serveur d'autorisation : HTTPS obligatoire, sans espace ni caractère de
 * contrôle, sans port explicite ni chaîne de requête, nom de domaine public (aucun littéral
 * IPv4/IPv6 ni domaine local/spécial), chemin non vide distinct de `/`, sans fragment ni `..`.
 */
export function estClientIdMetadonneesValide(clientId: string): boolean {
  if (
    typeof clientId !== "string" ||
    clientId.length === 0 ||
    clientId.length > 512 ||
    contientControleOuEspaceUrl(clientId)
  ) {
    return false;
  }
  let u: URL;
  try {
    u = new URL(clientId);
  } catch {
    return false;
  }
  if (
    u.protocol !== "https:" ||
    u.username !== "" ||
    u.password !== "" ||
    u.hash !== "" ||
    u.search !== ""
  ) {
    return false;
  }
  if (u.port !== "" || aPortExpliciteDansAutorite(clientId)) {
    return false;
  }
  if (u.pathname === "/" || u.pathname.length < 2 || contientSegmentParent(clientId, u.pathname)) {
    return false;
  }
  if (estHoteInterditPourCimd(u.hostname)) {
    return false;
  }
  return true;
}

export interface ClientCimdValide {
  readonly clientId: string;
  readonly clientName?: string;
  readonly redirectUris: readonly string[];
  readonly tokenEndpointAuthMethod: "none" | "private_key_jwt";
  readonly tokenEndpointAuthMethodsSupported?: readonly ("none" | "private_key_jwt")[];
}

export type ResultatValidationClientCimd =
  | { readonly ok: true; readonly client: ClientCimdValide }
  | { readonly ok: false; readonly motif: string };

function estUriRedirectionCimdValide(uri: string, autoriserBoucleLocale: boolean): boolean {
  if (
    typeof uri !== "string" ||
    uri.length === 0 ||
    uri.length > 512 ||
    contientControleOuEspaceUrl(uri)
  ) {
    return false;
  }
  let u: URL;
  try {
    u = new URL(uri);
  } catch {
    return false;
  }
  if (u.username !== "" || u.password !== "" || u.hash !== "") return false;
  if (contientSegmentParent(uri, u.pathname)) return false;
  if (u.protocol === "https:") {
    return !estHoteInterditPourCimd(u.hostname);
  }
  if (u.protocol === "http:" && autoriserBoucleLocale) {
    return estUriRedirectionAutorisee(uri, { autoriserBoucleLocale: true });
  }
  return false;
}

/**
 * Valide hors réseau le document JSON d'un client CIMD récupéré via `fetch(clientId, { redirect: "manual" })` :
 * concordance exacte de `client_id`, interdiction de tout secret symétrique (`client_secret*`) et
 * validation stricte du tableau `redirect_uris`.
 */
export function validerMetadonneesClientCimd(
  clientIdAttendu: string,
  document: unknown,
  options: { autoriserBoucleLocale?: boolean } = {},
): ResultatValidationClientCimd {
  if (!estClientIdMetadonneesValide(clientIdAttendu)) {
    return { ok: false, motif: "client_id CIMD invalide." };
  }
  if (typeof document !== "object" || document === null || Array.isArray(document)) {
    return { ok: false, motif: "Document CIMD non objet." };
  }
  const doc = document as Record<string, unknown>;
  if (!Object.hasOwn(doc, "client_id") || doc.client_id !== clientIdAttendu) {
    return { ok: false, motif: "Discordance de client_id dans le document CIMD." };
  }
  if (Object.hasOwn(doc, "client_secret") && doc.client_secret !== undefined) {
    return { ok: false, motif: "Un document CIMD public ne peut pas déclarer client_secret." };
  }

  const methodeAuthBrute = Object.hasOwn(doc, "token_endpoint_auth_method")
    ? doc.token_endpoint_auth_method
    : "none";
  if (methodeAuthBrute !== "none" && methodeAuthBrute !== "private_key_jwt") {
    return {
      ok: false,
      motif: "Méthode d'authentification CIMD interdite (secrets symétriques refusés).",
    };
  }

  let methodesAuthSupportees: readonly ("none" | "private_key_jwt")[] | undefined;
  if (
    Object.hasOwn(doc, "token_endpoint_auth_methods_supported") &&
    doc.token_endpoint_auth_methods_supported !== undefined
  ) {
    const brutSupportees = doc.token_endpoint_auth_methods_supported;
    if (
      !Array.isArray(brutSupportees) ||
      brutSupportees.length === 0 ||
      brutSupportees.length > 8 ||
      !brutSupportees.every(
        (m): m is "none" | "private_key_jwt" => m === "none" || m === "private_key_jwt",
      )
    ) {
      return {
        ok: false,
        motif:
          "Tableau token_endpoint_auth_methods_supported CIMD invalide ou méthodes non prises en charge.",
      };
    }
    methodesAuthSupportees = [...new Set(brutSupportees)];
  }

  if (!Object.hasOwn(doc, "redirect_uris") || !Array.isArray(doc.redirect_uris)) {
    return { ok: false, motif: "Tableau redirect_uris manquant." };
  }
  if (doc.redirect_uris.length === 0 || doc.redirect_uris.length > 16) {
    return { ok: false, motif: "Taille de redirect_uris hors bornes (1..16)." };
  }

  const autoriserBoucle = options.autoriserBoucleLocale === true;
  const uris: string[] = [];
  for (const entree of doc.redirect_uris) {
    if (typeof entree !== "string" || !estUriRedirectionCimdValide(entree, autoriserBoucle)) {
      return { ok: false, motif: "URI de redirection CIMD invalide ou non sécurisée." };
    }
    if (!uris.includes(entree)) uris.push(entree);
  }

  let clientName: string | undefined;
  if (Object.hasOwn(doc, "client_name") && doc.client_name !== undefined) {
    if (
      typeof doc.client_name !== "string" ||
      doc.client_name.trim().length === 0 ||
      doc.client_name.length > 120
    ) {
      return { ok: false, motif: "Champ client_name invalide." };
    }
    clientName = doc.client_name.trim();
  }

  return {
    ok: true,
    client: {
      clientId: clientIdAttendu,
      ...(clientName !== undefined ? { clientName } : {}),
      redirectUris: uris,
      tokenEndpointAuthMethod: methodeAuthBrute,
      ...(methodesAuthSupportees !== undefined
        ? { tokenEndpointAuthMethodsSupported: methodesAuthSupportees }
        : {}),
    },
  };
}

export type MethodeAuthEndpointTokenDcr = "none" | "client_secret_post" | "client_secret_basic";

export interface ClientDcrValide {
  readonly clientName?: string;
  readonly redirectUris: readonly string[];
  readonly tokenEndpointAuthMethod: MethodeAuthEndpointTokenDcr;
  readonly grantTypes: readonly ["authorization_code"];
  readonly responseTypes: readonly ["code"];
}

export type CodeErreurValidationDcr = "invalid_redirect_uri" | "invalid_client_metadata";

export type ResultatValidationInscriptionDcr =
  | { readonly ok: true; readonly client: ClientDcrValide }
  | {
      readonly ok: false;
      readonly codeErreur: CodeErreurValidationDcr;
      readonly motif: string;
    };

function contientControleTexte(brut: string): boolean {
  for (let i = 0; i < brut.length; i++) {
    const code = brut.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

/**
 * Valide hors réseau une requête RFC 7591 d'inscription dynamique de client (`POST /oauth/register`)
 * en bloquant toute URI non sécurisée / SSRF (`invalid_redirect_uri`) et en bornant strictement
 * les métadonnées admises (PKCE `authorization_code` + `code` uniquement ; `"refresh_token"` éventuel
 * dans la demande est toléré sans être réémis).
 */
export function validerMetadonneesInscriptionDcr(
  document: unknown,
  options: { autoriserBoucleLocale?: boolean } = {},
): ResultatValidationInscriptionDcr {
  if (typeof document !== "object" || document === null || Array.isArray(document)) {
    return {
      ok: false,
      codeErreur: "invalid_client_metadata",
      motif: "Requête d'inscription JSON non objet.",
    };
  }
  const doc = document as Record<string, unknown>;

  if (
    !Object.hasOwn(doc, "redirect_uris") ||
    !Array.isArray(doc.redirect_uris) ||
    doc.redirect_uris.length === 0 ||
    doc.redirect_uris.length > 8
  ) {
    return {
      ok: false,
      codeErreur: "invalid_redirect_uri",
      motif: "Tableau redirect_uris manquant ou hors bornes (1..8).",
    };
  }

  const autoriserBoucle = options.autoriserBoucleLocale === true;
  const uris: string[] = [];
  for (const entree of doc.redirect_uris) {
    if (typeof entree !== "string" || !estUriRedirectionCimdValide(entree, autoriserBoucle)) {
      return {
        ok: false,
        codeErreur: "invalid_redirect_uri",
        motif: "URI de redirection manquante, invalide ou non sécurisée.",
      };
    }
    if (!uris.includes(entree)) uris.push(entree);
  }
  if (uris.length === 0 || JSON.stringify(uris).length > 1_024) {
    return {
      ok: false,
      codeErreur: "invalid_redirect_uri",
      motif: "Ensemble redirect_uris vide ou trop volumineux.",
    };
  }

  const methodeBrute = Object.hasOwn(doc, "token_endpoint_auth_method")
    ? (doc.token_endpoint_auth_method ?? "none")
    : "none";
  if (
    methodeBrute !== "none" &&
    methodeBrute !== "client_secret_post" &&
    methodeBrute !== "client_secret_basic"
  ) {
    return {
      ok: false,
      codeErreur: "invalid_client_metadata",
      motif: "Méthode token_endpoint_auth_method non prise en charge.",
    };
  }

  if (Object.hasOwn(doc, "grant_types") && doc.grant_types !== undefined) {
    if (
      !Array.isArray(doc.grant_types) ||
      doc.grant_types.length === 0 ||
      doc.grant_types.length > 4 ||
      !doc.grant_types.every(
        (g): g is string => g === "authorization_code" || g === "refresh_token",
      ) ||
      !doc.grant_types.includes("authorization_code")
    ) {
      return {
        ok: false,
        codeErreur: "invalid_client_metadata",
        motif: "Seul grant_types incluant authorization_code est pris en charge.",
      };
    }
  }

  if (Object.hasOwn(doc, "response_types") && doc.response_types !== undefined) {
    if (
      !Array.isArray(doc.response_types) ||
      doc.response_types.length !== 1 ||
      doc.response_types[0] !== "code"
    ) {
      return {
        ok: false,
        codeErreur: "invalid_client_metadata",
        motif: "Seul response_types ['code'] est pris en charge.",
      };
    }
  }

  let clientName: string | undefined;
  if (Object.hasOwn(doc, "client_name") && doc.client_name !== undefined) {
    if (typeof doc.client_name !== "string" || contientControleTexte(doc.client_name)) {
      return {
        ok: false,
        codeErreur: "invalid_client_metadata",
        motif: "Champ client_name invalide.",
      };
    }
    const propre = doc.client_name.trim();
    if (propre.length === 0 || propre.length > 80) {
      return {
        ok: false,
        codeErreur: "invalid_client_metadata",
        motif: "Champ client_name vide ou trop long (1..80).",
      };
    }
    clientName = propre;
  }

  return {
    ok: true,
    client: {
      ...(clientName !== undefined ? { clientName } : {}),
      redirectUris: uris,
      tokenEndpointAuthMethod: methodeBrute,
      grantTypes: ["authorization_code"],
      responseTypes: ["code"],
    },
  };
}

export const MAX_SERVICES_PORTEE = 8;
export const MOTIF_SERVICE_PORTEE = /^[a-z0-9_-]{2,40}$/;

function extraireServicesTriesValides(servicesConnus: readonly string[]): string[] {
  const uniques = new Set<string>();
  for (const brut of servicesConnus) {
    if (typeof brut !== "string") {
      throw new Error("Nom de portée de service non textuel.");
    }
    const propre = brut.trim();
    if (!MOTIF_SERVICE_PORTEE.test(propre) || propre === PORTEE_UNIVERSELLE) {
      throw new Error(`Nom de portée de service invalide : « ${brut} ».`);
    }
    uniques.add(propre);
  }
  if (uniques.size === 0 || uniques.size > MAX_SERVICES_PORTEE) {
    throw new Error(
      `Nombre de services de portée hors bornes (1..${MAX_SERVICES_PORTEE}, reçu ${uniques.size}).`,
    );
  }
  return [...uniques].sort();
}

/**
 * Calcule la liste ordonnée et sans doublon de toutes les valeurs canoniques admises pour la
 * colonne `portee` de `DB_IDENTITE` (`jeton` et `code_oauth`) : `les_deux` suivi de tous les
 * sous-ensembles propres non vides triés lexicographiquement (par taille croissante puis ordre
 * ASCII), garantissant une concordance exacte entre `normaliserPorteeOAuth` et la contrainte SQL
 * `CHECK (portee IN (...))` quel que soit le nombre de services ($1 \le N \le 8$).
 */
export function porteesCanoniques(servicesConnus: readonly string[]): string[] {
  const services = extraireServicesTriesValides(servicesConnus);
  if (services.length === 1) {
    return [PORTEE_UNIVERSELLE, services[0]!];
  }

  const sousEnsemblesParTaille: string[][] = Array.from({ length: services.length - 1 }, () => []);

  function parcourir(indexDebut: number, courant: string[]): void {
    if (courant.length > 0 && courant.length < services.length) {
      sousEnsemblesParTaille[courant.length - 1]!.push(courant.join(" "));
    }
    if (courant.length >= services.length - 1) return;
    for (let i = indexDebut; i < services.length; i++) {
      courant.push(services[i]!);
      parcourir(i + 1, courant);
      courant.pop();
    }
  }

  parcourir(0, []);
  return [PORTEE_UNIVERSELLE, ...sousEnsemblesParTaille.flat()];
}

/**
 * Normalise le paramètre `scope` OAuth 2.1 (séparé par espaces, RFC 6749 §3.3) vers la valeur
 * canonique stockée dans `DB_IDENTITE` (`les_deux` par défaut ou lorsque tous les services connus
 * sont demandés, un sous-ensemble propre trié lexicographiquement sinon, ou `null` sur toute
 * portée ou configuration inconnue).
 */
export function normaliserPorteeOAuth(
  porteeBrute: string | null | undefined,
  servicesConnus: readonly string[],
): string | null {
  let services: string[];
  try {
    services = extraireServicesTriesValides(servicesConnus);
  } catch {
    return null;
  }

  if (porteeBrute === null || porteeBrute === undefined) {
    return PORTEE_UNIVERSELLE;
  }
  if (porteeBrute.length > 512) {
    return null;
  }
  if (porteeBrute.trim().length === 0) {
    return PORTEE_UNIVERSELLE;
  }
  const demandes = [
    ...new Set(
      porteeBrute
        .trim()
        .split(/\s+/)
        .filter((s) => s.length > 0),
    ),
  ];
  if (demandes.length === 0) return PORTEE_UNIVERSELLE;

  for (const jeton of demandes) {
    if (jeton !== PORTEE_UNIVERSELLE && !services.includes(jeton)) {
      return null;
    }
  }

  if (demandes.includes(PORTEE_UNIVERSELLE) || services.every((srv) => demandes.includes(srv))) {
    return PORTEE_UNIVERSELLE;
  }

  return [...demandes].sort().join(" ");
}
