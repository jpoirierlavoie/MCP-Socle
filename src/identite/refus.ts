import { corsHeaders, JSON_HEADERS, NO_STORE_HEADERS } from "../protocole/http";

export type FormeRefus = "404" | "401";

export type CodeErreurBearerOAuth = "invalid_token" | "insufficient_scope";

export interface OptionsRefus401 {
  resourceMetadata?: string;
  scope?: string;
  error?: CodeErreurBearerOAuth;
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
  return new Response(null, {
    status: 404,
    headers: { ...NO_STORE_HEADERS, ...corsHeaders(origin) },
  });
}

export function origineInterdite(): Response {
  return new Response(JSON.stringify({ error: "forbidden_origin" }), {
    status: 403,
    headers: { ...JSON_HEADERS, ...NO_STORE_HEADERS },
  });
}

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

export function methodeNonPermise(origin: string | null = null): Response {
  return new Response(null, {
    status: 405,
    headers: { Allow: "POST, OPTIONS", ...NO_STORE_HEADERS, ...corsHeaders(origin) },
  });
}
