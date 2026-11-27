import { sansBarresFinales } from "../identite/porteur";

export const JSON_HEADERS = { "Content-Type": "application/json; charset=utf-8" };
export const NO_STORE_HEADERS = { "Cache-Control": "no-store" };

export const ORIGINES_PAR_DEFAUT = [
  "https://claude.ai",
  "https://claude.com",
  "https://gemini.google.com",
  "https://aistudio.google.com",
  "https://chatgpt.com",
  "https://chat.openai.com",
  "https://platform.openai.com",
] as const;

export function originesAdmises(supplementaires?: string): string[] {
  const sup = (supplementaires ?? "")
    .split(",")
    .map((o) => sansBarresFinales(o.trim()))
    .filter((o) => o.length > 0);
  return [...new Set([...ORIGINES_PAR_DEFAUT, ...sup])];
}

export function origineAutorisee(request: Request, admises: readonly string[]): string | null {
  const o = request.headers.get("Origin");
  if (!o) return null;
  return admises.includes(o) ? o : null;
}

export function origineRefusee(request: Request, admises: readonly string[]): boolean {
  const o = request.headers.get("Origin");
  return o !== null && !admises.includes(o);
}

export function corsHeaders(origin: string | null): Record<string, string> {
  if (!origin) return {};
  return {
    "Access-Control-Allow-Origin": origin,
    Vary: "Origin",
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

export interface Limiteur {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

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

export function drapeau(valeur: unknown, defaut = false): boolean {
  if (typeof valeur === "boolean") return valeur;
  if (typeof valeur !== "string") return defaut;
  const v = valeur.trim().toLowerCase();
  if (v === "true") return true;
  if (v === "false") return false;
  return defaut;
}

export interface OptionsSante {
  actif?: boolean;
  commit?: string;
  origin?: string | null;
}

export function reponseSante(options: OptionsSante = {}): Response {
  if (options.actif === false) {
    return new Response("Not found", { status: 404, headers: NO_STORE_HEADERS });
  }
  const commit =
    typeof options.commit === "string" && options.commit.length > 0 ? options.commit : "inconnu";
  return jsonResponse({ status: "ok", commit }, 200, options.origin ?? null);
}

export function repondreDocumentJsonPublic(
  method: string,
  document: unknown,
  options: { cacheMaxAge?: number; contentType?: string; allowHeaders?: string } = {},
): Response {
  if (method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
        "Access-Control-Allow-Headers": options.allowHeaders ?? "Accept, Content-Type",
        "Access-Control-Max-Age": "86400",
      },
    });
  }
  if (method !== "GET" && method !== "HEAD") {
    return new Response(JSON.stringify({ error: "method_not_allowed" }), {
      status: 405,
      headers: {
        ...JSON_HEADERS,
        Allow: "GET, HEAD, OPTIONS",
        "Access-Control-Allow-Origin": "*",
      },
    });
  }
  const maxAge = options.cacheMaxAge ?? 600;
  const headers: Record<string, string> = {
    "Content-Type": options.contentType ?? "application/json; charset=utf-8",
    "Cache-Control": `public, max-age=${maxAge}`,
    "X-Content-Type-Options": "nosniff",
    "Access-Control-Allow-Origin": "*",
  };
  return method === "HEAD"
    ? new Response(null, { status: 200, headers })
    : new Response(JSON.stringify(document), { status: 200, headers });
}
