import { type IdentiteServeur, resultatDecouverte } from "./decouverte";
import { HEADER_MISMATCH, validerEntetes } from "./entetes";
import { corsHeaders, jsonResponse } from "./http";
import { habillerResultat, type PorteeCache } from "./meta";
import {
  errorResponse,
  INTERNAL_ERROR,
  INVALID_REQUEST,
  isNotification,
  JsonRpcError,
  type JsonRpcMessage,
  METHOD_NOT_FOUND,
  PARSE_ERROR,
  parseMessage,
  resultResponse,
  type ToolResult,
} from "./rpc";
import {
  estModerne,
  negocier,
  negocierInitialize,
  VERSION_SANS_ENTETE,
  versionAbsenteAdmise,
} from "./versions";

export const MAX_OCTETS_CORPS_MCP = 65_536;

export interface OptionsServeurMcp {
  versions: readonly string[];
  capabilities: Record<string, unknown>;
  serverInfo: IdentiteServeur;
  instructions?: string;
  descripteurs: Array<Record<string, unknown>> | (() => Array<Record<string, unknown>>);
  appeler: (nom: unknown, args: unknown, message: JsonRpcMessage) => Promise<ToolResult>;
  origin: string | null;
  sertAvant2025_06_18?: boolean;
  exigerVersionMeta?: boolean;
  ttlListeMs?: number;
  cacheScope?: PorteeCache;
  maxOctetsCorps?: number;
  surErreur?: (methode: string, erreur: unknown) => void;
}

type LectureCorps = { ok: true; texte: string } | { ok: false; motif: "trop_grand" | "encodage" };

export async function lireCorpsBorne(
  request: Request,
  maxOctets = MAX_OCTETS_CORPS_MCP,
): Promise<LectureCorps> {
  const enteteLongueur = request.headers.get("Content-Length");
  if (enteteLongueur !== null) {
    const declaree = Number(enteteLongueur);
    if (Number.isFinite(declaree) && declaree > maxOctets) {
      return { ok: false, motif: "trop_grand" };
    }
  }

  if (!request.body) {
    return { ok: true, texte: "" };
  }

  const reader = request.body.getReader();
  const morceaux: Uint8Array[] = [];
  let total = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value || value.byteLength === 0) continue;
      total += value.byteLength;
      if (total > maxOctets) {
        await reader.cancel().catch(() => {});
        return { ok: false, motif: "trop_grand" };
      }
      morceaux.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const buffer = new Uint8Array(total);
  let decalage = 0;
  for (const m of morceaux) {
    buffer.set(m, decalage);
    decalage += m.byteLength;
  }

  try {
    const texte = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(buffer);
    return { ok: true, texte };
  } catch {
    return { ok: false, motif: "encodage" };
  }
}

const METHODES_SANS_META_OBLIGATOIRE = new Set(["initialize", "ping", "server/discover"]);

export async function servirRequeteMcp(
  request: Request,
  options: OptionsServeurMcp,
): Promise<Response> {
  const origin = options.origin;
  const maxOctets = options.maxOctetsCorps ?? MAX_OCTETS_CORPS_MCP;
  const ttlListe = options.ttlListeMs ?? 3_600_000;
  const cacheScope = options.cacheScope ?? "public";

  const lecture = await lireCorpsBorne(request, maxOctets);
  if (!lecture.ok) {
    if (lecture.motif === "trop_grand") {
      return jsonResponse(
        errorResponse(null, INVALID_REQUEST, "Corps de requête trop volumineux."),
        413,
        origin,
      );
    }
    return jsonResponse(errorResponse(null, PARSE_ERROR, "Encodage UTF-8 invalide."), 200, origin);
  }

  let message: JsonRpcMessage;
  try {
    message = parseMessage(lecture.texte);
  } catch (e) {
    const je = e instanceof JsonRpcError ? e : new JsonRpcError(PARSE_ERROR, "Erreur d'analyse.");
    return jsonResponse(errorResponse(je.requestId, je.code, je.message), 200, origin);
  }

  if (isNotification(message)) {
    return new Response(null, { status: 202, headers: corsHeaders(origin) });
  }

  const id = message.id ?? null;
  const params = message.params ?? {};

  const entete = request.headers.get("MCP-Protocol-Version");
  let version: string;
  if (entete === null) {
    if (!versionAbsenteAdmise(message.method, options.sertAvant2025_06_18 ?? false)) {
      return jsonResponse(
        errorResponse(id, HEADER_MISMATCH, "En-tête « MCP-Protocol-Version » manquant."),
        400,
        origin,
      );
    }
    version =
      typeof params.protocolVersion === "string" ? params.protocolVersion : VERSION_SANS_ENTETE;
  } else {
    const n = negocier(entete, options.versions);
    if ("erreur" in n) {
      return jsonResponse({ jsonrpc: "2.0", id, error: n.erreur }, 400, origin);
    }
    version = n.version;
  }

  const moderne = estModerne(version);

  if (moderne && message.method !== "initialize") {
    const exigerVersionMeta =
      Boolean(options.exigerVersionMeta) && !METHODES_SANS_META_OBLIGATOIRE.has(message.method);
    const faute = validerEntetes(
      request.headers,
      { method: message.method, params },
      { exigerVersionMeta },
    );
    if (faute) {
      return jsonResponse(errorResponse(id, HEADER_MISMATCH, faute), 400, origin);
    }
  }

  try {
    switch (message.method) {
      case "server/discover":
        return jsonResponse(
          resultResponse(
            id,
            resultatDecouverte({
              supportedVersions: options.versions,
              capabilities: options.capabilities,
              serverInfo: options.serverInfo,
              instructions: options.instructions,
              ttlMs: ttlListe,
              cacheScope,
            }),
          ),
          200,
          origin,
        );

      case "initialize": {
        const negociee = negocierInitialize(params.protocolVersion, options.versions);
        return jsonResponse(
          resultResponse(id, {
            protocolVersion: negociee,
            capabilities: options.capabilities,
            serverInfo: options.serverInfo,
            ...(options.instructions !== undefined ? { instructions: options.instructions } : {}),
          }),
          200,
          origin,
        );
      }

      case "ping":
        return jsonResponse(resultResponse(id, habillerResultat({}, { moderne })), 200, origin);

      case "tools/list": {
        const tools =
          typeof options.descripteurs === "function"
            ? options.descripteurs()
            : options.descripteurs;
        return jsonResponse(
          resultResponse(id, habillerResultat({ tools }, { moderne, ttlMs: ttlListe, cacheScope })),
          200,
          origin,
        );
      }

      case "tools/call": {
        const resultat = await options.appeler(params.name, params.arguments, message);
        return jsonResponse(
          resultResponse(
            id,
            habillerResultat(resultat as unknown as Record<string, unknown>, { moderne }),
          ),
          200,
          origin,
        );
      }

      default:
        return jsonResponse(
          errorResponse(id, METHOD_NOT_FOUND, `Méthode inconnue : ${message.method}`),
          404,
          origin,
        );
    }
  } catch (e) {
    if (e instanceof JsonRpcError) {
      return jsonResponse(errorResponse(id, e.code, e.message), 200, origin);
    }
    options.surErreur?.(message.method, e);
    return jsonResponse(errorResponse(id, INTERNAL_ERROR, "Erreur interne."), 200, origin);
  }
}
