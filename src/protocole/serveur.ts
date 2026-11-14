/**
 * Répartiteur MCP HTTP sans état, commun aux deux serveurs.
 *
 * Prend une requête `POST` déjà contrôlée en amont (coupe-circuit, origine, débit,
 * authentification), lit le corps de façon bornée, négocie la version, vérifie la
 * concordance des en-têtes sous les révisions modernes, et répartit `server/discover`,
 * `initialize`, `ping`, `tools/list` et `tools/call`.
 */

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

/** Plafond de lecture du corps d'une requête JSON-RPC MCP : 64 Kio. */
export const MAX_OCTETS_CORPS_MCP = 65_536;

export interface OptionsServeurMcp {
  /** Versions MCP servies, la plus élevée en tête. */
  versions: readonly string[];
  /** Capacités annoncées à `initialize` et `server/discover`. */
  capabilities: Record<string, unknown>;
  /** Identité du serveur (`name`, `title?`, `version`). */
  serverInfo: IdentiteServeur;
  /** Instructions générales renvoyées à `initialize` et `server/discover`. */
  instructions?: string;
  /** Descripteurs publics renvoyés à `tools/list`. */
  descripteurs: Array<Record<string, unknown>> | (() => Array<Record<string, unknown>>);
  /** Gestionnaire d'exécution pour `tools/call`. */
  appeler: (nom: unknown, args: unknown, message: JsonRpcMessage) => Promise<ToolResult>;
  /** Origine CORS autorisée pour cette requête (ou `null` hors navigateur). */
  origin: string | null;
  /** Admettre une requête sans en-tête `MCP-Protocol-Version` (clients < `2025-06-18`). */
  sertAvant2025_06_18?: boolean;
  /**
   * Exiger `_meta["io.modelcontextprotocol/protocolVersion"]` sous une révision moderne pour les
   * méthodes non exemptées (`initialize`, `ping`, `server/discover` restent tolérantes s'il est
   * omis, mais rejettent toujours une valeur non textuelle ou discordante). Défaut : `false`.
   */
  exigerVersionMeta?: boolean;
  /** Durée de cache en millisecondes pour `server/discover` et `tools/list`. Défaut : 1 heure. */
  ttlListeMs?: number;
  /** Portée de cache des résultats cachables. Défaut : `"public"`. */
  cacheScope?: PorteeCache;
  /** Plafond d'octets du corps JSON-RPC. Défaut : `MAX_OCTETS_CORPS_MCP`. */
  maxOctetsCorps?: number;
  /** Journalisation sûre en cas d'exception inattendue (méthode + erreur, jamais de secret). */
  surErreur?: (methode: string, erreur: unknown) => void;
}

type LectureCorps = { ok: true; texte: string } | { ok: false; motif: "trop_grand" | "encodage" };

/**
 * Lit le corps d'une requête HTTP en plafonnant strictement le nombre d'octets reçus, sans
 * faire confiance au seul en-tête `Content-Length`.
 */
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

/** Traite un appel `POST` JSON-RPC MCP déjà authentifié et autorisé en origine/débit. */
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
