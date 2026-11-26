/**
 * `server/discover` — obligatoire sous `2026-07-28`.
 *
 * C'est ce qui remplace la poignée : un client apprend en UN appel les versions servies,
 * les capacités et l'identité du serveur, sans créer de session. C'est aussi la sonde de
 * compatibilité — il peut l'appeler avant tout le reste.
 *
 * L'appeler reste FACULTATIF pour le client : il peut envoyer n'importe quelle requête et
 * traiter l'erreur de version si elle vient. Le servir, en revanche, est obligatoire.
 */

import { avecCache, avecServerInfo, complet, type PorteeCache } from "./meta";

export interface IdentiteServeur {
  name: string;
  title?: string;
  version: string;
}

export const SERVER_CARD_SCHEMA =
  "https://static.modelcontextprotocol.io/schemas/v1/server-card.schema.json";

export const CHEMIN_WELL_KNOWN_CARTE_SERVEUR = "/.well-known/mcp/server-card.json";

export const SERVER_CARD_CONTENT_TYPE = "application/mcp-server-card+json; charset=utf-8";

export interface EnteteCarteServeur {
  name: string;
  description: string;
  isRequired: boolean;
  isSecret: boolean;
}

export interface PointDistantCarteServeur {
  type: "streamable-http";
  url: string;
  supportedProtocolVersions: string[];
  headers: EnteteCarteServeur[];
}

export interface OptionsCarteServeur {
  /** Identifiant canonique de la fiche (`ca.poirierlavoie.<depot>/<nom>`). */
  name: string;
  title: string;
  version: string;
  description: string;
  websiteUrl: string;
  repositoryUrl: string;
  remoteUrl: string;
  supportedProtocolVersions: readonly string[];
  /** Point d'entrée OAuth 2.1 optionnel sans en-tête statique requis (`headers: []`). */
  oauthRemoteUrl?: string;
  /** Description de l'en-tête `Authorization` annoncée aux catalogues. */
  authDescription?: string;
}

export interface CarteServeur {
  $schema: string;
  name: string;
  title: string;
  version: string;
  description: string;
  websiteUrl: string;
  repository: { url: string; source: "github" };
  remotes: PointDistantCarteServeur[];
}

/** Construit une fiche SEP-2127 (`/mcp/server-card`), sans accès aux secrets. */
export function construireCarteServeur(o: OptionsCarteServeur): CarteServeur {
  return {
    $schema: SERVER_CARD_SCHEMA,
    name: o.name,
    title: o.title,
    version: o.version,
    description: o.description,
    websiteUrl: o.websiteUrl,
    repository: {
      url: o.repositoryUrl,
      source: "github",
    },
    remotes: [
      {
        type: "streamable-http",
        url: o.remoteUrl,
        supportedProtocolVersions: [...o.supportedProtocolVersions],
        headers: [
          {
            name: "Authorization",
            description:
              o.authDescription ?? "Jeton ou secret partagé de l'instance (« Bearer <jeton> »).",
            isRequired: true,
            isSecret: true,
          },
        ],
      },
      ...(o.oauthRemoteUrl
        ? [
            {
              type: "streamable-http" as const,
              url: o.oauthRemoteUrl,
              supportedProtocolVersions: [...o.supportedProtocolVersions],
              headers: [],
            },
          ]
        : []),
    ],
  };
}

/** Sert une réponse HTTP conforme à SEP-2127 pour `GET`, `HEAD`, `OPTIONS` et `405` ailleurs. */
export function repondreCarteServeur(
  method: string,
  carte: CarteServeur | Record<string, unknown>,
  options: { cacheMaxAge?: number } = {},
): Response {
  if (method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
        "Access-Control-Allow-Headers": "Accept, Content-Type",
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
    "Content-Type": SERVER_CARD_CONTENT_TYPE,
    "Cache-Control": `public, max-age=${maxAge}`,
    "X-Content-Type-Options": "nosniff",
    "Access-Control-Allow-Origin": "*",
  };
  return method === "HEAD"
    ? new Response(null, { status: 200, headers })
    : new Response(JSON.stringify(carte), { status: 200, headers });
}

export interface OptionsDecouverte {
  supportedVersions: readonly string[];
  capabilities: Record<string, unknown>;
  serverInfo: IdentiteServeur;
  instructions?: string;
  /** Une heure par défaut : l'identité et les capacités ne bougent qu'au déploiement. */
  ttlMs?: number;
  cacheScope?: PorteeCache;
}

/**
 * Construit le résultat de `server/discover`.
 *
 * ⚠ `serverInfo` VOYAGE DANS `_meta`, et non à la racine du résultat. C'est l'erreur facile,
 *   parce que la poignée `initialize` le mettait, elle, à la racine.
 *
 * ⚠ NE PAS DÉCLARER `listChanged: true` dans les capacités tant que `subscriptions/listen`
 *   n'est pas servi : sous cette révision, c'est le SEUL véhicule des notifications de
 *   changement. Déclarer la capacité sans le canal, c'est promettre un signal qui ne
 *   viendra jamais.
 */
export function resultatDecouverte(o: OptionsDecouverte): Record<string, unknown> {
  const base: Record<string, unknown> = {
    supportedVersions: [...o.supportedVersions],
    capabilities: o.capabilities,
  };
  if (o.instructions !== undefined) base.instructions = o.instructions;

  return avecCache(
    avecServerInfo(complet(base), o.serverInfo),
    o.ttlMs ?? 3_600_000,
    o.cacheScope ?? "public",
  );
}
