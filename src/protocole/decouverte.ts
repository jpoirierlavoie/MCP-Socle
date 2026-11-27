import { repondreDocumentJsonPublic } from "./http";
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
  name: string;
  title: string;
  version: string;
  description: string;
  websiteUrl: string;
  repositoryUrl: string;
  remoteUrl: string;
  supportedProtocolVersions: readonly string[];
  oauthRemoteUrl?: string;
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

export function repondreCarteServeur(
  method: string,
  carte: CarteServeur | Record<string, unknown>,
  options: { cacheMaxAge?: number } = {},
): Response {
  return repondreDocumentJsonPublic(method, carte, {
    cacheMaxAge: options.cacheMaxAge,
    contentType: SERVER_CARD_CONTENT_TYPE,
    allowHeaders: "Accept, Content-Type",
  });
}

export interface OptionsDecouverte {
  supportedVersions: readonly string[];
  capabilities: Record<string, unknown>;
  serverInfo: IdentiteServeur;
  instructions?: string;
  ttlMs?: number;
  cacheScope?: PorteeCache;
}

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
