import { describe, expect, it } from "vitest";
import {
  construireCarteServeur,
  repondreCarteServeur,
  resultatDecouverte,
  SERVER_CARD_CONTENT_TYPE,
  SERVER_CARD_SCHEMA,
} from "../src/protocole/decouverte";
import { decoderSentinelle, HEADER_MISMATCH, validerEntetes } from "../src/protocole/entetes";
import {
  avecCache,
  avecServerInfo,
  CLEF_CLIENT,
  CLEF_SERVEUR,
  CLEF_VERSION,
  clientLisible,
  complet,
  estCachable,
  habillerResultat,
  lireMeta,
} from "../src/protocole/meta";
import {
  erreurVersion,
  estModerne,
  negocier,
  negocierInitialize,
  PREMIERE_MODERNE,
  UNSUPPORTED_PROTOCOL_VERSION,
  versionAbsenteAdmise,
} from "../src/protocole/versions";

const SERVIES = ["2026-07-28", "2025-11-25", "2025-06-18"];
const h = (o: Record<string, string>) => new Headers(o);

describe("versions", () => {
  it("la frontière du moderne est 2026-07-28, incluse", () => {
    expect(estModerne(PREMIERE_MODERNE)).toBe(true);
    expect(estModerne("2026-11-01")).toBe(true);
    expect(estModerne("2025-11-25")).toBe(false);
    expect(estModerne("2025-03-26")).toBe(false);
  });

  it("négocier rend la version servie, ou une erreur EXPLOITABLE", () => {
    expect(negocier("2025-11-25", SERVIES)).toEqual({ version: "2025-11-25" });
    const r = negocier("1900-01-01", SERVIES) as { erreur: { code: number; data: unknown } };
    expect(r.erreur.code).toBe(UNSUPPORTED_PROTOCOL_VERSION);
    // Sans la liste des versions servies, un client ne peut que renoncer ; avec elle, il
    // en choisit une et réessaie. C'est tout l'intérêt du champ `data`.
    expect(r.erreur.data).toEqual({ supported: SERVIES, requested: "1900-01-01" });
  });

  it("erreurVersion COPIE la liste — un appelant ne doit pas pouvoir la muter", () => {
    const servies = ["2026-07-28"];
    const e = erreurVersion("x", servies);
    e.data.supported.push("faux");
    expect(servies).toEqual(["2026-07-28"]);
  });

  it("`initialize` est TOUJOURS exempté de l'en-tête de version", () => {
    // Sous 2025-06-18 l'en-tête n'est exigé qu'APRÈS l'initialisation : le POST initialize
    // n'en porte légitimement aucun. Le refuser rejetterait la poignée de tout client
    // conforme, connecteur claude.ai compris.
    expect(versionAbsenteAdmise("initialize", false)).toBe(true);
    expect(versionAbsenteAdmise("initialize", true)).toBe(true);
  });

  it("toute AUTRE méthode sans en-tête suit la décision du dépôt", () => {
    expect(versionAbsenteAdmise("tools/list", false)).toBe(false);
    expect(versionAbsenteAdmise("tools/list", true)).toBe(true);
  });
});

describe("sentinelle base64", () => {
  it("laisse passer une valeur ASCII ordinaire", () => {
    expect(decoderSentinelle("legislation_get_article")).toBe("legislation_get_article");
  });

  it("décode l'UTF-8, et pas seulement les octets", () => {
    // `atob` rend une chaîne d'octets : sans relecture UTF-8, « é » revient en deux
    // caractères et la comparaison échoue sur un nom pourtant correct.
    const encode = `=?base64?${btoa(String.fromCharCode(...new TextEncoder().encode("café à Montréal")))}?=`;
    expect(decoderSentinelle(encode)).toBe("café à Montréal");
  });

  it("rend null sur une charge illisible — un refus vaut mieux qu'un demi-décodage", () => {
    expect(decoderSentinelle("=?base64?!!!pas du base64!!!?=")).toBeNull();
  });

  it("n'est pas déclenchée par une valeur qui y ressemble de loin", () => {
    expect(decoderSentinelle("=?base64?sans fin")).toBe("=?base64?sans fin");
  });
});

describe("validation en-tête contre corps", () => {
  const ok = { method: "tools/list", versionMeta: "2026-07-28" };
  const entetesOk = { "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/list" };

  it("laisse passer ce qui concorde", () => {
    expect(validerEntetes(h(entetesOk), ok)).toBeNull();
  });

  it("le code de refus est bien -32020", () => {
    expect(HEADER_MISMATCH).toBe(-32020);
  });

  it("un en-tête de version MANQUANT est un refus, pas un défaut silencieux", () => {
    expect(validerEntetes(h({ "Mcp-Method": "tools/list" }), ok)).toMatch(/MCP-Protocol-Version/);
  });

  it("une version d'en-tête qui contredit le corps est refusée", () => {
    const r = validerEntetes(
      h({ "MCP-Protocol-Version": "2025-11-25", "Mcp-Method": "tools/list" }),
      ok,
    );
    expect(r).toMatch(/ne correspond pas/);
  });

  it("`Mcp-Method` manquant ou divergent est refusé", () => {
    expect(validerEntetes(h({ "MCP-Protocol-Version": "2026-07-28" }), ok)).toMatch(/Mcp-Method/);
    expect(validerEntetes(h({ ...entetesOk, "Mcp-Method": "tools/call" }), ok)).toMatch(
      /ne correspond pas/,
    );
  });

  it("`Mcp-Name` n'est exigé que pour les trois méthodes qui en ont un", () => {
    // `tools/list` n'a pas de nom : en réclamer un refuserait un client conforme.
    expect(validerEntetes(h(entetesOk), ok)).toBeNull();
  });

  it("`tools/call` exige un `Mcp-Name` qui reflète `params.name`", () => {
    const corps = {
      method: "tools/call",
      params: { name: "outil_x" },
      versionMeta: "2026-07-28",
    };
    const base = { "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call" };
    expect(validerEntetes(h({ ...base, "Mcp-Name": "outil_x" }), corps)).toBeNull();
    expect(validerEntetes(h({ ...base, "Mcp-Name": "autre" }), corps)).toMatch(/ne correspond pas/);
    expect(validerEntetes(h(base), corps)).toMatch(/Mcp-Name/);
  });

  it("`resources/read` compare à `params.uri`, non à `params.name`", () => {
    const corps = {
      method: "resources/read",
      params: { uri: "https://x/id/1" },
      versionMeta: "2026-07-28",
    };
    const base = { "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "resources/read" };
    expect(validerEntetes(h({ ...base, "Mcp-Name": "https://x/id/1" }), corps)).toBeNull();
  });

  it("l'en-tête est DÉCODÉ avant comparaison — sinon tout nom accentué serait refusé", () => {
    const nom = "outil_café";
    const corps = { method: "tools/call", params: { name: nom }, versionMeta: "2026-07-28" };
    const encode = `=?base64?${btoa(String.fromCharCode(...new TextEncoder().encode(nom)))}?=`;
    expect(
      validerEntetes(
        h({
          "MCP-Protocol-Version": "2026-07-28",
          "Mcp-Method": "tools/call",
          "Mcp-Name": encode,
        }),
        corps,
      ),
    ).toBeNull();
  });
});

describe("_meta", () => {
  it("lit version, client et capacités sous leurs clefs préfixées", () => {
    const m = lireMeta({
      _meta: {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": { name: "ExempleClient", version: "1.0.0" },
        "io.modelcontextprotocol/clientCapabilities": {},
      },
    });
    expect(m.protocolVersion).toBe("2026-07-28");
    expect(m.clientInfo?.name).toBe("ExempleClient");
  });

  it("un `_meta` absent ne lève pas", () => {
    expect(lireMeta(undefined)).toEqual({});
    expect(lireMeta({})).toEqual({});
  });

  it("clientLisible ne garde QUE le nom et la version", () => {
    // `clientInfo` est un objet ouvert : un client peut y mettre n'importe quoi, et rien
    // d'autre que ces deux champs ne doit pouvoir entrer dans un journal.
    expect(clientLisible({ name: "Claude", version: "2.1" })).toBe("Claude/2.1");
    expect(clientLisible({ name: "Claude" })).toBe("Claude");
    expect(clientLisible(undefined)).toBeUndefined();
  });

  it("serverInfo va dans `_meta`, PAS à la racine du résultat", () => {
    const r = avecServerInfo({ a: 1 }, { name: "S", version: "1" });
    // Le cast est nécessaire : le TYPE dit déjà qu'il n'y a pas de `serverInfo` à la
    // racine. On vérifie ici le FAIT à l'exécution, pour que la garantie survive à un
    // changement de signature qui l'y remettrait.
    expect((r as Record<string, unknown>).serverInfo).toBeUndefined();
    expect((r._meta as Record<string, unknown>)[CLEF_SERVEUR]).toEqual({ name: "S", version: "1" });
  });

  it("avecServerInfo préserve un `_meta` déjà présent", () => {
    const r = avecServerInfo({ _meta: { autre: 1 } }, { name: "S", version: "1" });
    expect((r._meta as Record<string, unknown>).autre).toBe(1);
  });
});

describe("indices de cache", () => {
  it("`server/discover` EST cachable — le tableau de la §3.2 l'oubliait", () => {
    expect(estCachable("server/discover")).toBe(true);
    for (const m of ["tools/list", "resources/read", "resources/templates/list"]) {
      expect(estCachable(m)).toBe(true);
    }
    expect(estCachable("tools/call")).toBe(false);
  });

  it("refuse un ttlMs négatif ou fractionnaire", () => {
    expect(() => avecCache({}, -1, "public")).toThrow();
    expect(() => avecCache({}, 1.5, "public")).toThrow();
    expect(avecCache({}, 0, "private").ttlMs).toBe(0);
  });

  it("complet() pose resultType, et rien d'autre", () => {
    expect(complet({ a: 1 })).toEqual({ a: 1, resultType: "complete" });
  });
});

describe("server/discover", () => {
  const base = {
    supportedVersions: SERVIES,
    capabilities: { tools: {} },
    serverInfo: { name: "Serveur", version: "0.2.0" },
    instructions: "Orientation.",
  };

  it("porte versions, capacités, instructions, resultType ET les indices de cache", () => {
    const r = resultatDecouverte(base);
    expect(r.supportedVersions).toEqual(SERVIES);
    expect(r.capabilities).toEqual({ tools: {} });
    expect(r.instructions).toBe("Orientation.");
    expect(r.resultType).toBe("complete");
    expect(r.ttlMs).toBe(3_600_000);
    expect(r.cacheScope).toBe("public");
  });

  it("met serverInfo dans `_meta` — l'erreur facile, puisque initialize le mettait ailleurs", () => {
    const r = resultatDecouverte(base);
    expect(r.serverInfo).toBeUndefined();
    expect((r._meta as Record<string, unknown>)[CLEF_SERVEUR]).toEqual(base.serverInfo);
  });

  it("omet `instructions` quand il n'y en a pas, au lieu d'en mettre une vide", () => {
    const { instructions, ...sans } = base;
    expect(resultatDecouverte(sans)).not.toHaveProperty("instructions");
  });
});

describe("durcissement UTF-8, _meta et prototype sur entetes/meta", () => {
  it("decoderSentinelle rejette les octets UTF-8 invalides au lieu de substituer U+FFFD", () => {
    const invalide = `=?base64?${btoa(String.fromCharCode(0xff, 0xfe, 0xfd))}?=`;
    expect(decoderSentinelle(invalide)).toBeNull();
  });

  it("validerEntetes rejette un _meta non-objet ou protocolVersion non textuel", () => {
    const headers = h({ "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/list" });
    expect(validerEntetes(headers, { method: "tools/list", versionMeta: 123 })).not.toBeNull();
    expect(
      validerEntetes(headers, {
        method: "tools/list",
        params: { _meta: { [CLEF_VERSION]: 123 } },
      }),
    ).not.toBeNull();
    expect(
      validerEntetes(headers, {
        method: "tools/list",
        params: { _meta: { [CLEF_VERSION]: "2025-11-25" } },
      }),
    ).not.toBeNull();
    expect(
      validerEntetes(headers, {
        method: "tools/list",
        params: { _meta: ["tableau"] },
      }),
    ).not.toBeNull();
  });

  it("validerEntetes supporte exigerVersionMeta et résiste aux noms du prototype", () => {
    const headers = h({ "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "toString" });
    expect(validerEntetes(headers, { method: "toString" })).toBeNull();
    expect(
      validerEntetes(
        h({ "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/list" }),
        { method: "tools/list" },
        { exigerVersionMeta: true },
      ),
    ).not.toBeNull();
    expect(
      validerEntetes(
        h({ "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/list" }),
        { method: "tools/list", params: { _meta: { [CLEF_VERSION]: "2026-07-28" } } },
        { exigerVersionMeta: true },
      ),
    ).toBeNull();
  });

  it("lireMeta et clientLisible ignorent les tableaux et champs non textuels", () => {
    expect(lireMeta({ _meta: ["tableau"] })).toEqual({});
    expect(lireMeta({ _meta: { [CLEF_CLIENT]: ["x"], [CLEF_VERSION]: 42 } })).toEqual({
      protocolVersion: undefined,
      clientInfo: undefined,
      clientCapabilities: undefined,
    });
    expect(lireMeta({ _meta: { [CLEF_CLIENT]: { name: 123, version: {} } } }).clientInfo).toEqual(
      {},
    );
    expect(clientLisible({ name: 123 as unknown as string, version: "1.0" })).toBeUndefined();
    expect(clientLisible({ name: "Claude", version: 99 as unknown as string })).toBe("Claude");
  });
});

describe("habillerResultat et negocierInitialize", () => {
  it("habillerResultat laisse intact sous hérité et habille sous moderne", () => {
    expect(habillerResultat({ ok: true }, { moderne: false, ttlMs: 1000 })).toEqual({ ok: true });
    const mod = habillerResultat(
      { ok: true },
      { moderne: true, ttlMs: 60_000, serverInfo: { name: "S", title: "Titre", version: "1.0" } },
    );
    expect(mod.resultType).toBe("complete");
    expect(mod.ttlMs).toBe(60_000);
    expect(mod.cacheScope).toBe("public");
    expect((mod._meta as Record<string, unknown>)[CLEF_SERVEUR]).toEqual({
      name: "S",
      title: "Titre",
      version: "1.0",
    });
  });

  it("negocierInitialize retombe sur la plus haute version héritée", () => {
    expect(negocierInitialize("2025-06-18", SERVIES)).toBe("2025-06-18");
    expect(negocierInitialize("1999-01-01", SERVIES)).toBe("2025-11-25");
    expect(negocierInitialize(undefined, SERVIES)).toBe("2025-11-25");
    expect(negocierInitialize(123, SERVIES)).toBe("2025-11-25");
    expect(negocierInitialize(undefined, [PREMIERE_MODERNE])).toBe(PREMIERE_MODERNE);
  });
});

describe("fiche SEP-2127 (server card)", () => {
  it("construit et sert GET, HEAD, OPTIONS et 405", async () => {
    const carte = construireCarteServeur({
      name: "ca.exemple/test",
      title: "Serveur Test",
      version: "0.6.0",
      description: "Description publique.",
      websiteUrl: "https://exemple.test/",
      repositoryUrl: "https://github.com/exemple/test",
      remoteUrl: "https://exemple.test/mcp",
      supportedProtocolVersions: SERVIES,
    });
    expect(carte.$schema).toBe(SERVER_CARD_SCHEMA);
    expect(carte.remotes[0]!.supportedProtocolVersions).toEqual(SERVIES);

    const opt = repondreCarteServeur("OPTIONS", carte);
    expect(opt.status).toBe(204);
    expect(opt.headers.get("Access-Control-Allow-Origin")).toBe("*");

    const get = repondreCarteServeur("GET", carte);
    expect(get.status).toBe(200);
    expect(get.headers.get("Content-Type")).toBe(SERVER_CARD_CONTENT_TYPE);
    expect(get.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(await get.json()).toEqual(carte);

    const head = repondreCarteServeur("HEAD", carte);
    expect(head.status).toBe(200);
    expect(await head.text()).toBe("");

    const post = repondreCarteServeur("POST", carte);
    expect(post.status).toBe(405);
    expect(post.headers.get("Allow")).toBe("GET, HEAD, OPTIONS");
  });
});
