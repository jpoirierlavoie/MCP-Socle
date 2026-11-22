import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { construireSchemaIdentiteD1 } from "../src/identite/gouverne";
import {
  calculerDefiPkceS256,
  construireRessourceProtegee,
  construireServeurAutorisation,
  estClientIdMetadonneesValide,
  estUriRedirectionAutorisee,
  estVerificateurPkceValide,
  MAX_SERVICES_PORTEE,
  normaliserPorteeOAuth,
  porteesCanoniques,
  repondreRessourceProtegee,
  repondreServeurAutorisation,
  URIS_REDIRECTION_CLAUDE,
  URIS_REDIRECTION_GOOGLE_CONNUES,
  URIS_REDIRECTION_OPENAI_CONNUES,
  urlMetadonneesRessource,
  validerMetadonneesClientCimd,
  validerMetadonneesInscriptionDcr,
  verifierDefiPkceS256,
} from "../src/identite/oauth";
import { construireEnteteBearer, refuser } from "../src/identite/refus";
import { preflight } from "../src/protocole/http";

describe("refus 401 RFC 9728 vs 404 sans oracle et pré-vol extensible", () => {
  it("émet WWW-Authenticate Bearer avec resource_metadata valide, translittère les accents et rejette toute injection", async () => {
    const rep401 = refuser("401", "https://gemini.google.com", {
      resourceMetadata: "https://exemple.test/.well-known/oauth-protected-resource/mcp/oauth",
      scope: "les_deux",
      error: "invalid_token",
      errorDescription: 'Jeton expiré\r\n"test"',
    });

    expect(rep401.status).toBe(401);
    expect(rep401.headers.get("Access-Control-Allow-Origin")).toBe("https://gemini.google.com");
    const www = rep401.headers.get("WWW-Authenticate") ?? "";
    expect(www).toContain(
      'resource_metadata="https://exemple.test/.well-known/oauth-protected-resource/mcp/oauth"',
    );
    expect(www).toContain('scope="les_deux"');
    expect(www).toContain('error="invalid_token"');
    expect(www).toContain('error_description="Jeton expire test"');
    expect(www).not.toContain("\r");
    expect(www).not.toContain("\n");

    // Une resourceMetadata malveillante contenant CRLF ou guillemet est rejetée intégralement :
    const wwwInjectee = construireEnteteBearer({
      resourceMetadata:
        'https://exemple.test/.well-known/oauth-protected-resource/mcp/oauth"\r\nX-Injecte: 1',
      errorDescription: "Sans code error -> ne doit pas émettre error_description (RFC 6750 §3.1)",
    });
    expect(wwwInjectee).toBe("Bearer");
    expect(wwwInjectee).not.toContain("X-Injecte");
    expect(wwwInjectee).not.toContain("error_description");

    expect(construireEnteteBearer()).toBe("Bearer");

    // Sur /mcp (forme 404), aucune option OAuth ne doit jamais fuir.
    const rep404 = refuser("404", "https://claude.ai", {
      resourceMetadata: "https://exemple.test/.well-known/oauth-protected-resource",
    });
    expect(rep404.status).toBe(404);
    expect(await rep404.text()).toBe("");
    expect(rep404.headers.get("WWW-Authenticate")).toBeNull();
  });

  it("preflight accepte des en-têtes supplémentaires valides et ignore les entrées mal formées", () => {
    const rep = preflight("https://claude.ai", ["X-Porteur-Externe", "Mauvais En-Tete\r\n"]);
    const allow = rep.headers.get("Access-Control-Allow-Headers") ?? "";
    expect(allow).toContain("X-Porteur-Externe");
    expect(allow).not.toContain("Mauvais");
  });
});

describe("RFC 9728 et RFC 8414 — découverte OAuth 2.1", () => {
  it("calcule et sert la fiche de ressource protégée RFC 9728 (GET, HEAD, OPTIONS, 405)", async () => {
    const urlMeta = urlMetadonneesRessource("https://service.exemple.test/mcp/oauth/");
    expect(urlMeta).toBe(
      "https://service.exemple.test/.well-known/oauth-protected-resource/mcp/oauth",
    );
    expect(urlMetadonneesRessource("https://service.exemple.test/")).toBe(
      "https://service.exemple.test/.well-known/oauth-protected-resource",
    );

    const doc = construireRessourceProtegee({
      resource: "https://service.exemple.test/mcp/oauth",
      authorizationServers: ["https://acces.exemple.test/"],
      scopesSupported: ["les_deux", "service_a"],
      resourceDocumentation: "https://service.exemple.test/",
    });

    expect(doc).toEqual({
      resource: "https://service.exemple.test/mcp/oauth",
      authorization_servers: ["https://acces.exemple.test"],
      bearer_methods_supported: ["header"],
      scopes_supported: ["les_deux", "service_a"],
      resource_documentation: "https://service.exemple.test/",
    });

    const getRep = repondreRessourceProtegee("GET", doc);
    expect(getRep.status).toBe(200);
    expect(getRep.headers.get("Access-Control-Allow-Origin")).toBe("*");
    expect(getRep.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(await getRep.json()).toEqual(doc);

    const headRep = repondreRessourceProtegee("HEAD", doc);
    expect(headRep.status).toBe(200);
    expect(await headRep.text()).toBe("");

    expect(repondreRessourceProtegee("OPTIONS", doc).status).toBe(204);
    expect(repondreRessourceProtegee("POST", doc).status).toBe(405);

    expect(() =>
      construireRessourceProtegee({
        resource: "http://non-https.test/mcp/oauth",
        authorizationServers: ["https://acces.exemple.test"],
      }),
    ).toThrow();
    expect(() =>
      construireRessourceProtegee({
        resource: "https://service.exemple.test/mcp/oauth",
        authorizationServers: [],
      }),
    ).toThrow();
  });

  it("construit et sert la fiche de serveur d'autorisation RFC 8414 (S256 obligatoire, CIMD actif)", async () => {
    const asMeta = construireServeurAutorisation({
      issuer: "https://acces.exemple.test/",
      scopesSupported: ["les_deux"],
      revocationEndpoint: "https://acces.exemple.test/oauth/revoke",
      authorizationResponseIssParameterSupported: true,
    });

    expect(asMeta.issuer).toBe("https://acces.exemple.test");
    expect(asMeta.authorization_endpoint).toBe("https://acces.exemple.test/oauth/authorize");
    expect(asMeta.token_endpoint).toBe("https://acces.exemple.test/oauth/token");
    expect(asMeta.code_challenge_methods_supported).toEqual(["S256"]);
    expect(asMeta.client_id_metadata_document_supported).toBe(true);
    expect(asMeta.authorization_response_iss_parameter_supported).toBe(true);

    const rep = repondreServeurAutorisation("GET", asMeta);
    expect(rep.status).toBe(200);
    expect(await rep.json()).toEqual(asMeta);
  });
});

describe("G35 — PKCE S256 (vecteur officiel RFC 7636 Annexe B et rejets OAuth 2.1)", () => {
  it("calcule exactement le vecteur RFC 7636 Annexe B et rejette plain ainsi que les bornes hors 43..128", async () => {
    const verificateurRfc = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const defiAttenduRfc = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    expect(await calculerDefiPkceS256(verificateurRfc)).toBe(defiAttenduRfc);
    expect(await verifierDefiPkceS256(verificateurRfc, defiAttenduRfc, "S256")).toBe(true);
    expect(await verifierDefiPkceS256(verificateurRfc, defiAttenduRfc, "plain")).toBe(false);
    expect(await verifierDefiPkceS256(`${verificateurRfc}X`, defiAttenduRfc, "S256")).toBe(false);

    expect(estVerificateurPkceValide("a".repeat(42))).toBe(false);
    expect(estVerificateurPkceValide("a".repeat(43))).toBe(true);
    expect(estVerificateurPkceValide("a".repeat(128))).toBe(true);
    expect(estVerificateurPkceValide("a".repeat(129))).toBe(false);
    expect(estVerificateurPkceValide(`${"a".repeat(42)} `)).toBe(false);
  });
});

describe("G36 — Validation des redirect_uri, CIMD anti-SSRF et normalisation de portée", () => {
  it("autorise les rappels HTTPS exacts (Claude, Gemini/Vertex) et rejette espaces, caractères de contrôle et normalisations implicites", () => {
    const urisAutorisees = [
      ...URIS_REDIRECTION_CLAUDE,
      ...URIS_REDIRECTION_GOOGLE_CONNUES,
      ...URIS_REDIRECTION_OPENAI_CONNUES,
    ];
    expect(
      estUriRedirectionAutorisee("https://chatgpt.com/connector_platform_oauth_redirect", {
        urisExactesAutorisees: urisAutorisees,
      }),
    ).toBe(true);

    expect(
      estUriRedirectionAutorisee("https://claude.ai/api/mcp/auth_callback", {
        urisExactesAutorisees: urisAutorisees,
      }),
    ).toBe(true);
    expect(
      estUriRedirectionAutorisee("https://vertexaisearch.cloud.google.com/oauth-redirect", {
        urisExactesAutorisees: urisAutorisees,
      }),
    ).toBe(true);
    expect(
      estUriRedirectionAutorisee("https://antigravity.google/oauth-callback", {
        urisExactesAutorisees: urisAutorisees,
      }),
    ).toBe(true);

    // Boucle locale désactivée par défaut :
    expect(estUriRedirectionAutorisee("http://127.0.0.1:54321/callback")).toBe(false);

    // Boucle locale activée (avec et sans port explicite) :
    for (const locale of [
      "http://127.0.0.1/callback",
      "http://localhost/callback",
      "http://127.0.0.1:54321/callback",
      "http://localhost:8080/oauth/callback",
      "http://127.0.0.1:54321/oauth-callback",
      "http://localhost:8080/oauth2callback",
      "http://127.0.0.1:8080/auth/callback",
      "http://[::1]:3000/callback",
    ]) {
      expect(estUriRedirectionAutorisee(locale, { autoriserBoucleLocale: true })).toBe(true);
    }

    // Rejets de sécurité (incluant \x00/\r/\n/\t rognés silencieusement par WHATWG URL et :443) :
    for (const dangereuse of [
      "http://claude.ai/api/mcp/auth_callback",
      " https://claude.ai/api/mcp/auth_callback",
      "https://claude.ai/api/mcp/auth_callback\n",
      "\x00https://claude.ai/api/\r\nmcp/auth_callback",
      "https://CLAUDE.AI/api/mcp/auth_callback",
      "https://claude.ai:443/api/mcp/auth_callback",
      "http://127.0.0.1:/callback",
      "http://127.0.0.1:80/callback",
      "http://127.0.0.1:0080/callback",
      "http://127.0.0.1:8080/call\r\nback",
      "http://LOCALHOST:8080/callback",
      "http://192.168.1.10:8080/callback",
      "https://claude.ai/api/mcp/auth_callback#fragment",
      "https://user:pass@claude.ai/api/mcp/auth_callback",
      "http://127.0.0.1:8080/callback?fuite=1",
      "http://127.0.0.1:8080/autre",
      "https://claude.ai/api/mcp/../autre",
      "javascript:alert(1)",
    ]) {
      expect(
        estUriRedirectionAutorisee(dangereuse, {
          urisExactesAutorisees: urisAutorisees,
          autoriserBoucleLocale: true,
        }),
        dangereuse,
      ).toBe(false);
    }
  });

  it("bloque tout vecteur SSRF, requête de contournement de cache et caractère de contrôle sur les URLs CIMD", () => {
    expect(estClientIdMetadonneesValide("https://client.exemple.org/oauth/client.json")).toBe(true);
    expect(estClientIdMetadonneesValide("https://app.claude.ai/.well-known/client.json")).toBe(
      true,
    );
    expect(
      estClientIdMetadonneesValide("https://xn--bcher-kva.exemple.org/oauth/client.json"),
    ).toBe(true);

    for (const ssrfOuInvalide of [
      "http://client.exemple.org/oauth/client.json",
      " https://client.exemple.org/oauth/client.json",
      "https://client.exemple.org/oauth/\r\nclient.json",
      "https://client.exemple.org/",
      "https://client.exemple.org:8443/oauth/client.json",
      "https://client.exemple.org:443/oauth/client.json",
      "https://client.exemple.org/oauth/client.json?cachebust=1",
      "https://client.exemple.org/oauth/../secret.json",
      "https://client.exemple.org/oauth/client.json#frag",
      "https://user:secret@client.exemple.org/oauth/client.json",
      "https://localhost/client.json",
      "https://sub.localhost/client.json",
      "https://intranet.local/client.json",
      "https://metadata.internal/client.json",
      "https://cache.onion/client.json",
      "https://interne.corp/client.json",
      "https://hote-sans-point/client.json",
      "https://127.0.0.1/client.json",
      "https://127.0.0.1./client.json",
      "https://localhost./client.json",
      "https://intranet.local./client.json",
      "https://client.exemple.org/oauth%2f..%2fsecret.json",
      "https://client.exemple.org/oauth/%00client.json",
      "https://client.exemple.org/oauth/%0d%0aclient.json",
      "https://169.254.169.254/latest/meta-data",
      "https://0177.0.0.1/client.json",
      "https://2130706433/client.json",
      "https://[::1]/client.json",
      "https://[fe80::1%25eth0]/client.json",
      "https://[::ffff:127.0.0.1]/client.json",
    ]) {
      expect(estClientIdMetadonneesValide(ssrfOuInvalide), ssrfOuInvalide).toBe(false);
    }
  });

  it("valide les documents clients CIMD (interdiction des secrets symétriques) et normalise les portées OAuth", () => {
    const cid = "https://app.claude.ai/.well-known/oauth-client.json";
    const okDoc = validerMetadonneesClientCimd(cid, {
      client_id: cid,
      client_name: "Client Recherche",
      redirect_uris: ["https://claude.ai/api/mcp/auth_callback"],
      token_endpoint_auth_method: "none",
    });
    expect(okDoc).toEqual({
      ok: true,
      client: {
        clientId: cid,
        clientName: "Client Recherche",
        redirectUris: ["https://claude.ai/api/mcp/auth_callback"],
        tokenEndpointAuthMethod: "none",
      },
    });

    const sep3149 = validerMetadonneesClientCimd("https://chatgpt.com/oauth/client.json", {
      client_id: "https://chatgpt.com/oauth/client.json",
      client_name: "ChatGPT",
      redirect_uris: ["https://chatgpt.com/connector_platform_oauth_redirect"],
      token_endpoint_auth_method: "private_key_jwt",
      token_endpoint_auth_methods_supported: ["none", "private_key_jwt"],
    });
    expect(sep3149).toEqual({
      ok: true,
      client: {
        clientId: "https://chatgpt.com/oauth/client.json",
        clientName: "ChatGPT",
        redirectUris: ["https://chatgpt.com/connector_platform_oauth_redirect"],
        tokenEndpointAuthMethod: "private_key_jwt",
        tokenEndpointAuthMethodsSupported: ["none", "private_key_jwt"],
      },
    });

    expect(
      validerMetadonneesClientCimd("https://chatgpt.com/oauth/client.json", {
        client_id: "https://chatgpt.com/oauth/client.json",
        redirect_uris: ["https://chatgpt.com/connector_platform_oauth_redirect"],
        token_endpoint_auth_method: "private_key_jwt",
        token_endpoint_auth_methods_supported: ["client_secret_post"],
      }).ok,
    ).toBe(false);

    // Rejette client_id discordant, client_secret public ou redirect_uri SSRF :
    expect(
      validerMetadonneesClientCimd(cid, {
        client_id: "https://autre.exemple.org/c.json",
        redirect_uris: ["https://claude.ai/api/mcp/auth_callback"],
      }).ok,
    ).toBe(false);
    expect(
      validerMetadonneesClientCimd(cid, {
        client_id: cid,
        client_secret: "interdit-en-public",
        redirect_uris: ["https://claude.ai/api/mcp/auth_callback"],
      }).ok,
    ).toBe(false);
    expect(
      validerMetadonneesClientCimd(cid, {
        client_id: cid,
        token_endpoint_auth_method: "client_secret_post",
        redirect_uris: ["https://claude.ai/api/mcp/auth_callback"],
      }).ok,
    ).toBe(false);
    expect(
      validerMetadonneesClientCimd(cid, {
        client_id: cid,
        redirect_uris: ["https://127.0.0.1/callback"],
      }).ok,
    ).toBe(false);

    // Normalisation des portées OAuth vers DB_IDENTITE :
    const services = ["service_a", "service_b"];
    expect(normaliserPorteeOAuth(undefined, services)).toBe("les_deux");
    expect(normaliserPorteeOAuth("", services)).toBe("les_deux");
    expect(normaliserPorteeOAuth("les_deux", services)).toBe("les_deux");
    expect(normaliserPorteeOAuth("service_b service_a", services)).toBe("les_deux");
    expect(normaliserPorteeOAuth("service_a", services)).toBe("service_a");
    expect(normaliserPorteeOAuth("service_a portee_inconnue", services)).toBeNull();
    expect(normaliserPorteeOAuth("service_a", [])).toBeNull();
    expect(normaliserPorteeOAuth("service_a", ["les_deux"])).toBeNull();
    expect(normaliserPorteeOAuth("service_a ".repeat(60), services)).toBeNull();
    expect(
      normaliserPorteeOAuth(
        "s1",
        Array.from({ length: MAX_SERVICES_PORTEE + 1 }, (_, i) => `s_${i}`),
      ),
    ).toBeNull();
  });

  it("maintient une cohérence stricte entre normaliserPorteeOAuth et CHECK (portee IN (...)) sur D1 pour 3+ services", async () => {
    const troisServices = ["service_c", "service_a", "service_b"];
    expect(porteesCanoniques(troisServices)).toEqual([
      "les_deux",
      "service_a",
      "service_b",
      "service_c",
      "service_a service_b",
      "service_a service_c",
      "service_b service_c",
    ]);

    expect(normaliserPorteeOAuth("service_b service_a", troisServices)).toBe("service_a service_b");
    expect(normaliserPorteeOAuth("service_c service_a", troisServices)).toBe("service_a service_c");
    expect(normaliserPorteeOAuth("service_c service_b service_a", troisServices)).toBe("les_deux");

    const db = env.DB_IDENTITE_TEST;
    const instructions = construireSchemaIdentiteD1(troisServices)
      .split(";")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    await db.batch([
      db.prepare("PRAGMA foreign_keys = ON"),
      ...instructions.map((sql) => db.prepare(sql)),
    ]);

    await db
      .prepare(
        `INSERT INTO titulaire (
          id, cree_le, etat, nom, numero_membre, section, courriel, attestation_le, attestation_ver, cgu_ver
        ) VALUES ('tit_oauth_3', '2026-11-18T00:00:00.000Z', 'actif', 'Test Trois', '333333-3', 'Montreal', 'trois@exemple.org', '2026-11-18T00:00:00.000Z', 'v1', 'v1')`,
      )
      .run();

    const porteeSousEnsemble = normaliserPorteeOAuth("service_b service_a", troisServices)!;
    await db
      .prepare(
        `INSERT INTO code_oauth (
          id, titulaire_id, empreinte_code, client_id, redirect_uri, portee, defi_pkce, methode_pkce, cree_le, expire_le
        ) VALUES ('co_3_ok', 'tit_oauth_3', 'hash_co_3_ok', 'cl_1', 'https://claude.ai/api/mcp/auth_callback', ?1, 'defi_s256', 'S256', '2026-11-18T00:00:00.000Z', '2026-11-18T00:05:00.000Z')`,
      )
      .bind(porteeSousEnsemble)
      .run();

    await db
      .prepare(
        `INSERT INTO jeton (
          id, titulaire_id, empreinte, queue, libelle, portee, emis_le
        ) VALUES ('jet_3_ok', 'tit_oauth_3', 'hash_jet_3_ok', '123456', 'Sous-ensemble', ?1, '2026-11-18T00:00:00.000Z')`,
      )
      .bind(porteeSousEnsemble)
      .run();

    // Une portée non triée (« service_b service_a ») ou hors schéma est rejetée par SQLite CHECK :
    await expect(
      db
        .prepare(
          `INSERT INTO jeton (
            id, titulaire_id, empreinte, queue, libelle, portee, emis_le
          ) VALUES ('jet_3_bad', 'tit_oauth_3', 'hash_jet_3_bad', '654321', 'Non triee', 'service_b service_a', '2026-11-18T00:00:00.000Z')`,
        )
        .run(),
    ).rejects.toThrow();
  });
});

describe("RFC 7591 — Validation hors réseau d'inscription dynamique DCR", () => {
  it("valide les clients publics et confidentiels autorisés et normalise grant_types/response_types", () => {
    const publicLoopback = validerMetadonneesInscriptionDcr(
      {
        client_name: "  Antigravity IDE  ",
        redirect_uris: [
          "http://127.0.0.1:54321/oauth-callback",
          "http://127.0.0.1:54321/oauth-callback",
        ],
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: "none",
      },
      { autoriserBoucleLocale: true },
    );
    expect(publicLoopback).toEqual({
      ok: true,
      client: {
        clientName: "Antigravity IDE",
        redirectUris: ["http://127.0.0.1:54321/oauth-callback"],
        tokenEndpointAuthMethod: "none",
        grantTypes: ["authorization_code"],
        responseTypes: ["code"],
      },
    });

    const publicDefaut = validerMetadonneesInscriptionDcr({
      redirect_uris: ["https://claude.ai/api/mcp/auth_callback"],
    });
    expect(publicDefaut).toEqual({
      ok: true,
      client: {
        redirectUris: ["https://claude.ai/api/mcp/auth_callback"],
        tokenEndpointAuthMethod: "none",
        grantTypes: ["authorization_code"],
        responseTypes: ["code"],
      },
    });

    const confidentielPost = validerMetadonneesInscriptionDcr({
      client_name: "Connecteur Confidentiel",
      redirect_uris: ["https://claude.com/api/mcp/auth_callback"],
      token_endpoint_auth_method: "client_secret_post",
    });
    expect(confidentielPost).toEqual({
      ok: true,
      client: {
        clientName: "Connecteur Confidentiel",
        redirectUris: ["https://claude.com/api/mcp/auth_callback"],
        tokenEndpointAuthMethod: "client_secret_post",
        grantTypes: ["authorization_code"],
        responseTypes: ["code"],
      },
    });

    const confidentielBasic = validerMetadonneesInscriptionDcr({
      redirect_uris: ["https://antigravity.google/oauth-callback"],
      token_endpoint_auth_method: "client_secret_basic",
    });
    expect(confidentielBasic.ok).toBe(true);
  });

  it("rejette les URIs dangereuses ou SSRF (invalid_redirect_uri) et métadonnées non conformes (invalid_client_metadata)", () => {
    for (const mauvaisUri of [
      [],
      Array.from({ length: 9 }, (_, i) => `https://app${i}.exemple.org/cb`),
      ["http://exemple.org/callback"],
      ["https://127.0.0.1/callback"],
      ["https://169.254.169.254/latest/meta-data"],
      ["http://127.0.0.1:54321/oauth-callback"], // boucle locale non activée
      ["javascript:alert(1)"],
    ]) {
      const res = validerMetadonneesInscriptionDcr({ redirect_uris: mauvaisUri });
      expect(res.ok, JSON.stringify(mauvaisUri)).toBe(false);
      if (!res.ok) {
        expect(res.codeErreur).toBe("invalid_redirect_uri");
      }
    }

    for (const mauvaisDoc of [
      null,
      [],
      { redirect_uris: ["https://claude.ai/cb"], grant_types: ["client_credentials"] },
      { redirect_uris: ["https://claude.ai/cb"], grant_types: ["refresh_token"] },
      { redirect_uris: ["https://claude.ai/cb"], response_types: ["token"] },
      { redirect_uris: ["https://claude.ai/cb"], token_endpoint_auth_method: "private_key_jwt" },
      { redirect_uris: ["https://claude.ai/cb"], client_name: "Bad\r\nName" },
      { redirect_uris: ["https://claude.ai/cb"], client_name: "   " },
      { redirect_uris: ["https://claude.ai/cb"], client_name: "x".repeat(81) },
    ]) {
      const res = validerMetadonneesInscriptionDcr(mauvaisDoc);
      expect(res.ok, JSON.stringify(mauvaisDoc)).toBe(false);
      if (!res.ok) {
        expect(res.codeErreur).toBe("invalid_client_metadata");
      }
    }
  });
});
