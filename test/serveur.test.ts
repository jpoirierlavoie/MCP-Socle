import { describe, expect, it } from "vitest";
import { HEADER_MISMATCH } from "../src/protocole/entetes";
import { CLEF_SERVEUR, CLEF_VERSION } from "../src/protocole/meta";
import { appelerOutil, listToolDescriptors, type Registre } from "../src/protocole/registre";
import {
  INTERNAL_ERROR,
  INVALID_REQUEST,
  METHOD_NOT_FOUND,
  ok,
  PARSE_ERROR,
} from "../src/protocole/rpc";
import { lireCorpsBorne, MAX_OCTETS_CORPS_MCP, servirRequeteMcp } from "../src/protocole/serveur";

const VERSIONS = ["2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"] as const;
const SERVER_INFO = { name: "Test", title: "Serveur Test", version: "0.6.0" };
const CAPABILITIES = { tools: { listChanged: false } };

const REGISTRE: Registre<{ tag: string }> = {
  saluer: {
    title: "Saluer",
    description: "Renvoie un salut",
    inputSchema: {
      type: "object",
      properties: { qui: { type: "string" } },
      required: ["qui"],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true },
    handler: async (args, ctx) => ok(`Bonjour ${String(args.qui)} (${ctx.tag})`),
  },
  résumer: {
    title: "Résumer",
    description: "Outil avec accent pour tester la sentinelle base64",
    inputSchema: { type: "object", additionalProperties: false },
    annotations: { readOnlyHint: true },
    handler: async () => ok("résumé prêt"),
  },
};

function optionsBase(extra: Partial<Parameters<typeof servirRequeteMcp>[1]> = {}) {
  return {
    versions: VERSIONS,
    capabilities: CAPABILITIES,
    serverInfo: SERVER_INFO,
    instructions: "Instructions de test.",
    descripteurs: listToolDescriptors(REGISTRE),
    appeler: (nom: unknown, args: unknown) => appelerOutil(REGISTRE, nom, args, { tag: "v1" }),
    origin: "https://claude.ai",
    sertAvant2025_06_18: true,
    ...extra,
  };
}

function post(body: string | BodyInit, headers: Record<string, string> = {}) {
  return new Request("https://exemple.test/mcp", { method: "POST", body, headers });
}

describe("lireCorpsBorne", () => {
  it("rejette d'emblée un Content-Length supérieur au plafond", async () => {
    const r = new Request("https://exemple.test/mcp", {
      method: "POST",
      body: "{}",
      headers: { "Content-Length": String(MAX_OCTETS_CORPS_MCP + 1) },
    });
    expect(await lireCorpsBorne(r)).toEqual({ ok: false, motif: "trop_grand" });
  });

  it("coupe un flux sans Content-Length dès que le plafond est dépassé", async () => {
    let i = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (i++ < 10) {
          controller.enqueue(new Uint8Array(10_000).fill(97));
        } else {
          controller.close();
        }
      },
    });
    const res = await lireCorpsBorne(post(stream), 32_768);
    expect(res).toEqual({ ok: false, motif: "trop_grand" });
  });

  it("rejette les séquences UTF-8 invalides", async () => {
    const res = await lireCorpsBorne(post(new Uint8Array([0xff, 0xfe, 0xfd])));
    expect(res).toEqual({ ok: false, motif: "encodage" });
  });
});

describe("servirRequeteMcp", () => {
  it("rend 413 si le corps dépasse MAX_OCTETS_CORPS_MCP", async () => {
    const tropGros = JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "ping",
      params: { pad: "x".repeat(MAX_OCTETS_CORPS_MCP) },
    });
    const rep = await servirRequeteMcp(post(tropGros), optionsBase());
    expect(rep.status).toBe(413);
    expect(rep.headers.get("Access-Control-Allow-Origin")).toBe("https://claude.ai");
    const json = (await rep.json()) as { error: { code: number } };
    expect(json.error.code).toBe(INVALID_REQUEST);
  });

  it("rend 200 avec PARSE_ERROR sur JSON invalide et 202 sur notification", async () => {
    const invalide = await servirRequeteMcp(post("{pas-json"), optionsBase());
    expect(invalide.status).toBe(200);
    expect(((await invalide.json()) as { error: { code: number } }).error.code).toBe(PARSE_ERROR);

    const notif = await servirRequeteMcp(
      post(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })),
      optionsBase(),
    );
    expect(notif.status).toBe(202);
    expect(await notif.text()).toBe("");
    expect(notif.headers.get("Access-Control-Allow-Origin")).toBe("https://claude.ai");
  });

  it("gère la négociation de version et les erreurs d'en-tête", async () => {
    const manquant = await servirRequeteMcp(
      post(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" })),
      optionsBase({ sertAvant2025_06_18: false }),
    );
    expect(manquant.status).toBe(400);
    expect(((await manquant.json()) as { error: { code: number } }).error.code).toBe(
      HEADER_MISMATCH,
    );

    const inconnu = await servirRequeteMcp(
      post(JSON.stringify({ jsonrpc: "2.0", id: 2, method: "ping" }), {
        "MCP-Protocol-Version": "1999-01-01",
      }),
      optionsBase(),
    );
    expect(inconnu.status).toBe(400);

    const discordeMeta = await servirRequeteMcp(
      post(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 3,
          method: "tools/list",
          params: { _meta: { [CLEF_VERSION]: 123 } },
        }),
        { "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/list" },
      ),
      optionsBase(),
    );
    expect(discordeMeta.status).toBe(400);
    expect(((await discordeMeta.json()) as { error: { code: number } }).error.code).toBe(
      HEADER_MISMATCH,
    );
  });

  it("permet d'omettre _meta sur ping même avec exigerVersionMeta et vérifie Mcp-Name", async () => {
    const ping = await servirRequeteMcp(
      post(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }), {
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": "ping",
      }),
      optionsBase({ exigerVersionMeta: true }),
    );
    expect(ping.status).toBe(200);
    expect(((await ping.json()) as { result: { resultType: string } }).result.resultType).toBe(
      "complete",
    );

    const callSansMeta = await servirRequeteMcp(
      post(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 2,
          method: "tools/call",
          params: { name: "saluer", arguments: { qui: "Alice" } },
        }),
        {
          "MCP-Protocol-Version": "2026-07-28",
          "Mcp-Method": "tools/call",
          "Mcp-Name": "saluer",
        },
      ),
      optionsBase({ exigerVersionMeta: true }),
    );
    expect(callSansMeta.status).toBe(400);

    const callOk = await servirRequeteMcp(
      post(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 3,
          method: "tools/call",
          params: {
            name: "saluer",
            arguments: { qui: "Alice" },
            _meta: { [CLEF_VERSION]: "2026-07-28" },
          },
        }),
        {
          "MCP-Protocol-Version": "2026-07-28",
          "Mcp-Method": "tools/call",
          "Mcp-Name": "saluer",
        },
      ),
      optionsBase({ exigerVersionMeta: true }),
    );
    expect(callOk.status).toBe(200);
    const callJson = (await callOk.json()) as {
      result: { content: Array<{ text: string }>; resultType: string };
    };
    expect(callJson.result.content[0]!.text).toBe("Bonjour Alice (v1)");
    expect(callJson.result.resultType).toBe("complete");

    const utf8Bytes = new TextEncoder().encode("résumer");
    const sentinelle = `=?base64?${btoa(String.fromCharCode(...utf8Bytes))}?=`;
    const callAccent = await servirRequeteMcp(
      post(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 4,
          method: "tools/call",
          params: {
            name: "résumer",
            arguments: {},
            _meta: { [CLEF_VERSION]: "2026-07-28" },
          },
        }),
        {
          "MCP-Protocol-Version": "2026-07-28",
          "Mcp-Method": "tools/call",
          "Mcp-Name": sentinelle,
        },
      ),
      optionsBase({ exigerVersionMeta: true }),
    );
    expect(callAccent.status).toBe(200);
    expect(
      ((await callAccent.json()) as { result: { content: Array<{ text: string }> } }).result
        .content[0]!.text,
    ).toBe("résumé prêt");
  });

  it("sert server/discover, initialize, tools/list, 404 et erreur interne sûre", async () => {
    const discover = await servirRequeteMcp(
      post(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "server/discover" }), {
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": "server/discover",
      }),
      optionsBase(),
    );
    const dJson = (await discover.json()) as {
      result: { supportedVersions: string[]; resultType: string; _meta: Record<string, unknown> };
    };
    expect(dJson.result.resultType).toBe("complete");
    expect(dJson.result._meta[CLEF_SERVEUR]).toEqual(SERVER_INFO);

    const init = await servirRequeteMcp(
      post(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 2,
          method: "initialize",
          params: { protocolVersion: "1999-01-01" },
        }),
      ),
      optionsBase(),
    );
    expect(
      ((await init.json()) as { result: { protocolVersion: string } }).result.protocolVersion,
    ).toBe("2025-11-25");

    const inconnu = await servirRequeteMcp(
      post(JSON.stringify({ jsonrpc: "2.0", id: 3, method: "inexistant" }), {
        "MCP-Protocol-Version": "2025-11-25",
      }),
      optionsBase(),
    );
    expect(inconnu.status).toBe(404);
    expect(((await inconnu.json()) as { error: { code: number } }).error.code).toBe(
      METHOD_NOT_FOUND,
    );

    const erreurs: string[] = [];
    const interne = await servirRequeteMcp(
      post(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 4,
          method: "tools/call",
          params: { name: "saluer", arguments: { qui: "x" } },
        }),
        { "MCP-Protocol-Version": "2025-11-25" },
      ),
      optionsBase({
        appeler: async () => {
          throw new Error("secret-interne");
        },
        surErreur: (m) => erreurs.push(m),
      }),
    );
    expect(interne.status).toBe(200);
    const intJson = (await interne.json()) as { error: { code: number; message: string } };
    expect(intJson.error.code).toBe(INTERNAL_ERROR);
    expect(intJson.error.message).not.toContain("secret-interne");
    expect(erreurs).toEqual(["tools/call"]);
  });
});
