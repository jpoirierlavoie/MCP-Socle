import { describe, expect, it } from "vitest";
import {
  methodeNonPermise,
  origineInterdite,
  refuser,
  tropDeRequetes,
} from "../src/identite/refus";
import {
  corsHeaders,
  debitAcceptable,
  drapeau,
  jsonResponse,
  ORIGINES_PAR_DEFAUT,
  origineAutorisee,
  origineRefusee,
  originesAdmises,
  preflight,
  reponseSante,
} from "../src/protocole/http";

const req = (h: Record<string, string> = {}) => new Request("https://x/mcp", { headers: h });
const ADMISES = originesAdmises();

describe("origines", () => {
  it("claude.ai, claude.com et les origines web Gemini sont admises par défaut", () => {
    expect([...ORIGINES_PAR_DEFAUT]).toEqual([
      "https://claude.ai",
      "https://claude.com",
      "https://gemini.google.com",
      "https://aistudio.google.com",
      "https://chatgpt.com",
      "https://chat.openai.com",
      "https://platform.openai.com",
    ]);
  });

  it("normalise les barres finales et déduplique les origines supplémentaires", () => {
    const a = originesAdmises("https://claude.ai/, https://exemple.test///, https://exemple.test/");
    expect(a).toEqual([...ORIGINES_PAR_DEFAUT, "https://exemple.test"]);
    const pathologique = `https://exemple.test/${"/".repeat(5_000)}`;
    expect(originesAdmises(pathologique)).toEqual([...ORIGINES_PAR_DEFAUT, "https://exemple.test"]);
  });

  it("la liste supplémentaire AJOUTE, elle ne remplace pas", () => {
    const a = originesAdmises("https://exemple.test , https://autre.test");
    expect(a).toContain("https://claude.ai");
    expect(a).toContain("https://exemple.test");
    expect(a).toContain("https://autre.test");
  });

  it("une liste vide ou pleine de blancs n'ajoute rien", () => {
    expect(originesAdmises("")).toEqual([...ORIGINES_PAR_DEFAUT]);
    expect(originesAdmises(" , , ")).toEqual([...ORIGINES_PAR_DEFAUT]);
  });

  it("une origine ABSENTE est admise — serveur à serveur", () => {
    expect(origineAutorisee(req(), ADMISES)).toBeNull();
    expect(origineRefusee(req(), ADMISES)).toBe(false);
  });

  it("une origine de navigateur INCONNUE est refusée — ré-attachement DNS", () => {
    const r = req({ Origin: "https://mechant.test" });
    expect(origineAutorisee(r, ADMISES)).toBeNull();
    expect(origineRefusee(r, ADMISES)).toBe(true);
  });

  it("une origine connue est reflétée", () => {
    expect(origineAutorisee(req({ Origin: "https://claude.ai" }), ADMISES)).toBe(
      "https://claude.ai",
    );
  });
});

describe("corsHeaders", () => {
  it("sans origine, aucun en-tête — une réponse serveur à serveur n'en porte pas", () => {
    expect(corsHeaders(null)).toEqual({});
  });

  it("porte TOUJOURS Vary: Origin", () => {
    expect(corsHeaders("https://claude.ai").Vary).toBe("Origin");
  });

  it("expose les en-têtes que le client doit pouvoir LIRE", () => {
    const h = corsHeaders("https://claude.ai")["Access-Control-Expose-Headers"];
    expect(h).toContain("WWW-Authenticate");
    expect(h).toContain("MCP-Protocol-Version");
    expect(h).toContain("Retry-After");
  });
});

describe("preflight", () => {
  it("rend 204 sans corps", async () => {
    const r = preflight("https://claude.ai");
    expect(r.status).toBe(204);
    expect(await r.text()).toBe("");
  });

  it("autorise les en-têtes que 2026-07-28 et les clients navigateur exigent", () => {
    const h = preflight("https://claude.ai").headers.get("Access-Control-Allow-Headers") ?? "";
    for (const attendu of [
      "Authorization",
      "MCP-Protocol-Version",
      "Mcp-Method",
      "Mcp-Name",
      "Mcp-Session-Id",
      "Last-Event-ID",
    ]) {
      expect(h).toContain(attendu);
    }
  });
});

describe("debitAcceptable", () => {
  it("sans liaison, laisse passer — ÉCHOUE OUVERT", () => {
    return expect(debitAcceptable(undefined, "k")).resolves.toBe(true);
  });

  it("une liaison qui LÈVE laisse passer aussi", async () => {
    const casse = {
      limit: () => {
        throw new Error("panne");
      },
    };
    expect(await debitAcceptable(casse, "k")).toBe(true);
  });

  it("respecte le verdict quand la liaison répond", async () => {
    expect(await debitAcceptable({ limit: async () => ({ success: false }) }, "k")).toBe(false);
    expect(await debitAcceptable({ limit: async () => ({ success: true }) }, "k")).toBe(true);
  });

  it("transmet la clé telle quelle", async () => {
    let vue = "";
    await debitAcceptable(
      {
        limit: async ({ key }) => {
          vue = key;
          return { success: true };
        },
      },
      "titulaire-42",
    );
    expect(vue).toBe("titulaire-42");
  });
});

describe("refus", () => {
  it("404 : corps VIDE, Cache-Control no-store et aucun en-tête annonçant un point d'entrée MCP", async () => {
    const r = refuser("404");
    expect(r.status).toBe(404);
    expect(await r.text()).toBe("");
    expect(r.headers.get("WWW-Authenticate")).toBeNull();
    expect(r.headers.get("Cache-Control")).toBe("no-store");
  });

  it("401 : porte WWW-Authenticate et Cache-Control no-store — la bascule derrière drapeau", () => {
    const r = refuser("401");
    expect(r.status).toBe(401);
    expect(r.headers.get("WWW-Authenticate")).toBe("Bearer");
    expect(r.headers.get("Cache-Control")).toBe("no-store");
  });

  it("les deux formes portent les en-têtes CORS, pour que le navigateur les LISE", () => {
    for (const forme of ["404", "401"] as const) {
      expect(refuser(forme, "https://claude.ai").headers.get("Access-Control-Allow-Origin")).toBe(
        "https://claude.ai",
      );
    }
  });

  it("origine interdite : 403 SANS en-tête CORS et avec Cache-Control no-store — sinon le refus est un oracle", () => {
    const r = origineInterdite();
    expect(r.status).toBe(403);
    expect(r.headers.get("Access-Control-Allow-Origin")).toBeNull();
    expect(r.headers.get("Cache-Control")).toBe("no-store");
  });

  it("429 porte Retry-After en secondes et Cache-Control no-store", () => {
    const r = tropDeRequetes(300);
    expect(r.headers.get("Retry-After")).toBe("300");
    expect(r.headers.get("Cache-Control")).toBe("no-store");
  });

  it("405 annonce Allow et Cache-Control no-store, et ne se sert qu'APRÈS l'identité", () => {
    const r = methodeNonPermise();
    expect(r.headers.get("Allow")).toBe("POST, OPTIONS");
    expect(r.headers.get("Cache-Control")).toBe("no-store");
  });
});

describe("jsonResponse", () => {
  it("sérialise, pose le type, Cache-Control no-store et la charge", async () => {
    const r = jsonResponse({ a: 1 }, 200);
    expect(r.headers.get("Content-Type")).toContain("application/json");
    expect(r.headers.get("Cache-Control")).toBe("no-store");
    expect(await r.json()).toEqual({ a: 1 });
  });
});

describe("drapeau et reponseSante", () => {
  it("lit les drapeaux d'environnement avec valeur par défaut explicite", () => {
    expect(drapeau(undefined, true)).toBe(true);
    expect(drapeau(undefined, false)).toBe(false);
    expect(drapeau("", true)).toBe(true);
    expect(drapeau(" FALSE ", true)).toBe(false);
    expect(drapeau("0", true)).toBe(true);
    expect(drapeau("true", false)).toBe(true);
    expect(drapeau("1", false)).toBe(false);
    expect(drapeau("quelconque", true)).toBe(true);
    expect(drapeau("quelconque", false)).toBe(false);
  });

  it("reponseSante renvoie 200 JSON si actif et 404 sinon, toujours avec Cache-Control no-store", async () => {
    const ok = reponseSante({ actif: true, commit: "abc1234" });
    expect(ok.status).toBe(200);
    expect(ok.headers.get("Cache-Control")).toBe("no-store");
    expect(await ok.json()).toEqual({ status: "ok", commit: "abc1234" });

    const defaut = reponseSante();
    expect(defaut.headers.get("Cache-Control")).toBe("no-store");
    expect(await defaut.json()).toEqual({ status: "ok", commit: "inconnu" });

    const coupe = reponseSante({ actif: false, commit: "abc1234" });
    expect(coupe.status).toBe(404);
    expect(coupe.headers.get("Cache-Control")).toBe("no-store");
    expect(await coupe.text()).toBe("Not found");
  });
});
