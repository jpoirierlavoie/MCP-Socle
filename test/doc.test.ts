import { describe, expect, it } from "vitest";
import claudeMd from "../CLAUDE.md?raw";
import geminiMd from "../GEMINI.md?raw";
import pkgRaw from "../package.json?raw";
import readmeMd from "../README.md?raw";
import securityMd from "../SECURITY.md?raw";
import indexTs from "../src/index.ts?raw";

const RACINE_MD = import.meta.glob<string>("../*.md", {
  query: "?raw",
  import: "default",
  eager: true,
});

const ARCHIVE_MD = import.meta.glob<string>("../docs/archive/*.md", {
  query: "?raw",
  import: "default",
  eager: true,
});

const SOURCES_TS = import.meta.glob<string>("../src/**/*.ts", {
  query: "?raw",
  import: "default",
  eager: true,
});

function sansCommentaires(code: string): string {
  return code.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|\s)\/\/.*$/gm, "$1");
}

describe("hygiène documentaire et manifeste", () => {
  it("package.json déclare la version 0.6.2 et zéro dépendance d'exécution", () => {
    const pkg = JSON.parse(pkgRaw) as {
      version: string;
      dependencies?: Record<string, string>;
      scripts?: Record<string, string>;
    };
    expect(pkg.version).toBe("0.6.2");
    expect(Object.keys(pkg.dependencies ?? {})).toEqual([]);
    expect(pkg.scripts?.["type-check"]).toBe("tsc --noEmit");
    expect(pkg.scripts?.lint).toBe("biome check .");
    expect(pkg.scripts?.test).toBe("vitest run");
  });

  it("GEMINI.md respecte le plafond de 24 000 octets UTF-8", () => {
    const taille = new TextEncoder().encode(geminiMd).byteLength;
    expect(taille).toBeGreaterThan(200);
    expect(taille).toBeLessThan(24_000);
    expect(geminiMd).toContain("# MCP-Socle-Juridique");
  });

  it("la documentation active ne porte plus les anciens noms de dépôts ni d'étiquette périmée", () => {
    for (const doc of [readmeMd, claudeMd, geminiMd, securityMd]) {
      expect(doc.length).toBeGreaterThan(100);
      expect(doc).not.toContain("MCP-Jurisprudence-Quebec");
      expect(doc).not.toContain("MCP-Legislation-Quebec");
    }
    expect(readmeMd).toContain("#v0.6.2");
    expect(claudeMd).toContain("#v0.6.2");
    expect(readmeMd).not.toContain("#v0.1.0");
    expect(readmeMd).not.toContain("#v0.6.1");
    expect(claudeMd).not.toContain("#v0.5.0");
    expect(claudeMd).not.toContain("#v0.6.1");
  });

  it("les documents datés sont archivés sous docs/archive/ et absents de la racine", () => {
    const nomsRacine = Object.keys(RACINE_MD).map((p) => p.split("/").pop());
    for (const archive of [
      "FEUILLE-DE-ROUTE.md",
      "PROCEDURES-MANUELLES.md",
      "NOTE-OUVERTURE-PUBLIQUE.md",
    ]) {
      expect(nomsRacine).not.toContain(archive);
      const chemin = `../docs/archive/${archive}`;
      expect(ARCHIVE_MD[chemin]).toBeDefined();
      expect(ARCHIVE_MD[chemin]).toContain("Document d'archive");
    }
  });
});

describe("frontière de domaine et exports du socle", () => {
  const MOTS_DOMAINE =
    /\b(canlii|mjq|rlrq|cqlr|greffe|palais|tribunal|juridique|legislation_|jurisprudence_)\b/i;
  const IMPORT_SPECIFIERS = /(?:from|import)\s+["']([^"']+)["']/g;

  it("aucun module de src/ n'importe de dépendance externe ni de vocabulaire juridique", () => {
    for (const [chemin, contenu] of Object.entries(SOURCES_TS)) {
      const nu = sansCommentaires(contenu);
      expect(nu, chemin).not.toMatch(MOTS_DOMAINE);
      for (const m of nu.matchAll(IMPORT_SPECIFIERS)) {
        const cible = m[1]!;
        expect(cible.startsWith("./") || cible.startsWith("../"), `${chemin} -> ${cible}`).toBe(
          true,
        );
      }
    }
  });

  it("src/index.ts réexporte chaque module sous identite/ et protocole/", () => {
    for (const chemin of Object.keys(SOURCES_TS)) {
      const m = /^\.\.\/src\/((?:identite|protocole)\/[^/]+)\.ts$/.exec(chemin);
      if (!m) continue;
      expect(indexTs).toContain(`./${m[1]}`);
    }
  });
});
