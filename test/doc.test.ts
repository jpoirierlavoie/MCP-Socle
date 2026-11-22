import { describe, expect, it } from "vitest";
import claudeMd from "../CLAUDE.md?raw";
import geminiMd from "../GEMINI.md?raw";
import licenseRaw from "../LICENSE?raw";
import noticeRaw from "../NOTICE?raw";
import osvTomlRaw from "../osv-scanner.toml?raw";
import pkgRaw from "../package.json?raw";
import readmeMd from "../README.md?raw";
import securityMd from "../SECURITY.md?raw";
import specMd from "../SPEC-SOCLE-COMMUN.md?raw";
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
  it("package.json déclare le nom @poirierlavoie/mcp-socle, la version 0.8.3 et zéro dépendance d'exécution", () => {
    const pkg = JSON.parse(pkgRaw) as {
      name: string;
      version: string;
      license: string;
      dependencies?: Record<string, string>;
      scripts?: Record<string, string>;
    };
    expect(pkg.name).toBe("@poirierlavoie/mcp-socle");
    expect(pkg.version).toBe("0.8.3");
    expect(pkg.license).toBe("Apache-2.0");
    expect(Object.keys(pkg.dependencies ?? {})).toEqual([]);
    expect(pkg.scripts?.["type-check"]).toBe("tsc --noEmit");
    expect(pkg.scripts?.lint).toBe("biome check .");
    expect(pkg.scripts?.test).toBe("vitest run");
    expect(pkg.scripts?.audit).toBe("node scripts/verifier-audit.mjs");

    const blocsOsv = osvTomlRaw.split(/\[\[\s*IgnoredVulns\s*\]\]/g).slice(1);
    for (const bloc of blocsOsv) {
      const mId = /(?:^|\n)\s*id\s*=\s*"([^"]+)"/.exec(bloc);
      const mReason = /(?:^|\n)\s*reason\s*=\s*"([^"]+)"/.exec(bloc);
      expect(mId?.[1]).toMatch(/^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/);
      expect(mReason?.[1]).toMatch(/^\d{4}-\d{2}-\d{2}\s*:\s*.{20,}/);
    }
  });

  it("CLAUDE.md et GEMINI.md sont identiques octet pour octet et sous le plafond de 24 000 octets UTF-8", () => {
    expect(claudeMd).toBe(geminiMd);
    const taille = new TextEncoder().encode(geminiMd).byteLength;
    expect(taille).toBeGreaterThan(1_000);
    expect(taille).toBeLessThan(24_000);
    expect(geminiMd).toContain("# MCP-Socle");
    expect(geminiMd).not.toContain("# MCP-Socle-Juridique");
  });

  it("LICENSE conserve Apache-2.0 et NOTICE porte les mentions d'attribution et de non-revendication", () => {
    expect(licenseRaw).toContain("Apache License");
    expect(licenseRaw).toContain("Version 2.0, January 2004");
    expect(noticeRaw).toContain("Apache-2.0");
    expect(noticeRaw.startsWith("\uFEFF")).toBe(false);
    expect(noticeRaw.includes("\r")).toBe(false);
  });

  it("la documentation active ne porte plus les anciens noms de dépôts ni d'étiquette périmée", () => {
    for (const doc of [readmeMd, claudeMd, geminiMd, securityMd, specMd]) {
      expect(doc.length).toBeGreaterThan(100);
      expect(doc).not.toContain("MCP-Jurisprudence-Quebec");
      expect(doc).not.toContain("MCP-Legislation-Quebec");
      expect(doc).not.toContain("MCP-Socle-Juridique");
      expect(doc).not.toContain("socle-juridique");
      expect(doc).not.toContain("pratique-civile-outils");
    }
    expect(readmeMd).toContain("#v0.8.3");
    expect(claudeMd).toContain("#v0.8.3");
    expect(securityMd).toContain("#v0.8.3");
    expect(readmeMd).not.toContain("#v0.1.0");
    expect(readmeMd).not.toContain("#v0.6.1");
    expect(readmeMd).not.toContain("#v0.6.2");
    expect(readmeMd).not.toContain("#v0.7.0");
    expect(readmeMd).not.toContain("#v0.8.0");
    expect(readmeMd).not.toContain("#v0.8.1");
    expect(readmeMd).not.toContain("#v0.8.2");
    expect(claudeMd).not.toContain("#v0.5.0");
    expect(claudeMd).not.toContain("#v0.6.1");
    expect(claudeMd).not.toContain("#v0.6.2");
    expect(claudeMd).not.toContain("#v0.7.0");
    expect(claudeMd).not.toContain("#v0.8.0");
    expect(claudeMd).not.toContain("#v0.8.1");
    expect(claudeMd).not.toContain("#v0.8.2");
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

describe("frontière de domaine, gardes cryptographiques et exports du socle", () => {
  const MOTS_DOMAINE =
    /\b(article|articles|loi|lois|decision|decisions|avocat|avocats|canlii|mjq|rlrq|cqlr|greffe|palais|tribunal|juridique|barreau|legislation_|jurisprudence_|legislation|jurisprudence)\b/i;
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

  it("G33 : aucun Math.random dans src/, et getRandomValues est borné à porteur.ts et coffre.ts", () => {
    const autorisesGetRandomValues = new Set([
      "../src/identite/porteur.ts",
      "../src/identite/coffre.ts",
    ]);
    for (const [chemin, contenu] of Object.entries(SOURCES_TS)) {
      const nu = sansCommentaires(contenu);
      expect(nu, `${chemin} ne doit jamais appeler Math.random`).not.toMatch(/\bMath\.random\b/);
      if (!autorisesGetRandomValues.has(chemin)) {
        expect(nu, `${chemin} ne doit pas appeler getRandomValues`).not.toMatch(
          /\bgetRandomValues\b/,
        );
      }
    }
    expect(SOURCES_TS["../src/identite/porteur.ts"]).toContain("crypto.getRandomValues");
    expect(SOURCES_TS["../src/identite/coffre.ts"]).toContain("crypto.getRandomValues");
  });

  it("G10 & G9 : aucune fonction exportée nommée clef/key/secret ne rend string, et aucun console.* dans src/", () => {
    const signatureSensibleRendantString =
      /export\s+(?:async\s+)?function\s+[A-Za-z0-9_]*(?:clef|key|secret)[A-Za-z0-9_]*\s*(?:<[^>]*>)?\s*\([^)]*\)\s*:\s*(?:Promise<\s*string(?!\s*\[)(?:\s*\|\s*null)?\s*>|string(?!\s*\[)(?:\s*\|\s*null)?)/i;

    for (const [chemin, contenu] of Object.entries(SOURCES_TS)) {
      const nu = sansCommentaires(contenu);
      expect(nu, `${chemin} viole G10`).not.toMatch(signatureSensibleRendantString);
      expect(nu, `${chemin} ne doit pas exporter dechiffrer*`).not.toMatch(
        /\bexport\s+(?:async\s+)?function\s+dechiffrer/i,
      );
      expect(nu, `${chemin} ne doit pas journaliser via console.*`).not.toMatch(/\bconsole\./);
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
