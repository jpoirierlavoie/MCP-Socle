import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { scellerCoffre } from "../src/identite/coffre";
import * as moduleGouverne from "../src/identite/gouverne";
import {
  construireSchemaIdentiteD1,
  creerQuarantaineIpEchecs,
  ecrireEvenementTechniqueD1,
  enregistrerEchecAuth,
  erreurQuotaEpuise,
  formaterEvenementTechnique,
  incrementerCompteurJourD1,
  jourUtc,
  lireCompteursJourD1,
  minuteUtc,
  POLITIQUES_RETENTION_IDENTITE,
  purgerEvenementsTechniquesD1,
  purgerRetentionsD1,
  QUOTAS_ACTIF_PAR_DEFAUT,
  QUOTAS_LIMITE_PAR_DEFAUT,
  resoudreModeAdmission,
  retirerEntreeCoffreD1,
  SQL_SCHEMA_IDENTITE_D1,
  supprimerCompteTitulaireD1,
  verifierCouvertureRetentionSchema,
  verifierDebitPreAuth,
  verifierDebitTitulaire,
  verifierQuotaJour,
  verifierSchemaSansContenuIdentifiant,
} from "../src/identite/gouverne";
import { empreinte, frapperJeton, type Porte, porteursPresentes } from "../src/identite/porteur";
import { type BaseD1Minimale, ouvrirPrincipal } from "../src/identite/titulaire";
import type { Limiteur } from "../src/protocole/http";

async function reinitialiserSchemaD1(
  db: D1Database,
  services: readonly string[] = ["service_a", "service_b"],
): Promise<void> {
  const ordreInverseSuppression = [
    "registre_gouverne",
    "evenement_technique",
    "compteur_jour",
    "code_oauth",
    "client_oauth",
    "session_portail",
    "coffre_clef",
    "jeton",
    "demande_acces",
    "invitation_acces",
    "titulaire",
  ];
  await db.batch(ordreInverseSuppression.map((nom) => db.prepare(`DROP TABLE IF EXISTS "${nom}"`)));
  const instructions = construireSchemaIdentiteD1(services)
    .split(";")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  await db.batch([
    db.prepare("PRAGMA foreign_keys = ON"),
    ...instructions.map((sql) => db.prepare(sql)),
  ]);
}

function creerLimiteurFenetre(plafond: number): Limiteur & { compteur(cle: string): number } {
  const comptes = new Map<string, number>();
  return {
    async limit({ key }) {
      const prochain = (comptes.get(key) ?? 0) + 1;
      comptes.set(key, prochain);
      return { success: prochain <= plafond };
    },
    compteur(cle: string) {
      return comptes.get(cle) ?? 0;
    },
  };
}

describe("G32 & S15 — Débit d'arête : blocage brute-force vs rafales Deep Research sur IP partagée", () => {
  it("bloque 1 000 jetons distincts invalides avant D1 dès 20 échecs, sans jamais pénaliser 250 appels Deep Research valides sur une IP cloud partagée", async () => {
    const quarantaine = creerQuarantaineIpEchecs({ maxEntrees: 128, dureeMs: 60_000 });
    const rlRafaleIp = creerLimiteurFenetre(600);
    const rlEchecIp = creerLimiteurFenetre(20);
    const rlEchecsGlobal = creerLimiteurFenetre(300);
    const rlTitulaire = creerLimiteurFenetre(180);

    const ipAttaquant = "198.51.100.77";
    let lecturesD1Attaquant = 0;
    for (let i = 0; i < 1_000; i++) {
      const _jetonDistinct = frapperJeton();
      const passePreAuth = await verifierDebitPreAuth({
        ip: ipAttaquant,
        quarantaine,
        limiteurRafaleIp: rlRafaleIp,
        maintenantMs: 1_000,
      });
      if (!passePreAuth) continue;

      lecturesD1Attaquant++;
      await enregistrerEchecAuth({
        ip: ipAttaquant,
        quarantaine,
        limiteurEchecIp: rlEchecIp,
        limiteurEchecsGlobal: rlEchecsGlobal,
        maintenantMs: 1_000,
      });
    }

    expect(lecturesD1Attaquant).toBe(21);
    expect(quarantaine.estEnQuarantaine(ipAttaquant, 1_500)).toBe(true);
    expect(quarantaine.estEnQuarantaine(ipAttaquant, 62_000)).toBe(false);

    const ipCloudPartagee = "203.0.113.10";
    let succesDeepResearch = 0;
    for (let t = 1; t <= 5; t++) {
      const titulaireId = `tit_confrere_${t}`;
      for (let r = 0; r < 50; r++) {
        const okPre = await verifierDebitPreAuth({
          ip: ipCloudPartagee,
          quarantaine,
          limiteurRafaleIp: rlRafaleIp,
          maintenantMs: 2_000,
        });
        expect(okPre).toBe(true);
        const refusTitulaire = await verifierDebitTitulaire({
          titulaireId,
          etat: "actif",
          limiteurActif: rlTitulaire,
        });
        expect(refusTitulaire).toBeNull();
        succesDeepResearch++;
      }
    }
    expect(succesDeepResearch).toBe(250);
    expect(quarantaine.estEnQuarantaine(ipCloudPartagee, 2_000)).toBe(false);
    expect(rlEchecIp.compteur(ipCloudPartagee)).toBe(0);

    const jetonConfrereActif = frapperJeton();
    quarantaine.marquerEmpreinteValide(await empreinte(jetonConfrereActif), 3_000);
    quarantaine.placerEnQuarantaine(ipCloudPartagee, 3_000);

    expect(
      await verifierDebitPreAuth({
        ip: ipCloudPartagee,
        quarantaine,
        limiteurRafaleIp: rlRafaleIp,
        candidatsJetons: [jetonConfrereActif],
        maintenantMs: 3_500,
      }),
    ).toBe(true);

    expect(
      await verifierDebitPreAuth({
        ip: ipCloudPartagee,
        quarantaine,
        limiteurRafaleIp: rlRafaleIp,
        candidatsJetons: [frapperJeton()],
        maintenantMs: 3_500,
      }),
    ).toBe(false);

    const secretHex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const porteDual: Porte = {
      mount: "/mcp",
      queryKey: "key",
      nomsSecrets: ["MCP_TOKEN_TRANSITOIRE"],
      segmentBorne: true,
    };
    const urlDual = new URL(`https://exemple.test/mcp/${secretHex64}/`);
    const reqDual = new Request(urlDual.toString(), { method: "POST" });
    const ouvertDual = await ouvrirPrincipal(
      reqDual,
      urlDual,
      { MCP_TOKEN_TRANSITOIRE: secretHex64 },
      porteDual,
      {
        surEmpreinteValide: (h) => quarantaine.marquerEmpreinteValide(h, 3_600),
      },
    );
    expect(ouvertDual?.principal).toEqual({ type: "secret_partage" });

    expect(
      await verifierDebitPreAuth({
        ip: ipCloudPartagee,
        quarantaine,
        limiteurRafaleIp: creerLimiteurFenetre(0),
        candidatsJetons: porteursPresentes(reqDual, urlDual, porteDual),
        maintenantMs: 3_700,
      }),
    ).toBe(true);

    const secretHexInconnu = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    expect(
      await verifierDebitPreAuth({
        ip: ipCloudPartagee,
        quarantaine,
        limiteurRafaleIp: rlRafaleIp,
        candidatsJetons: [secretHexInconnu],
        maintenantMs: 3_700,
      }),
    ).toBe(false);

    await enregistrerEchecAuth({
      ip: ipCloudPartagee,
      quarantaine,
      limiteurEchecIp: rlEchecIp,
      limiteurEchecsGlobal: rlEchecsGlobal,
      candidatsJetons: [jetonConfrereActif],
      maintenantMs: 3_800,
    });
    expect(
      await verifierDebitPreAuth({
        ip: ipCloudPartagee,
        quarantaine,
        limiteurRafaleIp: rlRafaleIp,
        candidatsJetons: [jetonConfrereActif],
        maintenantMs: 3_850,
      }),
    ).toBe(false);
  });

  it("borne la mémoire de la quarantaine IP par éviction FIFO et applique Retry-After selon l'état", async () => {
    const q = creerQuarantaineIpEchecs({ maxEntrees: 2, dureeMs: 10_000 });
    q.placerEnQuarantaine("192.0.2.1", 0);
    q.placerEnQuarantaine("192.0.2.2", 0);
    q.placerEnQuarantaine("192.0.2.3", 0);
    expect(q.taille()).toBe(2);
    expect(q.estEnQuarantaine("192.0.2.1", 100)).toBe(false);
    expect(q.estEnQuarantaine("192.0.2.2", 100)).toBe(true);
    expect(q.estEnQuarantaine("192.0.2.3", 100)).toBe(true);

    const sature = creerLimiteurFenetre(0);
    const repActif = await verifierDebitTitulaire({
      titulaireId: "tit_1",
      etat: "actif",
      limiteurActif: sature,
      origin: "https://claude.ai",
    });
    expect(repActif?.status).toBe(429);
    expect(repActif?.headers.get("Retry-After")).toBe("60");
    expect(repActif?.headers.get("Access-Control-Allow-Origin")).toBe("https://claude.ai");

    const repLimite = await verifierDebitTitulaire({
      titulaireId: "tit_2",
      etat: "limite",
      limiteurLimite: sature,
    });
    expect(repLimite?.status).toBe(429);
    expect(repLimite?.headers.get("Retry-After")).toBe("300");
  });
});

describe("Quotas journaliers par classe d'outil", () => {
  it("autorise sous le plafond et rend QUOTA_EPUISE (HTTP 200 isError: true) dès le plafond atteint", () => {
    expect(QUOTAS_ACTIF_PAR_DEFAUT).toEqual({ local: 1_500, sortant: 200, semantique: 150 });
    expect(QUOTAS_LIMITE_PAR_DEFAUT).toEqual({ local: 150, sortant: 20, semantique: 15 });

    const ok = verifierQuotaJour({ sortant: 199 }, "sortant", "actif");
    expect(ok).toEqual({
      autorise: true,
      classe: "sortant",
      utilise: 199,
      plafond: 200,
      restant: 1,
    });

    const bloque = verifierQuotaJour({ sortant: 200 }, "sortant", "actif");
    expect(bloque).toEqual({
      autorise: false,
      code: "QUOTA_EPUISE",
      classe: "sortant",
      utilise: 200,
      plafond: 200,
    });

    const bloqueLimite = verifierQuotaJour({ semantique: 15 }, "semantique", "limite");
    expect(bloqueLimite.autorise).toBe(false);

    const outilErr = erreurQuotaEpuise("sortant", 200);
    expect(outilErr.isError).toBe(true);
    expect(outilErr.content[0]?.text).toContain("[QUOTA_EPUISE]");
  });
});

describe("Télémétrie technique sans contenu et purge à 90 jours (S13, G16)", () => {
  it("tronque systématiquement l'horodatage à la minute UTC et nettoie clientInfo", () => {
    const date = new Date("2026-11-18T23:59:58.999Z");
    expect(jourUtc(date)).toBe("2026-11-18");
    expect(minuteUtc(date)).toBe("2026-11-18T23:59");

    const ev = formaterEvenementTechnique({
      titulaireId: "tit_01",
      jetonId: "jet_01",
      service: "service_a",
      horodatage: date,
      outil: "rechercher_texte",
      classe: "semantique",
      issue: "quota",
      code: "QUOTA_EPUISE",
      ms: 42.7,
      sortants: 0,
      clientInfo: { name: "claude-ai\r\nmalicieux", version: "1.2.0" },
    });

    expect(ev).toEqual({
      titulaire_id: "tit_01",
      jeton_id: "jet_01",
      service: "service_a",
      minute: "2026-11-18T23:59",
      outil: "rechercher_texte",
      classe: "semantique",
      issue: "quota",
      code: "QUOTA_EPUISE",
      ms: 43,
      sortants: 0,
      client: "claude-aimalicieux/1.2.0",
    });

    expect(() =>
      formaterEvenementTechnique({
        titulaireId: "tit_01",
        jetonId: "jet_01",
        service: "service_a",
        outil: "outil avec requête libre",
        classe: "local",
        issue: "ok",
      }),
    ).toThrow();
  });

  it("utilise ON CONFLICT DO UPDATE (jamais REPLACE) et purge exactement au seuil de 90 jours (G16)", async () => {
    const requetes: Array<{ sql: string; args: unknown[] }> = [];
    const fausseD1: BaseD1Minimale = {
      prepare(sql: string) {
        return {
          bind(...args: unknown[]) {
            requetes.push({ sql, args });
            return {
              async first<T>() {
                return null as T | null;
              },
              async all<T>() {
                return {
                  results: [
                    { classe: "local", appels: 12 },
                    { classe: "sortant", appels: 3 },
                  ] as unknown as T[],
                };
              },
              async run() {
                return {};
              },
            };
          },
        };
      },
    };

    const lu = await lireCompteursJourD1(fausseD1, "tit_1", "2026-11-18");
    expect(lu).toEqual({ local: 12, sortant: 3, semantique: 0 });

    await incrementerCompteurJourD1(fausseD1, {
      titulaireId: "tit_1",
      jour: "2026-11-18",
      classe: "sortant",
      estErreur: false,
      estIntrouvable: true,
      sortants: 2,
    });
    expect(requetes[1]!.sql).toContain("ON CONFLICT(titulaire_id, jour, classe) DO UPDATE");
    expect(requetes[1]!.sql.toUpperCase()).not.toContain("REPLACE");

    const ev = formaterEvenementTechnique({
      titulaireId: "tit_1",
      jetonId: "jet_1",
      service: "service_a",
      horodatage: new Date("2026-11-18T12:00:00Z"),
      outil: "outil_x",
      classe: "local",
      issue: "ok",
    });
    await ecrireEvenementTechniqueD1(fausseD1, ev);

    const seuil = await purgerEvenementsTechniquesD1(
      fausseD1,
      new Date("2026-11-18T12:00:00Z"),
      90,
    );
    expect(seuil).toBe("2026-08-20T12:00");
    expect(requetes[3]!.args).toEqual(["2026-08-20T12:00"]);
  });
});

describe("G13, G18, G25 & modes d'admission — Garde statique du schéma SQL et de la rétention", () => {
  it("valide le schéma canonique SQL_SCHEMA_IDENTITE_D1, la couverture G18 et resoudreModeAdmission fermé par défaut", () => {
    expect(verifierSchemaSansContenuIdentifiant(SQL_SCHEMA_IDENTITE_D1)).toEqual([]);
    expect(verifierCouvertureRetentionSchema(SQL_SCHEMA_IDENTITE_D1)).toEqual([]);
    const schemaPersonnalise = construireSchemaIdentiteD1(["connecteur_un", "connecteur_deux"]);
    expect(verifierSchemaSansContenuIdentifiant(schemaPersonnalise)).toEqual([]);
    expect(verifierCouvertureRetentionSchema(schemaPersonnalise)).toEqual([]);
    expect(() => construireSchemaIdentiteD1(["MAUVAIS NOM!"])).toThrow();

    const sqlTableSansRetention = `${SQL_SCHEMA_IDENTITE_D1}\nCREATE TABLE table_oubliee (id TEXT PRIMARY KEY);`;
    expect(
      verifierCouvertureRetentionSchema(sqlTableSansRetention).some((a) =>
        a.includes("table_oubliee"),
      ),
    ).toBe(true);
    expect(
      verifierCouvertureRetentionSchema(SQL_SCHEMA_IDENTITE_D1, [
        ...POLITIQUES_RETENTION_IDENTITE,
        {
          table: "table_fantome",
          mode: "purge_automatique",
          conservationMax: "1 jour",
          purgeCode: "purgerFantome",
        },
      ]).some((a) => a.includes("table_fantome")),
    ).toBe(true);

    expect(resoudreModeAdmission("invitation")).toBe("invitation");
    expect(resoudreModeAdmission(" OUVERT ")).toBe("ouvert");
    expect(resoudreModeAdmission("ferme")).toBe("ferme");
    expect(resoudreModeAdmission(undefined)).toBe("ferme");
    expect(resoudreModeAdmission("")).toBe("ferme");
    expect(resoudreModeAdmission("inconnu")).toBe("ferme");
    expect(resoudreModeAdmission(42)).toBe("ferme");

    const exportsGouverne = moduleGouverne as Record<string, unknown>;
    for (const pol of POLITIQUES_RETENTION_IDENTITE) {
      if (pol.mode !== "configuration_service") {
        expect(typeof exportsGouverne[pol.purgeCode], `${pol.table} -> ${pol.purgeCode}`).toBe(
          "function",
        );
      }
    }
  });

  it("rejette search_log, forme_requete, toute jointure identité + texte libre (G13) et tout contenu horodaté sous le jour (G25)", () => {
    const avecSearchLog = `
      CREATE TABLE search_log (
        id INTEGER PRIMARY KEY,
        ts TEXT NOT NULL,
        query TEXT NOT NULL
      );
    `;
    const vSearch = verifierSchemaSansContenuIdentifiant(avecSearchLog);
    expect(vSearch.some((v) => v.includes("search_log"))).toBe(true);
    expect(vSearch.some((v) => v.includes("G25"))).toBe(true);

    const avecFormeRequete = `
      CREATE TABLE forme_requete (
        id INTEGER PRIMARY KEY,
        jour TEXT NOT NULL,
        forme TEXT NOT NULL
      );
    `;
    expect(
      verifierSchemaSansContenuIdentifiant(avecFormeRequete).some((v) =>
        v.includes("forme_requete"),
      ),
    ).toBe(true);

    const violationG13Explicite = `
      CREATE TABLE trace_fautive (
        id INTEGER PRIMARY KEY,
        titulaire_id TEXT NOT NULL,
        query TEXT NOT NULL
      );
    `;
    expect(
      verifierSchemaSansContenuIdentifiant(violationG13Explicite).some((v) => v.includes("G13")),
    ).toBe(true);

    const violationG13TexteNonContraint = `
      CREATE TABLE evenement_technique (
        id INTEGER PRIMARY KEY,
        titulaire_id TEXT NOT NULL,
        detail_libre TEXT
      );
    `;
    expect(
      verifierSchemaSansContenuIdentifiant(violationG13TexteNonContraint).some((v) =>
        v.includes("G13"),
      ),
    ).toBe(true);

    const contournementSyntaxe = `
      CREATE TABLE "trace_strict" (
        titulaire_id TEXT NOT NULL,
        etat TEXT CHECK (etat IN ('a', 'b')),
        commentaire_libre TEXT
      ) STRICT, WITHOUT ROWID
    `;
    expect(
      verifierSchemaSansContenuIdentifiant(contournementSyntaxe).some((v) => v.includes("G13")),
    ).toBe(true);

    const requetesAuJour = `
      CREATE TABLE requetes_jour (
        id INTEGER PRIMARY KEY,
        jour TEXT NOT NULL,
        query TEXT NOT NULL
      );
    `;
    expect(
      verifierSchemaSansContenuIdentifiant(requetesAuJour).some((v) => v.includes("S13/G13")),
    ).toBe(true);

    const parentheseDansLitteral = `
      CREATE TABLE evenement_technique (
        id INTEGER PRIMARY KEY,
        astuce TEXT CHECK (astuce IN ('ok)', 'ko(')),
        titulaire_id TEXT NOT NULL,
        query TEXT NOT NULL
      );
    `;
    expect(
      verifierSchemaSansContenuIdentifiant(parentheseDansLitteral).some((v) => v.includes("query")),
    ).toBe(true);

    const colonneNonTypee = `
      CREATE TABLE evenement_technique (
        id INTEGER PRIMARY KEY,
        titulaire_id TEXT NOT NULL,
        champ_non_type NOT NULL
      );
    `;
    expect(
      verifierSchemaSansContenuIdentifiant(colonneNonTypee).some((v) => v.includes("G13")),
    ).toBe(true);

    for (const contournementG13 of [
      `CREATE TABLE evenement_technique (id INTEGER PRIMARY KEY, titulaire_id TEXT NOT NULL, detail_libre TEXT CHECK (detail_libre NOT IN ('')));`,
      `CREATE TABLE evenement_technique (id INTEGER PRIMARY KEY, titulaire_id TEXT NOT NULL, detail_libre TEXT CHECK (1 IN (1) OR length(detail_libre) > 0));`,
      `CREATE TABLE evenement_technique (id INTEGER PRIMARY KEY, titulaire_id TEXT NOT NULL, charge_utile JSON NOT NULL);`,
      `CREATE TABLE evenement_technique (id INTEGER PRIMARY KEY, titulaire_id TEXT NOT NULL, charge_utile STRING NOT NULL);`,
      `CREATE TABLE evenement_technique (id INTEGER PRIMARY KEY, titulaire_id TEXT NOT NULL, charge_utile BLOB NOT NULL);`,
    ]) {
      expect(
        verifierSchemaSansContenuIdentifiant(contournementG13).some((v) => v.includes("G13")),
        contournementG13,
      ).toBe(true);
    }

    const tableAnonymeCreatedAt = `
      CREATE TABLE trace_anonyme (
        id INTEGER PRIMARY KEY,
        created_at TEXT NOT NULL,
        resume_libre TEXT NOT NULL
      );
    `;
    expect(
      verifierSchemaSansContenuIdentifiant(tableAnonymeCreatedAt).some((v) => v.includes("G25")),
    ).toBe(true);
  });

  it("exécute le schéma canonique complet, les contraintes CHECK/FK, ON CONFLICT DO UPDATE et la purge 90j sur une VRAIE base D1 (workerd)", async () => {
    const db = env.DB_IDENTITE_TEST;
    await reinitialiserSchemaD1(db, ["service_a", "service_b"]);

    await db
      .prepare(
        `INSERT INTO titulaire (
          id, cree_le, etat, nom, numero_membre, section, courriel, attestation_le, attestation_ver, cgu_ver
        ) VALUES ('tit_d1', '2026-11-18T00:00:00Z', 'actif', 'Test D1', '111111-1', 'Quebec', 'd1@exemple.org', '2026-11-18T00:00:00Z', 'v1', 'v1')`,
      )
      .run();

    await expect(
      db
        .prepare(
          `INSERT INTO code_oauth (
            id, titulaire_id, empreinte_code, client_id, redirect_uri, portee, defi_pkce, methode_pkce, cree_le, expire_le
          ) VALUES ('c1', 'tit_d1', 'h1', 'cl1', 'https://claude.ai/api/mcp/auth_callback', 'les_deux', 'defi', 'plain', '2026-11-18T00:00:00.000Z', '2026-11-18T00:05:00.000Z')`,
        )
        .run(),
    ).rejects.toThrow();

    await expect(
      db
        .prepare(
          `INSERT INTO code_oauth (
            id, titulaire_id, empreinte_code, client_id, redirect_uri, portee, defi_pkce, methode_pkce, cree_le, expire_le
          ) VALUES ('c_sans_ms', 'tit_d1', 'h_sans_ms', 'cl1', 'https://claude.ai/api/mcp/auth_callback', 'les_deux', 'defi', 'S256', '2026-11-18T00:00:00.000Z', '2026-11-18T00:05:00Z')`,
        )
        .run(),
    ).rejects.toThrow();

    await expect(
      db
        .prepare(
          `INSERT INTO session_portail (id, titulaire_id, courriel, type_lien, empreinte, cree_le, expire_le)
           VALUES ('sp_espace_sqlite', 'tit_d1', 'd1@exemple.org', 'connexion_moi', 'h_sp_bad', '2026-11-18T00:00:00.000Z', '2026-11-18 23:59:59')`,
        )
        .run(),
    ).rejects.toThrow();

    await expect(
      db
        .prepare(
          `INSERT INTO evenement_technique (titulaire_id, jeton_id, service, minute, outil, classe, issue)
           VALUES ('tit_d1', 'jet_d1', 'service_a', '2026-11-18T12:00:45.000Z', 'outil_x', 'local', 'ok')`,
        )
        .run(),
    ).rejects.toThrow();

    await expect(
      db
        .prepare(
          `INSERT INTO compteur_jour (titulaire_id, jour, classe, appels)
           VALUES ('tit_d1', '2026-11-18T00:00:00.000Z', 'local', 1)`,
        )
        .run(),
    ).rejects.toThrow();

    await expect(
      db
        .prepare(
          `INSERT INTO compteur_jour (titulaire_id, jour, classe, appels)
           VALUES ('tit_inexistant', '2026-11-18', 'local', 1)`,
        )
        .run(),
    ).rejects.toThrow();

    await incrementerCompteurJourD1(db, {
      titulaireId: "tit_d1",
      jour: "2026-11-18",
      classe: "sortant",
      estErreur: false,
      estIntrouvable: true,
      sortants: 2,
    });
    await incrementerCompteurJourD1(db, {
      titulaireId: "tit_d1",
      jour: "2026-11-18",
      classe: "sortant",
      estErreur: true,
      estIntrouvable: false,
      sortants: Number.NaN,
    });
    await incrementerCompteurJourD1(db, {
      titulaireId: "tit_d1",
      jour: "2026-11-18",
      classe: "local",
    });

    const compteurs = await lireCompteursJourD1(db, "tit_d1", "2026-11-18");
    expect(compteurs).toEqual({ local: 1, sortant: 2, semantique: 0 });

    const ligneSortant = await db
      .prepare(
        "SELECT appels, erreurs, introuvables, sortants FROM compteur_jour WHERE titulaire_id = 'tit_d1' AND jour = '2026-11-18' AND classe = 'sortant'",
      )
      .first<{ appels: number; erreurs: number; introuvables: number; sortants: number }>();
    expect(ligneSortant).toEqual({ appels: 2, erreurs: 1, introuvables: 1, sortants: 2 });

    for (const d of [
      new Date("2026-08-19T11:59:00Z"),
      new Date("2026-08-20T12:00:00Z"),
      new Date("2026-11-18T11:55:00Z"),
    ]) {
      await ecrireEvenementTechniqueD1(
        db,
        formaterEvenementTechnique({
          titulaireId: "tit_d1",
          jetonId: "jet_d1",
          service: "service_a",
          horodatage: d,
          outil: "outil_test",
          classe: "local",
          issue: "ok",
        }),
      );
    }

    const seuil = await purgerEvenementsTechniquesD1(db, new Date("2026-11-18T12:00:00Z"), 90);
    expect(seuil).toBe("2026-08-20T12:00");

    const restants = await db
      .prepare("SELECT minute FROM evenement_technique ORDER BY minute ASC")
      .all<{ minute: string }>();
    expect(restants.results.map((r: { minute: string }) => r.minute)).toEqual([
      "2026-08-20T12:00",
      "2026-11-18T11:55",
    ]);

    const planPurge = await db
      .prepare("EXPLAIN QUERY PLAN DELETE FROM evenement_technique WHERE minute < ?1")
      .bind(seuil)
      .all<Record<string, unknown>>();
    expect(JSON.stringify(planPurge.results)).toContain("et_par_minute");
  });

  it("empêche le squattage de numero_membre via demande_acces, indexe coffre_clef.empreinte_clef et exécute toutes les purges de rétention avec index sur D1", async () => {
    const db = env.DB_IDENTITE_TEST;
    await reinitialiserSchemaD1(db, ["service_a", "service_b"]);

    const maitre = "maitre-coffre-test-d1-au-moins-32-caracteres-solides";

    await db
      .prepare(
        `INSERT INTO invitation_acces (id, empreinte_code, cohorte, cree_le, expire_le)
         VALUES ('inv_active', 'hash_inv_active', 'pilote-1', '2026-11-18T11:00:00.000Z', '2026-11-25T11:00:00.000Z'),
                ('inv_exp', 'hash_inv_exp', 'pilote-1', '2026-11-10T11:00:00.000Z', '2026-11-17T11:00:00.000Z'),
                ('inv_consommee_exp', 'hash_inv_cons', 'pilote-1', '2026-11-10T11:00:00.000Z', '2026-11-17T11:00:00.000Z')`,
      )
      .run();
    await db
      .prepare(
        "UPDATE invitation_acces SET consomme_le = '2026-11-11T00:00:00.000Z' WHERE id = 'inv_consommee_exp'",
      )
      .run();

    await db
      .prepare(
        `INSERT INTO demande_acces (
          id, empreinte_jeton, nom, numero_membre, section, courriel, attestation_le, attestation_ver, cgu_ver, cree_le, expire_le
        ) VALUES ('dem_squatteur', 'hash_dem_squat', 'Faux Nom', '555555-5', 'Montreal', 'jetable@exemple.invalid', '2026-11-18T11:00:00.000Z', 'v1', 'v1', '2026-11-18T11:00:00.000Z', '2026-11-18T11:30:00.000Z')`,
      )
      .run();

    const enveloppeCandidat = await scellerCoffre("cle-fournisseur-16c9", {
      titulaireId: "tit_vrai_555",
      usage: "fournisseur_a",
      version: 1,
      maitre,
    });
    await db
      .prepare(
        `INSERT INTO demande_acces (
          id, empreinte_jeton, invitation_id, nom, numero_membre, section, courriel, attestation_le, attestation_ver, cgu_ver,
          coffre_version, coffre_iv, coffre_chiffre, coffre_repere, coffre_empreinte, cree_le, expire_le
        ) VALUES (?1, 'hash_dem_vrai', 'inv_active', 'Vrai Membre', '555555-5', 'Montreal', 'vrai@cabinet.exemple.org',
          '2026-11-18T11:45:00.000Z', 'v1', 'v1', ?2, ?3, ?4, ?5, ?6, '2026-11-18T11:45:00.000Z', '2026-11-18T12:15:00.000Z')`,
      )
      .bind(
        "tit_vrai_555",
        enveloppeCandidat.version,
        enveloppeCandidat.iv,
        enveloppeCandidat.chiffre,
        enveloppeCandidat.repere,
        enveloppeCandidat.empreinteClef,
      )
      .run();

    await expect(
      db
        .prepare(
          `INSERT INTO demande_acces (
            id, empreinte_jeton, nom, numero_membre, section, courriel, attestation_le, attestation_ver, cgu_ver,
            coffre_version, cree_le, expire_le
          ) VALUES ('dem_invalide', 'hash_dem_bad', 'Incomplet', '666666-6', 'Quebec', 'inc@exemple.org', '2026-11-18T11:45:00.000Z', 'v1', 'v1', 1, '2026-11-18T11:45:00.000Z', '2026-11-18T12:15:00.000Z')`,
        )
        .run(),
    ).rejects.toThrow();

    await db.batch([
      db.prepare(
        `INSERT INTO titulaire (
          id, cree_le, etat, nom, numero_membre, section, courriel, courriel_verifie_le, attestation_le, attestation_ver, cgu_ver
        ) VALUES ('tit_vrai_555', '2026-11-18T11:50:00.000Z', 'actif', 'Vrai Membre', '555555-5', 'Montreal', 'vrai@cabinet.exemple.org', '2026-11-18T11:50:00.000Z', '2026-11-18T11:45:00.000Z', 'v1', 'v1')`,
      ),
      db
        .prepare(
          `INSERT INTO coffre_clef (
            titulaire_id, usage, version, iv, chiffre, repere, empreinte_clef, pose_le, eprouve_le, etat
          ) VALUES ('tit_vrai_555', 'fournisseur_a', ?1, ?2, ?3, ?4, ?5, '2026-11-18T11:50:00.000Z', '2026-11-18T11:50:00.000Z', 'valide')`,
        )
        .bind(
          enveloppeCandidat.version,
          enveloppeCandidat.iv,
          enveloppeCandidat.chiffre,
          enveloppeCandidat.repere,
          enveloppeCandidat.empreinteClef,
        ),
      db.prepare(
        "UPDATE demande_acces SET consomme_le = '2026-11-18T11:50:00.000Z' WHERE id = 'tit_vrai_555'",
      ),
      db.prepare(
        "UPDATE invitation_acces SET consomme_le = '2026-11-18T11:50:00.000Z', titulaire_id = 'tit_vrai_555' WHERE id = 'inv_active'",
      ),
    ]);

    const enveloppeCollegue = await scellerCoffre("cle-fournisseur-16c9", {
      titulaireId: "tit_collegue_556",
      usage: "fournisseur_a",
      version: 1,
      maitre,
    });
    await db
      .prepare(
        `INSERT INTO titulaire (
          id, cree_le, etat, nom, numero_membre, section, courriel, courriel_verifie_le, attestation_le, attestation_ver, cgu_ver
        ) VALUES ('tit_collegue_556', '2026-11-18T11:55:00.000Z', 'actif', 'Collegue Cabinet', '555556-3', 'Montreal', 'collegue@cabinet.exemple.org', '2026-11-18T11:55:00.000Z', '2026-11-18T11:55:00.000Z', 'v1', 'v1')`,
      )
      .run();
    await db
      .prepare(
        `INSERT INTO coffre_clef (
          titulaire_id, usage, version, iv, chiffre, repere, empreinte_clef, pose_le, eprouve_le, etat
        ) VALUES ('tit_collegue_556', 'fournisseur_a', ?1, ?2, ?3, ?4, ?5, '2026-11-18T11:55:00.000Z', '2026-11-18T11:55:00.000Z', 'valide')`,
      )
      .bind(
        enveloppeCollegue.version,
        enveloppeCollegue.iv,
        enveloppeCollegue.chiffre,
        enveloppeCollegue.repere,
        enveloppeCollegue.empreinteClef,
      )
      .run();

    const doublons = await db
      .prepare(
        "SELECT titulaire_id FROM coffre_clef WHERE usage = ?1 AND empreinte_clef = ?2 ORDER BY titulaire_id ASC",
      )
      .bind("fournisseur_a", enveloppeCandidat.empreinteClef)
      .all<{ titulaire_id: string }>();
    expect(doublons.results.map((r) => r.titulaire_id)).toEqual([
      "tit_collegue_556",
      "tit_vrai_555",
    ]);

    const planEmpreinteCoffre = await db
      .prepare(
        "EXPLAIN QUERY PLAN SELECT titulaire_id FROM coffre_clef WHERE usage = ?1 AND empreinte_clef = ?2",
      )
      .bind("fournisseur_a", enveloppeCandidat.empreinteClef)
      .all<Record<string, unknown>>();
    expect(JSON.stringify(planEmpreinteCoffre.results)).toContain("cc_par_empreinte");

    await db
      .prepare(
        `INSERT INTO demande_acces (
          id, empreinte_jeton, nom, numero_membre, section, courriel, attestation_le, attestation_ver, cgu_ver, cree_le, expire_le
        ) VALUES ('dem_en_cours', 'hash_dem_active', 'En Cours', '777777-7', 'Laval', 'encours@exemple.org', '2026-11-18T11:55:00.000Z', 'v1', 'v1', '2026-11-18T11:55:00.000Z', '2026-11-18T12:25:00.000Z')`,
      )
      .run();

    await db
      .prepare(
        `INSERT INTO session_portail (id, titulaire_id, courriel, type_lien, empreinte, cree_le, expire_le, consomme_le)
         VALUES ('sp_exp', 'tit_vrai_555', 'vrai@cabinet.exemple.org', 'connexion_moi', 'h_sp_1', '2026-11-18T10:00:00.000Z', '2026-11-18T10:30:00.000Z', NULL),
                ('sp_cons', 'tit_vrai_555', 'vrai@cabinet.exemple.org', 'connexion_moi', 'h_sp_2', '2026-11-18T11:55:00.000Z', '2026-11-18T12:25:00.000Z', '2026-11-18T11:56:00.000Z'),
                ('sp_ok', 'tit_vrai_555', 'vrai@cabinet.exemple.org', 'session_moi', 'h_sp_3', '2026-11-18T11:56:00.000Z', '2026-11-18T23:56:00.000Z', NULL)`,
      )
      .run();

    await db
      .prepare(
        `INSERT INTO code_oauth (id, titulaire_id, empreinte_code, client_id, redirect_uri, portee, defi_pkce, methode_pkce, cree_le, expire_le, consomme_le)
         VALUES ('co_exp', 'tit_vrai_555', 'h_co_1', 'cl_1', 'https://claude.ai/api/mcp/auth_callback', 'les_deux', 'defi', 'S256', '2026-11-18T11:40:00.000Z', '2026-11-18T11:45:00.000Z', NULL),
                ('co_cons', 'tit_vrai_555', 'h_co_2', 'cl_1', 'https://claude.ai/api/mcp/auth_callback', 'les_deux', 'defi', 'S256', '2026-11-18T11:58:00.000Z', '2026-11-18T12:03:00.000Z', '2026-11-18T11:59:00.000Z'),
                ('co_ok', 'tit_vrai_555', 'h_co_3', 'cl_1', 'https://claude.ai/api/mcp/auth_callback', 'les_deux', 'defi', 'S256', '2026-11-18T11:59:00.000Z', '2026-11-18T12:04:00.000Z', NULL)`,
      )
      .run();

    for (const jour of ["2026-08-19", "2026-08-20", "2026-11-18"]) {
      await incrementerCompteurJourD1(db, {
        titulaireId: "tit_vrai_555",
        jour,
        classe: "local",
      });
    }

    const bilan = await purgerRetentionsD1(db, new Date("2026-11-18T12:00:00.000Z"));
    expect(bilan).toEqual({
      instantIso: "2026-11-18T12:00:00.000Z",
      jourCompteursSeuil: "2026-08-20",
      minuteEvenementsSeuil: "2026-08-20T12:00",
    });

    const demandesRestantes = await db
      .prepare("SELECT id FROM demande_acces ORDER BY id ASC")
      .all<{ id: string }>();
    expect(demandesRestantes.results.map((r) => r.id)).toEqual(["dem_en_cours"]);

    const invitationsRestantes = await db
      .prepare("SELECT id FROM invitation_acces ORDER BY id ASC")
      .all<{ id: string }>();
    expect(invitationsRestantes.results.map((r) => r.id)).toEqual(["inv_active"]);

    const sessionsRestantes = await db
      .prepare("SELECT id FROM session_portail ORDER BY id ASC")
      .all<{ id: string }>();
    expect(sessionsRestantes.results.map((r) => r.id)).toEqual(["sp_ok"]);

    const codesRestants = await db
      .prepare("SELECT id FROM code_oauth ORDER BY id ASC")
      .all<{ id: string }>();
    expect(codesRestants.results.map((r) => r.id)).toEqual(["co_ok"]);

    const joursCompteursRestants = await db
      .prepare(
        "SELECT jour FROM compteur_jour WHERE titulaire_id = 'tit_vrai_555' ORDER BY jour ASC",
      )
      .all<{ jour: string }>();
    expect(joursCompteursRestants.results.map((r) => r.jour)).toEqual(["2026-08-20", "2026-11-18"]);

    const verificationsPlans: Array<{ sql: string; arg: string; indexAttendu: string }> = [
      {
        sql: "EXPLAIN QUERY PLAN DELETE FROM compteur_jour WHERE jour < ?1",
        arg: bilan.jourCompteursSeuil,
        indexAttendu: "cj_par_jour",
      },
      {
        sql: "EXPLAIN QUERY PLAN DELETE FROM demande_acces WHERE expire_le <= ?1",
        arg: bilan.instantIso,
        indexAttendu: "da_par_expiration",
      },
      {
        sql: "EXPLAIN QUERY PLAN DELETE FROM demande_acces WHERE consomme_le IS NOT NULL AND consomme_le <= ?1",
        arg: bilan.instantIso,
        indexAttendu: "da_consommee",
      },
      {
        sql: "EXPLAIN QUERY PLAN DELETE FROM invitation_acces WHERE titulaire_id IS NULL AND expire_le <= ?1",
        arg: bilan.instantIso,
        indexAttendu: "ia_par_expiration",
      },
      {
        sql: "EXPLAIN QUERY PLAN DELETE FROM session_portail WHERE expire_le <= ?1",
        arg: bilan.instantIso,
        indexAttendu: "sp_par_expiration",
      },
      {
        sql: "EXPLAIN QUERY PLAN DELETE FROM session_portail WHERE consomme_le IS NOT NULL AND consomme_le <= ?1",
        arg: bilan.instantIso,
        indexAttendu: "sp_consommee",
      },
      {
        sql: "EXPLAIN QUERY PLAN DELETE FROM code_oauth WHERE expire_le <= ?1",
        arg: bilan.instantIso,
        indexAttendu: "co_par_expiration",
      },
      {
        sql: "EXPLAIN QUERY PLAN DELETE FROM code_oauth WHERE consomme_le IS NOT NULL AND consomme_le <= ?1",
        arg: bilan.instantIso,
        indexAttendu: "co_consomme",
      },
      {
        sql: "EXPLAIN QUERY PLAN DELETE FROM titulaire WHERE id = ?1",
        arg: "tit_vrai_555",
        indexAttendu: "sqlite_autoindex_titulaire_1",
      },
    ];

    for (const v of verificationsPlans) {
      const plan = await db.prepare(v.sql).bind(v.arg).all<Record<string, unknown>>();
      const textePlan = JSON.stringify(plan.results);
      expect(textePlan, v.sql).not.toContain("SCAN ");
      expect(textePlan, `${v.sql} -> ${v.indexAttendu}`).toContain(v.indexAttendu);
    }

    await retirerEntreeCoffreD1(db, "tit_collegue_556", "fournisseur_a");
    expect(
      await db
        .prepare("SELECT COUNT(*) AS n FROM coffre_clef WHERE titulaire_id = 'tit_collegue_556'")
        .first<{ n: number }>(),
    ).toEqual({ n: 0 });

    await db.batch([
      db.prepare(
        `INSERT INTO jeton (id, titulaire_id, empreinte, queue, libelle, portee, emis_le)
         VALUES ('jet_555', 'tit_vrai_555', 'h_jet_555', '123456', 'Principal', 'les_deux', '2026-11-18T11:55:00.000Z')`,
      ),
      db.prepare(
        `INSERT INTO registre_gouverne (titulaire_id, le, de, vers, motif, auteur)
         VALUES ('tit_vrai_555', '2026-11-18T11:50:00.000Z', 'en_attente', 'actif', 'admission', 'exploitant')`,
      ),
    ]);
    await ecrireEvenementTechniqueD1(
      db,
      formaterEvenementTechnique({
        titulaireId: "tit_vrai_555",
        jetonId: "jet_555",
        service: "service_a",
        horodatage: new Date("2026-11-18T11:58:00.000Z"),
        outil: "outil_x",
        classe: "local",
        issue: "ok",
      }),
    );

    const planPurgeEvTitulaire = await db
      .prepare("EXPLAIN QUERY PLAN DELETE FROM evenement_technique WHERE titulaire_id = ?1")
      .bind("tit_vrai_555")
      .all<Record<string, unknown>>();
    expect(JSON.stringify(planPurgeEvTitulaire.results)).toContain("et_par_titulaire");
    expect(JSON.stringify(planPurgeEvTitulaire.results)).not.toContain("SCAN ");

    await supprimerCompteTitulaireD1(db, "tit_vrai_555");

    for (const [table, col] of [
      ["titulaire", "id"],
      ["invitation_acces", "titulaire_id"],
      ["jeton", "titulaire_id"],
      ["coffre_clef", "titulaire_id"],
      ["session_portail", "titulaire_id"],
      ["code_oauth", "titulaire_id"],
      ["compteur_jour", "titulaire_id"],
      ["evenement_technique", "titulaire_id"],
      ["registre_gouverne", "titulaire_id"],
    ] as const) {
      const restant = await db
        .prepare(`SELECT COUNT(*) AS n FROM ${table} WHERE ${col} = 'tit_vrai_555'`)
        .first<{ n: number }>();
      expect(restant, `${table}.${col}`).toEqual({ n: 0 });
    }
  });
});
