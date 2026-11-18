import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { construireSchemaIdentiteD1 } from "../src/identite/gouverne";
import {
  empreinte,
  estCheminMontageAdmissible,
  estJetonFrappe,
  frapperJeton,
  LONGUEUR_QUEUE_JETON,
  MAX_LONGUEUR_PORTEUR,
  ouvrir,
  type Porte,
  porteurEntete,
  queueJeton,
} from "../src/identite/porteur";
import {
  type BaseD1Minimale,
  creerDepotJetonsD1,
  type DepotJetons,
  type EnregistrementJetonTitulaire,
  estEtatServi,
  horodatageUtcMs,
  MAX_CANDIDATS_JETON,
  ouvrirPrincipal,
  PORTEE_UNIVERSELLE,
  porteeAutorisee,
  resoudreJeton,
} from "../src/identite/titulaire";

const HORLOGE_FIXE = () => new Date("2026-11-18T14:30:45.123Z");
const PORTE_MCP: Porte = {
  mount: "/mcp",
  queryKey: "key",
  nomsSecrets: ["SECRET_CI"],
  segmentBorne: true,
};

function creerDepotMemoire(lignes: Record<string, EnregistrementJetonTitulaire>) {
  const lectures: string[] = [];
  const misesAJourVuLe: Array<{ jetonId: string; jourUtc: string }> = [];
  const depot: DepotJetons = {
    async trouverParEmpreinte(empreinteHex: string) {
      lectures.push(empreinteHex);
      return Object.hasOwn(lignes, empreinteHex) ? lignes[empreinteHex]! : null;
    },
    async marquerVuLe(jetonId: string, jourUtc: string) {
      misesAJourVuLe.push({ jetonId, jourUtc });
    },
  };
  return { depot, lectures, misesAJourVuLe };
}

describe("estJetonFrappe, queueJeton et porteurEntete", () => {
  it("reconnaît exclusivement les jetons 43 caractères base64url et en extrait la queue de 6 car.", () => {
    const j = frapperJeton();
    expect(estJetonFrappe(j)).toBe(true);
    expect(queueJeton(j)).toHaveLength(LONGUEUR_QUEUE_JETON);
    expect(j.endsWith(queueJeton(j))).toBe(true);

    expect(estJetonFrappe("trop-court")).toBe(false);
    expect(estJetonFrappe(`${j}x`)).toBe(false);
    expect(estJetonFrappe(`${"a".repeat(42)}+`)).toBe(false);
    expect(() => queueJeton("invalide")).toThrow();
  });

  it("lit un en-tête de surcharge client borné à MAX_LONGUEUR_PORTEUR", () => {
    const rOk = new Request("https://exemple.test/mcp", {
      headers: { "X-Porteur-Externe": "  valeur-valide  " },
    });
    expect(porteurEntete(rOk, "X-Porteur-Externe")).toBe("valeur-valide");
    expect(porteurEntete(rOk, "")).toBeNull();
    expect(porteurEntete(rOk, "X-Absent")).toBeNull();

    const rVide = new Request("https://exemple.test/mcp", {
      headers: { "X-Porteur-Externe": "   " },
    });
    expect(porteurEntete(rVide, "X-Porteur-Externe")).toBeNull();

    const rTropLong = new Request("https://exemple.test/mcp", {
      headers: { "X-Porteur-Externe": "x".repeat(MAX_LONGUEUR_PORTEUR + 1) },
    });
    expect(porteurEntete(rTropLong, "X-Porteur-Externe")).toBeNull();
  });
});

describe("estEtatServi et porteeAutorisee", () => {
  it("n'autorise que actif, surveille et limite", () => {
    for (const servi of ["actif", "surveille", "limite"]) {
      expect(estEtatServi(servi)).toBe(true);
    }
    for (const refuse of ["en_attente", "suspendu", "revoque", "refuse", "", null, undefined]) {
      expect(estEtatServi(refuse)).toBe(false);
    }
  });

  it("accepte les_deux partout et cloisonne les portées dédiées par service", () => {
    expect(porteeAutorisee(PORTEE_UNIVERSELLE, "service_a")).toBe(true);
    expect(porteeAutorisee(PORTEE_UNIVERSELLE, "service_b")).toBe(true);
    expect(porteeAutorisee(PORTEE_UNIVERSELLE)).toBe(true);

    expect(porteeAutorisee("service_a", "service_a")).toBe(true);
    expect(porteeAutorisee("service_a", "service_b")).toBe(false);
    expect(porteeAutorisee("service_a")).toBe(false);
    expect(porteeAutorisee("service_a service_b", "service_b")).toBe(true);
    expect(porteeAutorisee("", "service_a")).toBe(false);
    expect(porteeAutorisee(null, "service_a")).toBe(false);
  });
});

describe("resoudreJeton — G7 (zéro oracle) et G21 (fermé par défaut)", () => {
  it("G21 : dépôt absent, vide, candidat mal formé ou exception D1 => null", async () => {
    const j = frapperJeton();
    expect(await resoudreJeton(undefined, [j])).toBeNull();

    const vide = creerDepotMemoire({});
    expect(await resoudreJeton(vide.depot, [])).toBeNull();
    expect(vide.lectures).toHaveLength(0);

    expect(await resoudreJeton(vide.depot, ["non-base64url-43"])).toBeNull();
    expect(vide.lectures).toHaveLength(0);

    const enPanne: DepotJetons = {
      async trouverParEmpreinte() {
        throw new Error("D1 indisponible");
      },
    };
    expect(await resoudreJeton(enPanne, [j])).toBeNull();
  });

  it("G7 : jeton inconnu, expiré (y compris borne exacte), révoqué, hors portée ou titulaire non servi rendent tous null", async () => {
    const jInconnu = frapperJeton();
    const jExpireExact = frapperJeton();
    const jRevoque = frapperJeton();
    const jHorsPortee = frapperJeton();
    const jEnAttente = frapperJeton();
    const jSuspendu = frapperJeton();
    const jRevoqueTitulaire = frapperJeton();
    const jRefuse = frapperJeton();

    const baseLigne = {
      jeton_id: "jet_1",
      titulaire_id: "tit_1",
      etat: "actif",
      portee: "les_deux",
      hybride_permis: 1,
      expire_le: "2027-11-18T14:30:45.123Z",
      revoque_le: null,
      vu_le: null,
    };

    const table: Record<string, EnregistrementJetonTitulaire> = {
      [await empreinte(jExpireExact)]: {
        ...baseLigne,
        expire_le: "2026-11-18T14:30:45.123Z",
      },
      [await empreinte(jRevoque)]: {
        ...baseLigne,
        revoque_le: "2026-11-01T00:00:00.000Z",
      },
      [await empreinte(jHorsPortee)]: {
        ...baseLigne,
        portee: "service_b",
      },
      [await empreinte(jEnAttente)]: { ...baseLigne, etat: "en_attente" },
      [await empreinte(jSuspendu)]: { ...baseLigne, etat: "suspendu" },
      [await empreinte(jRevoqueTitulaire)]: { ...baseLigne, etat: "revoque" },
      [await empreinte(jRefuse)]: { ...baseLigne, etat: "refuse" },
    };

    const { depot } = creerDepotMemoire(table);
    for (const mauvais of [
      jInconnu,
      jExpireExact,
      jRevoque,
      jHorsPortee,
      jEnAttente,
      jSuspendu,
      jRevoqueTitulaire,
      jRefuse,
    ]) {
      expect(
        await resoudreJeton(depot, [mauvais], { service: "service_a", horloge: HORLOGE_FIXE }),
      ).toBeNull();
    }
  });

  it("résout un titulaire actif et met à jour vu_le au plus une fois par jour UTC", async () => {
    const jeton = frapperJeton();
    const hash = await empreinte(jeton);
    const taches: Promise<unknown>[] = [];

    const { depot, misesAJourVuLe } = creerDepotMemoire({
      [hash]: {
        jeton_id: "jet_42",
        titulaire_id: "tit_42",
        etat: "actif",
        portee: "service_a",
        hybride_permis: 0,
        expire_le: "2027-01-01T00:00:00.000Z",
        revoque_le: null,
        vu_le: "2026-11-17",
      },
    });

    const resolu = await resoudreJeton(depot, [jeton], {
      service: "service_a",
      horloge: HORLOGE_FIXE,
      planifierArrierePlan: (p) => taches.push(p),
    });
    await Promise.all(taches);

    expect(resolu).toEqual({
      titulaireId: "tit_42",
      jetonId: "jet_42",
      etat: "actif",
      portee: "service_a",
      hybridePermis: false,
      vuLe: "2026-11-17",
    });
    expect(misesAJourVuLe).toEqual([{ jetonId: "jet_42", jourUtc: "2026-11-18" }]);

    // Déjà vu le même jour UTC : aucune écriture D1 supplémentaire.
    const dejaVu = creerDepotMemoire({
      [hash]: {
        jeton_id: "jet_42",
        titulaire_id: "tit_42",
        etat: "surveille",
        portee: "les_deux",
        hybride_permis: 1,
        expire_le: null,
        revoque_le: null,
        vu_le: "2026-11-18",
      },
    });
    const taches2: Promise<unknown>[] = [];
    const resolu2 = await resoudreJeton(dejaVu.depot, [jeton], {
      service: "service_a",
      horloge: HORLOGE_FIXE,
      planifierArrierePlan: (p) => taches2.push(p),
    });
    await Promise.all(taches2);
    expect(resolu2?.hybridePermis).toBe(true);
    expect(dejaVu.misesAJourVuLe).toHaveLength(0);
  });

  it("plafonne le nombre de candidats interrogés à MAX_CANDIDATS_JETON et évalue tous les candidats sans court-circuit", async () => {
    const candidats = Array.from({ length: 10 }, () => frapperJeton());
    const { depot, lectures } = creerDepotMemoire({});
    expect(await resoudreJeton(depot, candidats)).toBeNull();
    expect(lectures).toHaveLength(MAX_CANDIDATS_JETON);

    // Même si le 1er candidat est actif, le 2e candidat est aussi interrogé (zéro court-circuit).
    const jActif = frapperJeton();
    const jSecond = frapperJeton();
    const sansCourtCircuit = creerDepotMemoire({
      [await empreinte(jActif)]: {
        jeton_id: "jet_a",
        titulaire_id: "tit_a",
        etat: "actif",
        portee: "les_deux",
        hybride_permis: 1,
        expire_le: null,
        revoque_le: null,
        vu_le: "2026-11-18",
      },
    });
    const empreintesValidees: string[] = [];
    const r = await resoudreJeton(sansCourtCircuit.depot, [jActif, jSecond], {
      service: "service_a",
      horloge: HORLOGE_FIXE,
      surEmpreinteValide: (h) => empreintesValidees.push(h),
    });
    expect(r?.jetonId).toBe("jet_a");
    expect(sansCourtCircuit.lectures).toHaveLength(2);
    expect(empreintesValidees).toEqual([await empreinte(jActif)]);
  });

  it("horodatageUtcMs et expire_le comparent l'époque numérique (RFC 3339 sans ms, SQLite UTC, dates invalides fermées)", async () => {
    // "2026-11-18T14:30:45Z" est ANTÉRIEUR à HORLOGE_FIXE ("2026-11-18T14:30:45.123Z") même si 'Z' > '.' en ASCII !
    const jSansMsExpire = frapperJeton();
    // Format SQLite "2026-11-18 23:59:59" est POSTÉRIEUR à HORLOGE_FIXE même si ' ' < 'T' en ASCII !
    const jSqliteEncoreValide = frapperJeton();
    // Chaîne corrompue -> doit échouer FERMÉ (null), jamais ouvert !
    const jDateCorrompue = frapperJeton();

    const baseLigne = {
      jeton_id: "jet_t",
      titulaire_id: "tit_t",
      etat: "actif",
      portee: "les_deux",
      hybride_permis: 1,
      revoque_le: null,
      vu_le: "2026-11-18",
    };

    const { depot } = creerDepotMemoire({
      [await empreinte(jSansMsExpire)]: {
        ...baseLigne,
        expire_le: "2026-11-18T14:30:45Z",
      },
      [await empreinte(jSqliteEncoreValide)]: {
        ...baseLigne,
        jeton_id: "jet_sqlite_ok",
        expire_le: "2026-11-18 23:59:59",
      },
      [await empreinte(jDateCorrompue)]: {
        ...baseLigne,
        expire_le: "date-corrompue",
      },
    });

    expect(
      await resoudreJeton(depot, [jSansMsExpire], { service: "service_a", horloge: HORLOGE_FIXE }),
    ).toBeNull();
    expect(
      await resoudreJeton(depot, [jDateCorrompue], { service: "service_a", horloge: HORLOGE_FIXE }),
    ).toBeNull();
    expect(
      (
        await resoudreJeton(depot, [jSqliteEncoreValide], {
          service: "service_a",
          horloge: HORLOGE_FIXE,
        })
      )?.jetonId,
    ).toBe("jet_sqlite_ok");

    expect(horodatageUtcMs("2026-02-30T00:00:00Z")).toBeNull();
    expect(horodatageUtcMs(" 2026-11-18T00:00:00Z")).toBeNull();
    expect(horodatageUtcMs("2026-11-18T14:30:45.123456Z")).toBe(
      Date.parse("2026-11-18T14:30:45.123Z"),
    );
  });
});

describe("ouvrirPrincipal et creerDepotJetonsD1", () => {
  it("permet la coexistence d'un jeton D1 et d'un secret CI sans qu'un Bearer périmé ne masque ?key=", async () => {
    const jetonPerime = frapperJeton();
    const jetonValide = frapperJeton();
    const { depot } = creerDepotMemoire({
      [await empreinte(jetonPerime)]: {
        jeton_id: "jet_old",
        titulaire_id: "tit_9",
        etat: "actif",
        portee: "les_deux",
        hybride_permis: 1,
        expire_le: "2020-01-01T00:00:00.000Z",
        revoque_le: null,
        vu_le: null,
      },
      [await empreinte(jetonValide)]: {
        jeton_id: "jet_ok",
        titulaire_id: "tit_9",
        etat: "limite",
        portee: "les_deux",
        hybride_permis: 1,
        expire_le: null,
        revoque_le: null,
        vu_le: "2026-11-18",
      },
    });

    const url = new URL(`https://exemple.test/mcp?key=${jetonValide}&garde=1`);
    const req = new Request(url.toString(), {
      method: "POST",
      headers: { Authorization: `Bearer ${jetonPerime}` },
    });

    const ouvert = await ouvrirPrincipal(req, url, { SECRET_CI: "secret-veille-ci" }, PORTE_MCP, {
      depot,
      service: "service_a",
      horloge: HORLOGE_FIXE,
    });

    expect(ouvert).not.toBeNull();
    expect(ouvert!.principal).toEqual({
      type: "titulaire",
      titulaireId: "tit_9",
      jetonId: "jet_ok",
      etat: "limite",
      portee: "les_deux",
      hybridePermis: true,
    });
    const urlSortie = new URL(ouvert!.requete.url);
    expect(urlSortie.pathname).toBe("/mcp");
    expect(urlSortie.searchParams.get("key")).toBeNull();
    expect(urlSortie.searchParams.get("garde")).toBe("1");

    // Appelant CI / transitoire par secret partagé (64 car. hex généré par openssl rand -hex 32) :
    const secretHex64 = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
    const empreintesSecretPartage: string[] = [];
    const reqCi = new Request("https://exemple.test/mcp", {
      method: "POST",
      headers: { Authorization: `Bearer ${secretHex64}` },
    });
    const ouvertCi = await ouvrirPrincipal(
      reqCi,
      new URL(reqCi.url),
      { SECRET_CI: secretHex64 },
      PORTE_MCP,
      {
        depot,
        service: "service_a",
        horloge: HORLOGE_FIXE,
        surEmpreinteValide: (h) => empreintesSecretPartage.push(h),
      },
    );
    expect(ouvertCi?.principal).toEqual({ type: "secret_partage" });
    expect(ouvertCi?.requete).toBe(reqCi);
    expect(empreintesSecretPartage).toEqual([await empreinte(secretHex64)]);

    // Sur la monture OAuth (/mcp/oauth, autoriserChemin: false), tout sous-chemin est rejeté MÊME avec Bearer valide :
    const porteOAuth: Porte = {
      mount: "/mcp/oauth",
      nomsSecrets: [],
      autoriserChemin: false,
    };
    const reqCheminOAuth = new Request("https://exemple.test/mcp/oauth/sous/chemin", {
      method: "POST",
      headers: { Authorization: `Bearer ${jetonValide}` },
    });
    expect(
      await ouvrirPrincipal(reqCheminOAuth, new URL(reqCheminOAuth.url), {}, porteOAuth, {
        depot,
        service: "service_a",
        horloge: HORLOGE_FIXE,
      }),
    ).toBeNull();

    // /mcp/oauth/ (barre finale seule) avec Bearer valide est accepté et normalisé vers /mcp/oauth :
    const reqBarreFinaleOAuth = new Request("https://exemple.test/mcp/oauth/", {
      method: "POST",
      headers: { Authorization: `Bearer ${jetonValide}` },
    });
    const ouvertOAuth = await ouvrirPrincipal(
      reqBarreFinaleOAuth,
      new URL(reqBarreFinaleOAuth.url),
      {},
      porteOAuth,
      { depot, service: "service_a", horloge: HORLOGE_FIXE },
    );
    expect(new URL(ouvertOAuth!.requete.url).pathname).toBe("/mcp/oauth");

    // Sur segmentBorne: true (/mcp), un chemin profond /mcp/a/b est rejeté MÊME avec Bearer ou secret CI valide :
    const reqProfonde = new Request("https://exemple.test/mcp/a/b", {
      method: "POST",
      headers: { Authorization: "Bearer secret-veille-ci" },
    });
    expect(estCheminMontageAdmissible("/mcp/a/b", PORTE_MCP)).toBe(false);
    expect(
      await ouvrir(
        reqProfonde,
        new URL(reqProfonde.url),
        { SECRET_CI: "secret-veille-ci" },
        PORTE_MCP,
      ),
    ).toBeNull();
    const effetsIndesirables: string[] = [];
    expect(
      await ouvrirPrincipal(
        reqProfonde,
        new URL(reqProfonde.url),
        { SECRET_CI: "secret-veille-ci" },
        PORTE_MCP,
        {
          depot,
          service: "service_a",
          horloge: HORLOGE_FIXE,
          surEmpreinteValide: (h) => effetsIndesirables.push(h),
        },
      ),
    ).toBeNull();
    expect(effetsIndesirables).toEqual([]);
  });

  it("exécute creerDepotJetonsD1 et resoudreJeton contre une VRAIE base Cloudflare D1 (workerd SQLite)", async () => {
    const db = env.DB_IDENTITE_TEST;
    const instructions = construireSchemaIdentiteD1(["service_a", "service_b"])
      .split(";")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    await db.batch([
      db.prepare("PRAGMA foreign_keys = ON"),
      ...instructions.map((sql) => db.prepare(sql)),
    ]);

    const jetonActif = frapperJeton();
    const jetonRevoque = frapperJeton();
    const hashActif = await empreinte(jetonActif);
    const hashRevoque = await empreinte(jetonRevoque);

    await db
      .prepare(
        `INSERT INTO titulaire (
          id, cree_le, etat, nom, numero_membre, section, courriel, attestation_le, attestation_ver, cgu_ver, hybride_permis
        ) VALUES (?1, ?2, 'actif', 'Confrere Test', '999999-0', 'Montreal', 'test@exemple.org', ?2, 'v1', 'v1', 0)`,
      )
      .bind("tit_reel_1", "2026-11-18T00:00:00Z")
      .run();

    await db
      .prepare(
        `INSERT INTO jeton (id, titulaire_id, empreinte, queue, libelle, portee, emis_le, expire_le, revoque_le, vu_le)
         VALUES (?1, ?2, ?3, ?4, 'Poste bureau', 'service_a', '2026-11-18T00:00:00Z', '2027-11-18T00:00:00Z', NULL, NULL)`,
      )
      .bind("jet_reel_1", "tit_reel_1", hashActif, queueJeton(jetonActif))
      .run();

    await db
      .prepare(
        `INSERT INTO jeton (id, titulaire_id, empreinte, queue, libelle, portee, emis_le, expire_le, revoque_le, motif_revoc)
         VALUES (?1, ?2, ?3, ?4, 'Ancien', 'les_deux', '2026-11-01T00:00:00Z', NULL, '2026-11-10T00:00:00Z', 'rotation')`,
      )
      .bind("jet_reel_2", "tit_reel_1", hashRevoque, queueJeton(jetonRevoque))
      .run();

    const depotD1 = creerDepotJetonsD1(db);
    const tachesVu: Promise<unknown>[] = [];
    const resolu = await resoudreJeton(depotD1, [jetonActif], {
      service: "service_a",
      horloge: HORLOGE_FIXE,
      planifierArrierePlan: (p) => tachesVu.push(p),
    });
    await Promise.all(tachesVu);

    expect(resolu).toEqual({
      titulaireId: "tit_reel_1",
      jetonId: "jet_reel_1",
      etat: "actif",
      portee: "service_a",
      hybridePermis: false,
      vuLe: null,
    });

    // Vérifie que vu_le a réellement été écrit dans SQLite/D1 et que le jeton révoqué/hors portée échoue :
    const apresVu = await resoudreJeton(depotD1, [jetonActif], {
      service: "service_a",
      horloge: HORLOGE_FIXE,
    });
    expect(apresVu?.vuLe).toBe("2026-11-18");
    expect(
      await resoudreJeton(depotD1, [jetonActif], { service: "service_b", horloge: HORLOGE_FIXE }),
    ).toBeNull();
    expect(
      await resoudreJeton(depotD1, [jetonRevoque], { service: "service_a", horloge: HORLOGE_FIXE }),
    ).toBeNull();
  });

  it("creerDepotJetonsD1 lie correctement les paramètres SQL préparés", async () => {
    const appelsSql: Array<{ sql: string; args: unknown[] }> = [];
    const fausseD1: BaseD1Minimale = {
      prepare(sql: string) {
        return {
          bind(...args: unknown[]) {
            appelsSql.push({ sql, args });
            return {
              async first<T>() {
                return null as T | null;
              },
              async all<T>() {
                return { results: [] as T[] };
              },
              async run() {
                return {};
              },
            };
          },
        };
      },
    };
    const depot = creerDepotJetonsD1(fausseD1);
    expect(await depot.trouverParEmpreinte("abcd")).toBeNull();
    await depot.marquerVuLe!("jet_1", "2026-11-18");
    expect(appelsSql).toHaveLength(2);
    expect(appelsSql[0]!.args).toEqual(["abcd"]);
    expect(appelsSql[1]!.args).toEqual(["jet_1", "2026-11-18"]);
  });
});
