import { describe, expect, it } from "vitest";
import {
  empreinteCoffre,
  expurger,
  type LigneCoffre,
  LONGUEUR_IV_COFFRE,
  ouvrirCoffre,
  repereCoffre,
  scellerCoffre,
} from "../src/identite/coffre";
import { empreinte, frapperJeton } from "../src/identite/porteur";

const MAITRE_V1 = "maitre-v1-entropie-suffisante-32-caracteres-minimum";
const MAITRE_V2 = "maitre-v2-rotation-entropie-suffisante-32-caracteres";

describe("scellerCoffre et ouvrirCoffre — chiffrement par enveloppe dans workerd", () => {
  it("scelle puis ouvre un secret dans la fermeture sans jamais retourner le texte clair (G10)", async () => {
    const valeurSecrete = "secret-fournisseur-externe-9876543210";
    const scelle = await scellerCoffre(valeurSecrete, {
      titulaireId: "tit_01",
      usage: "fournisseur_a",
      version: 1,
      maitre: MAITRE_V1,
    });

    expect(scelle.iv).toBeInstanceOf(Uint8Array);
    expect(scelle.iv.byteLength).toBe(LONGUEUR_IV_COFFRE);
    expect(scelle.chiffre.byteLength).toBeGreaterThan(valeurSecrete.length);
    expect(scelle.repere).toMatch(/^••••3210#[0-9a-f]{8}$/);
    expect(scelle.repere).not.toContain("secr");
    expect(scelle.empreinteClef).toMatch(/^[0-9a-f]{64}$/);

    // Deux scellements identiques produisent deux IV et deux chiffrés distincts.
    const scelleBis = await scellerCoffre(valeurSecrete, {
      titulaireId: "tit_01",
      usage: "fournisseur_a",
      version: 1,
      maitre: MAITRE_V1,
    });
    expect(Array.from(scelle.iv)).not.toEqual(Array.from(scelleBis.iv));

    const entreeD1: LigneCoffre = {
      titulaireId: "tit_01",
      version: 1,
      iv: scelle.iv.slice().buffer,
      chiffre: Array.from(scelle.chiffre),
      repere: scelle.repere,
      etat: "valide",
    };

    const ouverture = await ouvrirCoffre(
      {
        titulaireId: "tit_01",
        usage: "fournisseur_a",
        entree: entreeD1,
        maitres: { 1: MAITRE_V1 },
      },
      async (clairInterne) => ({
        longueur: clairInterne.length,
        correspond: clairInterne === valeurSecrete,
      }),
    );

    expect(ouverture).toEqual({
      ok: true,
      provenance: "coffre",
      client: { longueur: valeurSecrete.length, correspond: true },
    });
  });

  it("échoue fermé si la ligne est recopiée sur un autre titulaire, un autre usage ou altérée (AAD GCM)", async () => {
    const scelle = await scellerCoffre("secret-fournisseur-1234567890", {
      titulaireId: "tit_source",
      usage: "fournisseur_a",
      version: 1,
      maitre: MAITRE_V1,
    });

    const entreeBase: LigneCoffre = {
      titulaireId: "tit_source",
      version: 1,
      iv: scelle.iv,
      chiffre: scelle.chiffre,
      repere: scelle.repere,
      etat: "valide",
    };

    // Copie vers un autre titulaire (même en falsifiant entree.titulaireId) : AAD échoue.
    const copieAutreTitulaire = await ouvrirCoffre(
      {
        titulaireId: "tit_cible",
        usage: "fournisseur_a",
        entree: { ...entreeBase, titulaireId: "tit_cible" },
        maitres: { 1: MAITRE_V1 },
      },
      (c) => c.length,
    );
    expect(copieAutreTitulaire).toEqual({ ok: false, motif: "INVALIDE" });

    // Mauvais usage : AAD + HKDF info échouent.
    const mauvaisUsage = await ouvrirCoffre(
      {
        titulaireId: "tit_source",
        usage: "fournisseur_b",
        entree: entreeBase,
        maitres: { 1: MAITRE_V1 },
      },
      (c) => c.length,
    );
    expect(mauvaisUsage).toEqual({ ok: false, motif: "INVALIDE" });

    // Octet altéré dans le chiffré : tag GCM échoue.
    const altere = new Uint8Array(scelle.chiffre);
    altere[0] = (altere[0] ?? 0) ^ 0xff;
    const tagInvalide = await ouvrirCoffre(
      {
        titulaireId: "tit_source",
        usage: "fournisseur_a",
        entree: { ...entreeBase, chiffre: altere },
        maitres: { 1: MAITRE_V1 },
      },
      (c) => c.length,
    );
    expect(tagInvalide).toEqual({ ok: false, motif: "INVALIDE" });
  });

  it("gère la rotation des clés maîtres V1 -> V2 et rejette les clés maîtres trop courtes", async () => {
    await expect(
      scellerCoffre("secret-fournisseur-1234567890", {
        titulaireId: "tit_1",
        usage: "fournisseur_a",
        version: 1,
        maitre: "trop-court",
      }),
    ).rejects.toThrow();

    const v2 = await scellerCoffre("secret-v2-fournisseur-123456", {
      titulaireId: "tit_1",
      usage: "fournisseur_a",
      version: 2,
      maitre: MAITRE_V2,
    });

    const anneau = { 1: MAITRE_V1, 2: MAITRE_V2 };
    const okV2 = await ouvrirCoffre(
      {
        titulaireId: "tit_1",
        usage: "fournisseur_a",
        entree: { ...v2, etat: "valide" },
        maitres: anneau,
      },
      (clair) => clair.startsWith("secret-v2-"),
    );
    expect(okV2).toEqual({ ok: true, provenance: "coffre", client: true });

    const versionManquante = await ouvrirCoffre(
      {
        titulaireId: "tit_1",
        usage: "fournisseur_a",
        entree: { ...v2, version: 3, etat: "valide" },
        maitres: anneau,
      },
      () => true,
    );
    expect(versionManquante).toEqual({ ok: false, motif: "INVALIDE" });
  });

  it("G8 & S11 : applique l'ordre strict surchargeEntete -> coffre -> ABSENTE / REFUSEE sans retombée", async () => {
    let fabriqueAppelee = false;
    const absente = await ouvrirCoffre(
      {
        titulaireId: "tit_sans_entree",
        usage: "fournisseur_a",
        entree: null,
        maitres: { 1: MAITRE_V1 },
      },
      () => {
        fabriqueAppelee = true;
        return "interdit";
      },
    );
    expect(absente).toEqual({ ok: false, motif: "ABSENTE" });
    expect(fabriqueAppelee).toBe(false);

    const scelle = await scellerCoffre("secret-revoque-1234567890", {
      titulaireId: "tit_rev",
      usage: "fournisseur_a",
      version: 1,
      maitre: MAITRE_V1,
    });
    const refusee = await ouvrirCoffre(
      {
        titulaireId: "tit_rev",
        usage: "fournisseur_a",
        entree: { ...scelle, etat: "refusee" },
        maitres: { 1: MAITRE_V1 },
      },
      () => {
        fabriqueAppelee = true;
        return "interdit";
      },
    );
    expect(refusee).toEqual({ ok: false, motif: "REFUSEE" });
    expect(fabriqueAppelee).toBe(false);

    // S11 : une surcharge d'en-tête client valide prime même si l'entrée du coffre est refusée.
    const surcharge = await ouvrirCoffre(
      {
        titulaireId: "tit_rev",
        usage: "fournisseur_a",
        entree: { ...scelle, etat: "refusee" },
        maitres: { 1: MAITRE_V1 },
        surchargeEntete: "surcharge-locale-directe",
      },
      (clair) => ({ estSurcharge: clair === "surcharge-locale-directe" }),
    );
    expect(surcharge).toEqual({
      ok: true,
      provenance: "entete",
      client: { estSurcharge: true },
    });

    // Une surcharge d'en-tête dépassant MAX_LONGUEUR_PORTEUR, vide/blanche ou { etat: "invalide" }
    // échoue fermé ("INVALIDE") sans jamais retomber sur le coffre :
    for (const mauvaiseSurcharge of ["x".repeat(600), "", "   ", { etat: "invalide" } as const]) {
      let appelee = false;
      const surchargeInvalide = await ouvrirCoffre(
        {
          titulaireId: "tit_rev",
          usage: "fournisseur_a",
          entree: { ...scelle, etat: "valide" },
          maitres: { 1: MAITRE_V1 },
          surchargeEntete: mauvaiseSurcharge,
        },
        () => {
          appelee = true;
          return "interdit";
        },
      );
      expect(surchargeInvalide).toEqual({ ok: false, motif: "INVALIDE" });
      expect(appelee).toBe(false);
    }

    // Une surcharge { etat: "absent" } retombe normalement sur le coffre valide :
    const surchargeAbsente = await ouvrirCoffre(
      {
        titulaireId: "tit_rev",
        usage: "fournisseur_a",
        entree: { ...scelle, etat: "valide" },
        maitres: { 1: MAITRE_V1 },
        surchargeEntete: { etat: "absent" },
      },
      (clair) => ({ clair }),
    );
    expect(surchargeAbsente).toEqual({
      ok: true,
      provenance: "coffre",
      client: { clair: "secret-revoque-1234567890" },
    });

    // Une surcharge { etat: "valide" } prime sans déchiffrer le coffre :
    const surchargeObjetValide = await ouvrirCoffre(
      {
        titulaireId: "tit_rev",
        usage: "fournisseur_a",
        entree: { ...scelle, etat: "refusee" },
        maitres: { 1: MAITRE_V1 },
        surchargeEntete: { etat: "valide", valeur: "clef-via-resultat-porteur" },
      },
      (clair) => ({ clair }),
    );
    expect(surchargeObjetValide).toEqual({
      ok: true,
      provenance: "entete",
      client: { clair: "clef-via-resultat-porteur" },
    });

    // Une exception levée par `fabrique` se propage à l'identique sur `coffre` et `entete`
    // (ne doit jamais être travestie en échec de déchiffrement "INVALIDE") :
    const valide = await scellerCoffre("secret-actif-1234567890", {
      titulaireId: "tit_ok",
      usage: "fournisseur_a",
      version: 1,
      maitre: MAITRE_V1,
    });
    await expect(
      ouvrirCoffre(
        {
          titulaireId: "tit_ok",
          usage: "fournisseur_a",
          entree: { ...valide, etat: "valide" },
          maitres: { 1: MAITRE_V1 },
        },
        async () => {
          throw new Error("Erreur amont HTTP 503");
        },
      ),
    ).rejects.toThrow("Erreur amont HTTP 503");
  });
});

describe("empreinteCoffre, repereCoffre à clé maître et expurger (G9)", () => {
  it("produit une empreinte HMAC identique entre collègues partageant une même clé, mais dépendante du maître et de l'usage (zéro oracle SHA-256 non salé)", async () => {
    const clePartagee = "cleApiCabinet16c"; // 16 caractères exacts
    const sha256Brut = await empreinte(clePartagee);

    const col1 = await scellerCoffre(clePartagee, {
      titulaireId: "tit_collegue_1",
      usage: "fournisseur_a",
      version: 1,
      maitre: MAITRE_V1,
    });
    const col2 = await scellerCoffre(clePartagee, {
      titulaireId: "tit_collegue_2",
      usage: "fournisseur_a",
      version: 2,
      maitre: MAITRE_V2,
      maitreEmpreinte: MAITRE_V1,
    });

    // Même empreinteClef et même repere (détection de doublon en console) mais chiffrés distincts :
    expect(col1.empreinteClef).toBe(col2.empreinteClef);
    expect(col1.repere).toBe(col2.repere);
    expect(Array.from(col1.chiffre)).not.toEqual(Array.from(col2.chiffre));

    // Ni empreinteClef ni le suffixe de repere ne dérivent d'un SHA-256 non salé :
    expect(col1.empreinteClef).not.toBe(sha256Brut);
    expect(col1.repere.endsWith(`#${sha256Brut.slice(0, 8)}`)).toBe(false);
    // Séparation de domaine entre empreinteClef et le tag #8 de repere :
    expect(col1.repere.endsWith(`#${col1.empreinteClef.slice(0, 8)}`)).toBe(false);

    // Changement d'usage ou de secret maître -> empreinte et repère complètement distincts :
    const autreUsage = await empreinteCoffre(clePartagee, {
      usage: "fournisseur_b",
      maitre: MAITRE_V1,
    });
    const autreMaitre = await empreinteCoffre(clePartagee, {
      usage: "fournisseur_a",
      maitre: MAITRE_V2,
    });
    expect(autreUsage).not.toBe(col1.empreinteClef);
    expect(autreMaitre).not.toBe(col1.empreinteClef);
  });

  it("resserre le masquage de repereCoffre (< 16 : 0 car., 16..23 : 2 derniers, >= 24 : 4 derniers, zéro préfixe)", async () => {
    const opts = { usage: "fournisseur_a", maitre: MAITRE_V1 };

    // < 16 caractères (incluant 12..15 car.) : aucun caractère en clair exposé
    for (const court of ["court123", "douzecar1234", "quinzecaractere"]) {
      const r = await repereCoffre(court, opts);
      expect(r).toMatch(/^••••#[0-9a-f]{8}$/);
      expect(r.slice(0, r.indexOf("#"))).toBe("••••");
    }

    // 16..23 caractères (clés d'API usuelles de 16 à 20 car.) : uniquement les 2 derniers caractères
    const seize = await repereCoffre("AbcdEfghIjklMn9z", opts);
    expect(seize).toMatch(/^••••9z#[0-9a-f]{8}$/);
    expect(seize).not.toContain("Abcd");
    expect(seize).not.toContain("Mn9z");

    const vingtTrois = await repereCoffre("123456789012345678901Xy", opts);
    expect(vingtTrois).toMatch(/^••••Xy#[0-9a-f]{8}$/);

    // >= 24 caractères : uniquement les 4 derniers caractères, jamais de préfixe
    const vingtQuatre = await repereCoffre("PrefixeSecret00000007890", opts);
    expect(vingtQuatre).toMatch(/^••••7890#[0-9a-f]{8}$/);
    expect(vingtQuatre).not.toContain("Pref");

    // Points de code Unicode hors BMP (paires de substitution UTF-16 jamais scindées) :
    const astral = await repereCoffre(`${"A".repeat(15)}🔑`, opts);
    expect(astral).toMatch(/^••••A🔑#[0-9a-f]{8}$/);

    await expect(repereCoffre("   ", opts)).rejects.toThrow();
    await expect(
      repereCoffre("valeur-valide-123456", { usage: "fournisseur_a", maitre: "trop-court" }),
    ).rejects.toThrow();
    await expect(
      empreinteCoffre("valeur-valide-123456", { usage: "invalide:deuxpoints", maitre: MAITRE_V1 }),
    ).rejects.toThrow();
  });

  it("expurge ?key=, api_key=, Bearer, X-Clef-*, /mcp/<jeton> (y compris préfixé oauth-) et /mcp/oauth/<jeton> sans toucher /mcp/server-card ni /mcp/oauth", () => {
    const jeton = frapperJeton();
    const jetonPrefixeOAuth = `oauth-${"A".repeat(37)}`;
    const secretExterne = "mon/secret+externe=42";
    const brut = [
      `GET https://exemple.test/mcp?key=${jeton}&api_key=CLEF123&code=CODE_OAUTH_SECRET`,
      `POST https://exemple.test/mcp/${jeton}/ suite`,
      `POST https://exemple.test/mcp/${jetonPrefixeOAuth}`,
      "POST https://exemple.test/mcp/oauth/JETON_COLLE_PAR_ERREUR",
      "GET https://exemple.test/mcp/server-card",
      "GET https://exemple.test/.well-known/mcp/server-card.json",
      "POST https://exemple.test/mcp/oauth",
      `Authorization: Bearer ${jeton}`,
      "Authorization: Bearer secret%2Favec%2Bpourcent",
      "Authorization: Bearer identifiant:secret_interne_99",
      "X-Clef-Externe: CLEF_ENTETE_999",
      `Erreur amont avec ${secretExterne} et ${encodeURIComponent(secretExterne)}`,
    ].join(" | ");

    const propre = expurger(brut, [secretExterne]);
    expect(propre).not.toContain(jeton);
    expect(propre).not.toContain(jetonPrefixeOAuth);
    expect(propre).not.toContain("JETON_COLLE_PAR_ERREUR");
    expect(propre).not.toContain("CODE_OAUTH_SECRET");
    expect(propre).not.toContain("secret%2Favec%2Bpourcent");
    expect(propre).not.toContain("%2Favec%2Bpourcent");
    expect(propre).not.toContain("secret_interne_99");
    expect(propre).not.toContain("CLEF_ENTETE_999");
    expect(propre).not.toContain("CLEF123");
    expect(propre).not.toContain(secretExterne);
    expect(propre).not.toContain(encodeURIComponent(secretExterne));
    expect(propre).toContain("/mcp/server-card");
    expect(propre).toContain("/.well-known/mcp/server-card.json");
    expect(propre).toContain("/mcp/oauth |");

    // Corps x-www-form-urlencoded débutant directement par un paramètre sensible (sans ? ni &) :
    const formulaireOAuth = expurger("code=CODE_INITIAL_SECRET&code_verifier=PKCE_SECRET_43");
    expect(formulaireOAuth).toBe("code=[EXPURGE]&code_verifier=[EXPURGE]");

    // Paramètres sensibles dont le nom est partiellement ou totalement encodé en pourcentage :
    const encodes = expurger(
      "GET https://exemple.test/mcp?%6bey=SECRET_ENC&foo=bar&%63ode=OAUTH_ENC&a%70i%5Fkey=API_ENC&%4BEY=SECRET_MAJ&%ZZ=invalide",
    );
    expect(encodes).not.toContain("SECRET_ENC");
    expect(encodes).not.toContain("OAUTH_ENC");
    expect(encodes).not.toContain("API_ENC");
    expect(encodes).not.toContain("SECRET_MAJ");
    expect(encodes).toContain("?%6bey=[EXPURGE]");
    expect(encodes).toContain("&foo=bar");
    expect(encodes).toContain("&%63ode=[EXPURGE]");
    expect(encodes).toContain("&a%70i%5Fkey=[EXPURGE]");
    expect(encodes).toContain("&%4BEY=[EXPURGE]");
    expect(encodes).toContain("&%ZZ=invalide");
  });
});
