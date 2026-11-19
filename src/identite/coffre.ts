/**
 * Coffre de secrets tiers chiffré par enveloppe (`HKDF-SHA256` + `AES-256-GCM`) et expurgation
 * des traces journalisables.
 *
 * Invariants appliqués (§5.1–§5.4, portes `G8`, `G9`, `G10`) :
 * - **Dérivation liée au titulaire et à l'usage** :
 *   `DEK = HKDF-SHA256(ikm = maitre_v{n}, salt = titulaireId, info = "${usage}/v1")`
 *   `chiffre = AES-256-GCM(DEK, iv_12o, clair, aad = "${titulaireId}:${usage}:${version}")`
 *   Une ligne recopiée d'un titulaire ou d'un usage à un autre échoue à l'authentification GCM.
 * - **Fermeture stricte sur le texte clair (`G10`)** : aucune fonction exportée ne renvoie la
 *   valeur déchiffrée ; `ouvrirCoffre` ne la livre qu'à la fabrique asynchrone le temps de
 *   construire le client, puis efface le tampon d'octets temporaire.
 * - **Zéro retombée implicite (`G8`)** : ordre strict `surchargeEntete` -> `coffre` -> `"ABSENTE"`
 *   (ou `"REFUSEE"` si l'entrée a été invalidée).
 */

import { MAX_LONGUEUR_PORTEUR, type ResultatPorteurEntete } from "./porteur";

/** Taille standard du vecteur d'initialisation AES-GCM : 96 bits (12 octets). */
export const LONGUEUR_IV_COFFRE = 12;

/** Longueur minimale exigée pour un secret maître de coffre (`COFFRE_MAITRE_V{n}`). */
export const LONGUEUR_MIN_MAITRE_COFFRE = 32;

export const ETATS_ENTREE_COFFRE = ["valide", "refusee", "inconnue"] as const;

export type EtatEntreeCoffre = (typeof ETATS_ENTREE_COFFRE)[number];

/** Anneau des secrets maîtres indexés par numéro de version (`1`, `2`, …). */
export type AnneauMaitresCoffre = Readonly<Record<number, string | undefined>>;

export type BinaireD1 = Uint8Array | ArrayBuffer | readonly number[];

/** Ligne chiffrée stockée en base D1 pour un titulaire et un usage donné. */
export interface LigneCoffre {
  readonly titulaireId: string;
  readonly version: number;
  readonly iv: BinaireD1;
  readonly chiffre: BinaireD1;
  readonly repere: string;
  readonly empreinteClef?: string;
  readonly etat: EtatEntreeCoffre;
}

/** Résultat prêt à persister produit par `scellerCoffre`. */
export interface EntreeCoffreScellee {
  readonly titulaireId: string;
  readonly usage: string;
  readonly version: number;
  readonly iv: Uint8Array;
  readonly chiffre: Uint8Array;
  readonly repere: string;
  readonly empreinteClef: string;
}

export interface OptionsEmpreinteCoffre {
  readonly usage: string;
  readonly maitre: string;
}

export interface OptionsScellementCoffre {
  readonly titulaireId: string;
  readonly usage: string;
  readonly version: number;
  readonly maitre: string;
  /**
   * Matériau maître optionnel dédié à `empreinteClef` et `repere` (par ex. `COFFRE_MAITRE_V1`
   * stable lors d'une rotation d'enveloppe vers `V2`). Par défaut : `maitre`.
   */
  readonly maitreEmpreinte?: string;
}

export type MotifEchecCoffre = "ABSENTE" | "REFUSEE" | "INVALIDE";

export interface SourceCoffre {
  readonly titulaireId: string;
  readonly usage: string;
  readonly entree: LigneCoffre | null | undefined;
  readonly maitres: AnneauMaitresCoffre;
  /** Variante zéro-connaissance fournie par en-tête client maîtrisé (prime sur le coffre, S11). */
  readonly surchargeEntete?: string | ResultatPorteurEntete | null;
}

export type ResultatOuvertureCoffre<T> =
  | {
      readonly ok: true;
      readonly client: T;
      readonly provenance: "entete" | "coffre";
    }
  | {
      readonly ok: false;
      readonly motif: MotifEchecCoffre;
    };

function validerIdentifiantContexte(valeur: string, champ: string): string {
  const propre = valeur.trim();
  if (propre.length === 0 || propre.length > 128 || propre.includes(":")) {
    throw new Error(`Paramètre de coffre « ${champ} » invalide.`);
  }
  return propre;
}

function construireDonneeAuthentifiee(
  titulaireId: string,
  usage: string,
  version: number,
): Uint8Array {
  return new TextEncoder().encode(`${titulaireId}:${usage}:${version}`);
}

async function deriverCleEnveloppe(
  maitreBrut: string,
  titulaireId: string,
  usage: string,
  operations: readonly ("encrypt" | "decrypt")[],
): Promise<CryptoKey> {
  const maitre = maitreBrut.trim();
  if (maitre.length < LONGUEUR_MIN_MAITRE_COFFRE) {
    throw new Error("Matériau maître du coffre absent ou trop court.");
  }
  const enc = new TextEncoder();
  const materiau = await crypto.subtle.importKey("raw", enc.encode(maitre), "HKDF", false, [
    "deriveKey",
  ]);
  return await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: enc.encode(titulaireId),
      info: enc.encode(`${usage}/v1`),
    },
    materiau,
    { name: "AES-GCM", length: 256 },
    false,
    [...operations],
  );
}

function normaliserBinaire(entree: BinaireD1): Uint8Array | null {
  if (entree instanceof Uint8Array) {
    return new Uint8Array(entree);
  }
  if (entree instanceof ArrayBuffer) {
    return new Uint8Array(entree);
  }
  if (Array.isArray(entree)) {
    for (const v of entree) {
      if (typeof v !== "number" || !Number.isInteger(v) || v < 0 || v > 255) return null;
    }
    return Uint8Array.from(entree);
  }
  return null;
}

async function calculerHmacCoffreHex(
  clairBrut: string,
  options: OptionsEmpreinteCoffre,
  domaine: "empreinte" | "repere",
): Promise<{ clair: string; hex: string }> {
  const clair = clairBrut.trim();
  if (clair.length === 0 || clair.length > MAX_LONGUEUR_PORTEUR) {
    throw new Error("Longueur de valeur de coffre hors bornes.");
  }
  const usage = validerIdentifiantContexte(options.usage, "usage");
  const maitre = options.maitre.trim();
  if (maitre.length < LONGUEUR_MIN_MAITRE_COFFRE) {
    throw new Error("Matériau maître du coffre absent ou trop court.");
  }

  const enc = new TextEncoder();
  const materiau = await crypto.subtle.importKey("raw", enc.encode(maitre), "HKDF", false, [
    "deriveKey",
  ]);
  const cleHmac = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: enc.encode("coffre-hmac/v1"),
      info: enc.encode(`${usage}/${domaine}-v1`),
    },
    materiau,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    false,
    ["sign"],
  );

  const octetsClairs = enc.encode(clair);
  try {
    const sig = await crypto.subtle.sign("HMAC", cleHmac, octetsClairs);
    const hex = Array.from(new Uint8Array(sig))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    return { clair, hex };
  } finally {
    octetsClairs.fill(0);
  }
}

/**
 * Calcule l'empreinte non réversible à clé secrète (`HMAC-SHA256` dérivé par `HKDF-SHA256` du
 * secret maître et de `usage`, indépendamment de `titulaireId`) stockée dans
 * `coffre_clef.empreinte_clef` pour détecter les doublons inter-comptes en console sans jamais
 * offrir d'oracle de recherche exhaustive hors ligne sur une extraction D1.
 */
export async function empreinteCoffre(
  clairBrut: string,
  options: OptionsEmpreinteCoffre,
): Promise<string> {
  const { hex } = await calculerHmacCoffreHex(clairBrut, options, "empreinte");
  return hex;
}

/**
 * Construit un repère visuel non réversible à clé secrète (`HMAC-SHA256` dérivé du secret maître
 * et de `usage`, séparé par domaine de `empreinteCoffre`) sans jamais exposer de préfixe ni de
 * condensé non salé :
 * - `< 16` caractères : `••••#<8 hex HMAC>` (zéro caractère clair exposé) ;
 * - `16..23` caractères : `••••<2 derniers>#<8 hex HMAC>` ;
 * - `>= 24` caractères : `••••<4 derniers>#<8 hex HMAC>`.
 */
export async function repereCoffre(
  clairBrut: string,
  options: OptionsEmpreinteCoffre,
): Promise<string> {
  const { clair, hex } = await calculerHmacCoffreHex(clairBrut, options, "repere");
  const hmac8 = hex.slice(0, 8);
  const points = Array.from(clair);
  if (points.length < 16) {
    return `••••#${hmac8}`;
  }
  if (points.length < 24) {
    return `••••${points.slice(-2).join("")}#${hmac8}`;
  }
  return `••••${points.slice(-4).join("")}#${hmac8}`;
}

/**
 * Chiffre une valeur sensible sous enveloppe `HKDF-SHA256` + `AES-256-GCM` avec donnée
 * additionnelle authentifiée liée à `titulaireId`, `usage` et `version`, et calcule son repère
 * masqué ainsi que son empreinte HMAC à clé maître (`empreinteClef`).
 */
export async function scellerCoffre(
  clairBrut: string,
  options: OptionsScellementCoffre,
): Promise<EntreeCoffreScellee> {
  const clair = clairBrut.trim();
  if (clair.length === 0 || clair.length > MAX_LONGUEUR_PORTEUR) {
    throw new Error("Longueur de valeur à sceller hors bornes.");
  }
  if (!Number.isInteger(options.version) || options.version < 1) {
    throw new Error("Version de coffre invalide.");
  }
  const titulaireId = validerIdentifiantContexte(options.titulaireId, "titulaireId");
  const usage = validerIdentifiantContexte(options.usage, "usage");
  const secretEmpreinte = options.maitreEmpreinte ?? options.maitre;

  const dek = await deriverCleEnveloppe(options.maitre, titulaireId, usage, ["encrypt"]);
  const iv = new Uint8Array(LONGUEUR_IV_COFFRE);
  crypto.getRandomValues(iv);
  const aad = construireDonneeAuthentifiee(titulaireId, usage, options.version);
  const octetsClairs = new TextEncoder().encode(clair);

  try {
    const [tamponChiffre, repere, empreinteClef] = await Promise.all([
      crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad }, dek, octetsClairs),
      repereCoffre(clair, { usage, maitre: secretEmpreinte }),
      empreinteCoffre(clair, { usage, maitre: secretEmpreinte }),
    ]);
    return {
      titulaireId,
      usage,
      version: options.version,
      iv,
      chiffre: new Uint8Array(tamponChiffre),
      repere,
      empreinteClef,
    };
  } finally {
    octetsClairs.fill(0);
  }
}

/**
 * Résout et instancie un client consommateur sans jamais exposer le texte clair hors de la
 * fermeture `fabrique` (`G8`, `G10`).
 */
export async function ouvrirCoffre<T>(
  source: SourceCoffre,
  fabrique: (clair: string) => T | Promise<T>,
): Promise<ResultatOuvertureCoffre<T>> {
  if (source.surchargeEntete !== null && source.surchargeEntete !== undefined) {
    if (typeof source.surchargeEntete === "string") {
      const surcharge = source.surchargeEntete.trim();
      if (surcharge.length === 0 || surcharge.length > MAX_LONGUEUR_PORTEUR) {
        return { ok: false, motif: "INVALIDE" };
      }
      const client = await fabrique(surcharge);
      return { ok: true, client, provenance: "entete" };
    }
    if (source.surchargeEntete.etat === "invalide") {
      return { ok: false, motif: "INVALIDE" };
    }
    if (source.surchargeEntete.etat === "valide") {
      const surcharge = source.surchargeEntete.valeur.trim();
      if (surcharge.length === 0 || surcharge.length > MAX_LONGUEUR_PORTEUR) {
        return { ok: false, motif: "INVALIDE" };
      }
      const client = await fabrique(surcharge);
      return { ok: true, client, provenance: "entete" };
    }
  }

  const entree = source.entree;
  if (!entree) {
    return { ok: false, motif: "ABSENTE" };
  }
  if (entree.etat === "refusee") {
    return { ok: false, motif: "REFUSEE" };
  }
  if (entree.etat !== "valide" && entree.etat !== "inconnue") {
    return { ok: false, motif: "INVALIDE" };
  }

  let titulaireId: string;
  let usage: string;
  try {
    titulaireId = validerIdentifiantContexte(source.titulaireId, "titulaireId");
    usage = validerIdentifiantContexte(source.usage, "usage");
  } catch {
    return { ok: false, motif: "INVALIDE" };
  }

  if (entree.titulaireId !== titulaireId) {
    return { ok: false, motif: "INVALIDE" };
  }
  if (!Number.isInteger(entree.version) || entree.version < 1) {
    return { ok: false, motif: "INVALIDE" };
  }
  if (!Object.hasOwn(source.maitres, entree.version)) {
    return { ok: false, motif: "INVALIDE" };
  }
  const maitre = source.maitres[entree.version];
  if (typeof maitre !== "string" || maitre.trim().length < LONGUEUR_MIN_MAITRE_COFFRE) {
    return { ok: false, motif: "INVALIDE" };
  }

  const iv = normaliserBinaire(entree.iv);
  const chiffre = normaliserBinaire(entree.chiffre);
  if (!iv || iv.byteLength !== LONGUEUR_IV_COFFRE || !chiffre || chiffre.byteLength <= 16) {
    return { ok: false, motif: "INVALIDE" };
  }

  let clairDechiffre: string;
  let octetsClairs: Uint8Array | null = null;
  try {
    const dek = await deriverCleEnveloppe(maitre, titulaireId, usage, ["decrypt"]);
    const aad = construireDonneeAuthentifiee(titulaireId, usage, entree.version);
    const ivCopie = new Uint8Array(iv.byteLength);
    ivCopie.set(iv);
    const chiffreCopie = new Uint8Array(chiffre.byteLength);
    chiffreCopie.set(chiffre);
    const tampon = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: ivCopie, additionalData: aad },
      dek,
      chiffreCopie,
    );
    octetsClairs = new Uint8Array(tampon);
    clairDechiffre = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(
      octetsClairs,
    );
    if (clairDechiffre.length === 0 || clairDechiffre.length > MAX_LONGUEUR_PORTEUR) {
      return { ok: false, motif: "INVALIDE" };
    }
  } catch {
    return { ok: false, motif: "INVALIDE" };
  } finally {
    if (octetsClairs) octetsClairs.fill(0);
  }

  const client = await fabrique(clairDechiffre);
  return { ok: true, client, provenance: "coffre" };
}

const PARAMS_SENSIBLES_URL = new Set([
  "key",
  "api_key",
  "apikey",
  "access_token",
  "refresh_token",
  "client_secret",
  "code_verifier",
  "code",
  "token",
]);
const MOTIF_PARAM_URL = /((?:^|[?&])([^=?&#\s"'/]+)=)[^&#\s"']+/g;
const MOTIF_BEARER = /(\bBearer\s+)[^\s,;|"'<>]+/gi;
const MOTIF_ENTETE_SENSIBLE =
  /(\b(?:x-(?:clef|api-key)[A-Za-z0-9-]*|authorization)\s*:\s*)(?!Bearer\b|\[EXPURGE\])[^\r\n,;|"']+/gi;
const MOTIF_SEGMENT_OAUTH_MCP = /(\/mcp\/oauth\/)[^/?#\s"']+/gi;
const MOTIF_SEGMENT_MCP = /(\/mcp\/)(?!(?:server-card|oauth)(?:[/?#\s"']|$))[^/?#\s"']+/gi;

function expurgerParamsUrl(texte: string): string {
  return texte.replace(MOTIF_PARAM_URL, (correspondance, prefixe: string, nomBrut: string) => {
    let nomDecode = nomBrut;
    try {
      nomDecode = decodeURIComponent(nomBrut);
    } catch {
      // Séquence de pourcentage mal formée : comparer le nom brut tel quel.
    }
    return PARAMS_SENSIBLES_URL.has(nomDecode.toLowerCase())
      ? `${prefixe}[EXPURGE]`
      : correspondance;
  });
}

/**
 * Expurge les paramètres d'authentification d'URL (`?key=`, `api_key=`, `token=`, `code=`, etc.,
 * y compris lorsque le nom du paramètre est encodé en pourcentage), les en-têtes `Bearer` et
 * `X-Clef-*`, les segments `/mcp/<jeton>` ou `/mcp/oauth/<jeton>` ainsi que toute chaîne sensible
 * fournie explicitement (`G9`).
 */
export function expurger(texte: string, valeursSensibles: readonly string[] = []): string {
  let sortie = expurgerParamsUrl(texte)
    .replace(MOTIF_BEARER, "$1[EXPURGE]")
    .replace(MOTIF_ENTETE_SENSIBLE, "$1[EXPURGE]")
    .replace(MOTIF_SEGMENT_OAUTH_MCP, "$1[EXPURGE]")
    .replace(MOTIF_SEGMENT_MCP, "$1[EXPURGE]");

  for (const secret of valeursSensibles) {
    if (typeof secret !== "string") continue;
    const s = secret.trim();
    if (s.length < 4) continue;
    sortie = sortie.split(s).join("[EXPURGE]");
    const encode = encodeURIComponent(s);
    if (encode !== s) {
      sortie = sortie.split(encode).join("[EXPURGE]");
    }
  }
  return sortie;
}
