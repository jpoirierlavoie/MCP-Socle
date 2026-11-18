/**
 * Gouverne à deux étages (débit d'arête adapté aux rafales Deep Research + quotas journaliers D1
 * par classe d'outil) et télémétrie technique strictement dépourvue de contenu (`S13`, `S15`,
 * `S20`, portes `G13`, `G16`, `G25`, `G32`).
 *
 * Particularité Deep Research (`S15` + §2.1) :
 * - Les agents autonomes de recherche approfondie (`claude.ai`, `gemini.google.com`, API Deep
 *   Research) émettent leurs rafales depuis des adresses IP de sortie infonuagiques partagées.
 * - `verifierDebitPreAuth` n'applique en amont de D1 qu'une quarantaine locale des IP ayant déjà
 *   franchi le seuil d'ÉCHECS d'authentification ainsi qu'un plafond de rafale brute par IP élevé
 *   (ex. 600/min), tandis que `enregistrerEchecAuth` n'impute le compteur d'échecs IP (ex. 20/min)
 *   et le disjoncteur global `"echecs"` (ex. 300/min) QUE lorsque l'authentification échoue.
 *   Ainsi, le trafic authentifié légitime ne pénalise jamais l'adresse IP partagée.
 */

import { debitAcceptable, type Limiteur } from "../protocole/http";
import { clientLisible, type InfoClient } from "../protocole/meta";
import { err, type ToolResult } from "../protocole/rpc";
import { porteesCanoniques } from "./oauth";
import { empreinte, MAX_LONGUEUR_PORTEUR } from "./porteur";
import { tropDeRequetes } from "./refus";
import type { BaseD1Minimale, EtatTitulaireServi } from "./titulaire";

// ── Modes d'admission du portail (ouverture par cohorte puis file régulière) ────────────

export const MODES_ADMISSION = ["ferme", "invitation", "ouvert"] as const;

export type ModeAdmission = (typeof MODES_ADMISSION)[number];

/** Mode d'admission recommandé au déploiement initial par cohorte contrôlée. */
export const MODE_ADMISSION_PAR_DEFAUT: ModeAdmission = "invitation";

/**
 * Résout le mode d'admission configuré (`MODE_ADMISSION`).
 *
 * Fermé par défaut : toute valeur absente, non textuelle ou inconnue retombe sur `"ferme"`.
 */
export function resoudreModeAdmission(brut: unknown): ModeAdmission {
  if (typeof brut !== "string") return "ferme";
  const propre = brut.trim().toLowerCase();
  if (propre === "ferme" || propre === "invitation" || propre === "ouvert") {
    return propre;
  }
  return "ferme";
}

// ── Classes d'outils et quotas journaliers (S20 : source unique de vérité) ──────────────

export const CLASSES_OUTIL = ["local", "sortant", "semantique"] as const;

export type ClasseOutil = (typeof CLASSES_OUTIL)[number];

export type PlafondsQuotas = Readonly<Record<ClasseOutil, number>>;

/**
 * Quotas journaliers UTC par défaut pour un titulaire `actif` ou `surveille`.
 * Dimensionnés pour absorber plusieurs sessions de recherche approfondie multi-étapes par jour
 * tout en protégeant les appels API sortants (`200/jour`) et vectoriels (`150/jour`).
 */
export const QUOTAS_ACTIF_PAR_DEFAUT: PlafondsQuotas = {
  local: 1_500,
  sortant: 200,
  semantique: 150,
} as const;

/** Quotas journaliers UTC réduits pour un titulaire placé à l'état `limite`. */
export const QUOTAS_LIMITE_PAR_DEFAUT: PlafondsQuotas = {
  local: 150,
  sortant: 20,
  semantique: 15,
} as const;

export type CompteursJour = Readonly<Partial<Record<ClasseOutil, number>>>;

export type VerdictQuotaJour =
  | {
      readonly autorise: true;
      readonly classe: ClasseOutil;
      readonly utilise: number;
      readonly plafond: number;
      readonly restant: number;
    }
  | {
      readonly autorise: false;
      readonly code: "QUOTA_EPUISE";
      readonly classe: ClasseOutil;
      readonly utilise: number;
      readonly plafond: number;
    };

/** Renvoie la grille de plafonds journaliers applicable à l'état du titulaire. */
export function plafondsPourEtat(
  etat: EtatTitulaireServi,
  surcharges?: { actif?: Partial<PlafondsQuotas>; limite?: Partial<PlafondsQuotas> },
): PlafondsQuotas {
  if (etat === "limite") {
    return { ...QUOTAS_LIMITE_PAR_DEFAUT, ...(surcharges?.limite ?? {}) };
  }
  return { ...QUOTAS_ACTIF_PAR_DEFAUT, ...(surcharges?.actif ?? {}) };
}

/**
 * Vérifie le quota journalier d'une classe d'outil une fois le nom d'outil extrait du CORPS
 * JSON-RPC (§4.3 marche 11 : ne jamais décider sur l'en-tête `Mcp-Name` seul).
 */
export function verifierQuotaJour(
  compteurs: CompteursJour,
  classe: ClasseOutil,
  etat: EtatTitulaireServi,
  surcharges?: { actif?: Partial<PlafondsQuotas>; limite?: Partial<PlafondsQuotas> },
): VerdictQuotaJour {
  const plafonds = plafondsPourEtat(etat, surcharges);
  const plafond = plafonds[classe];
  const brut = Object.hasOwn(compteurs, classe) ? compteurs[classe] : 0;
  const utilise = typeof brut === "number" && Number.isFinite(brut) && brut > 0 ? brut : 0;

  if (utilise >= plafond) {
    return {
      autorise: false,
      code: "QUOTA_EPUISE",
      classe,
      utilise,
      plafond,
    };
  }

  return {
    autorise: true,
    classe,
    utilise,
    plafond,
    restant: plafond - utilise,
  };
}

/**
 * Construit l'erreur d'outil MCP (`HTTP 200`, `isError: true`) retournée au modèle lorsque le
 * quota journalier d'une classe est atteint (§4.3 marche 11).
 */
export function erreurQuotaEpuise(classe: ClasseOutil, plafond: number): ToolResult {
  return err(
    `[QUOTA_EPUISE] Le quota journalier UTC pour la classe d'outils « ${classe} » (${plafond} appels/jour) est atteint pour ce compte. Les compteurs sont réinitialisés à 00:00 UTC.`,
  );
}

// ── Étage 1 : limitation de débit d'arête compatible Deep Research (A1, S15, G32) ───────

/** Capacité bornée de la table de quarantaine IP en mémoire d'isolat (éviction FIFO). */
export const MAX_ENTREES_QUARANTAINE_IP = 4_096;

/** Durée par défaut de quarantaine locale d'une IP ayant saturé le budget d'échecs : 60 s. */
export const DUREE_QUARANTAINE_IP_MS = 60_000;

/**
 * Durée par défaut du laissez-passer pré-D1 d'une empreinte SHA-256 récemment authentifiée,
 * protégeant les sessions actives sur IP de sortie infonuagiques partagées (`S15`) sans jamais
 * court-circuiter la vérification D1 elle-même (`ouvrirPrincipal`).
 */
export const DUREE_LAISSEZ_PASSER_EMPREINTE_MS = 300_000;

/** Clé constante du disjoncteur global d'échecs d'authentification (§6.1). */
export const CLE_DISJONCTEUR_ECHECS = "echecs";

export interface QuarantaineIpEchecs {
  estEnQuarantaine(ip: string, maintenantMs?: number): boolean;
  placerEnQuarantaine(ip: string, maintenantMs?: number): void;
  marquerEmpreinteValide(empreinteHex: string, maintenantMs?: number): void;
  retirerEmpreinteValide(empreinteHex: string): void;
  estEmpreinteValideConnue(empreinteHex: string, maintenantMs?: number): boolean;
  taille(): number;
}

/**
 * Crée un cache borné en mémoire d'isolat consignant d'une part les adresses IP qui ont franchi le
 * seuil d'échecs d'authentification (pour couper leurs essais inconnus AVANT toute lecture D1, `G32`)
 * et d'autre part les empreintes SHA-256 récemment validées afin qu'un abus collatéral sur une IP
 * infonuagique partagée (`claude.ai`, `gemini.google.com`) n'interrompe jamais la session d'un
 * titulaire légitime (`S15`).
 */
export function creerQuarantaineIpEchecs(
  options: {
    maxEntrees?: number;
    dureeMs?: number;
    maxEmpreintesValides?: number;
    dureeEmpreinteValideMs?: number;
  } = {},
): QuarantaineIpEchecs {
  const maxEntrees = options.maxEntrees ?? MAX_ENTREES_QUARANTAINE_IP;
  const dureeMs = options.dureeMs ?? DUREE_QUARANTAINE_IP_MS;
  const maxValides = options.maxEmpreintesValides ?? MAX_ENTREES_QUARANTAINE_IP;
  const dureeValideMs = options.dureeEmpreinteValideMs ?? DUREE_LAISSEZ_PASSER_EMPREINTE_MS;
  const expirations = new Map<string, number>();
  const empreintesValides = new Map<string, number>();

  return {
    estEnQuarantaine(ip: string, maintenantMs = Date.now()): boolean {
      const cle = ip.trim() || "sans-ip";
      const exp = expirations.get(cle);
      if (exp === undefined) return false;
      if (exp <= maintenantMs) {
        expirations.delete(cle);
        return false;
      }
      return true;
    },
    placerEnQuarantaine(ip: string, maintenantMs = Date.now()): void {
      const cle = ip.trim() || "sans-ip";
      if (expirations.has(cle)) {
        expirations.delete(cle);
      } else if (expirations.size >= maxEntrees) {
        const plusAncienne = expirations.keys().next().value;
        if (plusAncienne !== undefined) expirations.delete(plusAncienne);
      }
      expirations.set(cle, maintenantMs + dureeMs);
    },
    marquerEmpreinteValide(empreinteHex: string, maintenantMs = Date.now()): void {
      const cle = empreinteHex.trim().toLowerCase();
      if (!/^[0-9a-f]{64}$/.test(cle)) return;
      if (empreintesValides.has(cle)) {
        empreintesValides.delete(cle);
      } else if (empreintesValides.size >= maxValides) {
        const plusAncienne = empreintesValides.keys().next().value;
        if (plusAncienne !== undefined) empreintesValides.delete(plusAncienne);
      }
      empreintesValides.set(cle, maintenantMs + dureeValideMs);
    },
    retirerEmpreinteValide(empreinteHex: string): void {
      const cle = empreinteHex.trim().toLowerCase();
      empreintesValides.delete(cle);
    },
    estEmpreinteValideConnue(empreinteHex: string, maintenantMs = Date.now()): boolean {
      const cle = empreinteHex.trim().toLowerCase();
      const exp = empreintesValides.get(cle);
      if (exp === undefined) return false;
      if (exp <= maintenantMs) {
        empreintesValides.delete(cle);
        return false;
      }
      return true;
    },
    taille(): number {
      return expirations.size;
    },
  };
}

export interface OptionsDebitPreAuth {
  ip: string;
  /** Quarantaine mémoire des IP ayant franchi le seuil d'échecs d'authentification. */
  quarantaine?: QuarantaineIpEchecs;
  /** Plafond grossier de rafale pré-D1 par IP (ex. 600/min, couvrant les sorties cloud). */
  limiteurRafaleIp?: Limiteur;
  /**
   * Porteurs candidats extraits de la requête : si l'un correspond à une empreinte SHA-256
   * récemment validée, la requête franchit la quarantaine IP pour être vérifiée normalement en D1.
   */
  candidatsJetons?: readonly string[];
  maintenantMs?: number;
}

/**
 * Nombre maximal de porteurs candidats inspectés lors du contrôle pré-D1 d'empreinte connue
 * (couvre `Bearer`, `?key=` et les variantes d'encodage de chemin, tant pour les jetons `frapperJeton`
 * de 43 car. que pour les secrets partagés transitoires / CI de 64 car. hexadécimaux).
 */
export const MAX_CANDIDATS_PORTEUR_PREAUTH = 8;

async function porteEmpreinteConnue(
  quarantaine: QuarantaineIpEchecs | undefined,
  candidats: readonly string[] | undefined,
  maintenantMs: number | undefined,
): Promise<boolean> {
  if (!quarantaine || !candidats || candidats.length === 0) return false;
  const vus = new Set<string>();
  for (const c of candidats) {
    if (typeof c !== "string" || c.length === 0 || c.length > MAX_LONGUEUR_PORTEUR) continue;
    if (vus.has(c)) continue;
    vus.add(c);
    const hash = await empreinte(c);
    if (quarantaine.estEmpreinteValideConnue(hash, maintenantMs)) return true;
    if (vus.size >= MAX_CANDIDATS_PORTEUR_PREAUTH) break;
  }
  return false;
}

/**
 * Garde pré-authentification exécutée AVANT toute lecture D1 (`G32`, `S15`).
 *
 * Renvoie `false` si l'IP est en quarantaine d'échecs ou dépasse le plafond brut de rafale, SAUF
 * lorsque le porteur soumis correspond à une empreinte SHA-256 récemment authentifiée sur l'isolat
 * (laquelle poursuivra néanmoins son contrôle complet de révocation/état dans `ouvrirPrincipal`).
 */
export async function verifierDebitPreAuth(options: OptionsDebitPreAuth): Promise<boolean> {
  const ip = options.ip.trim() || "sans-ip";
  const enQuarantaine = options.quarantaine?.estEnQuarantaine(ip, options.maintenantMs) ?? false;
  if (enQuarantaine) {
    return await porteEmpreinteConnue(
      options.quarantaine,
      options.candidatsJetons,
      options.maintenantMs,
    );
  }
  const rafaleOk = await debitAcceptable(options.limiteurRafaleIp, ip);
  if (!rafaleOk) {
    return await porteEmpreinteConnue(
      options.quarantaine,
      options.candidatsJetons,
      options.maintenantMs,
    );
  }
  return true;
}

export interface OptionsEchecAuth {
  ip: string;
  quarantaine?: QuarantaineIpEchecs;
  /** Limiteur d'arête strict sur les ÉCHECS par IP (ex. 20/min). */
  limiteurEchecIp?: Limiteur;
  /** Disjoncteur global d'échecs distribués sur clé constante `"echecs"` (ex. 300/min). */
  limiteurEchecsGlobal?: Limiteur;
  /**
   * Porteurs soumis lors de l'échec : toute empreinte SHA-256 correspondante est immédiatement
   * évincée du laissez-passer pré-D1 afin qu'un jeton compromis/révoqué ne contourne plus la
   * quarantaine IP (`G32`).
   */
  candidatsJetons?: readonly string[];
  maintenantMs?: number;
}

/**
 * Enregistre un ÉCHEC d'authentification : évince immédiatement les porteurs soumis du
 * laissez-passer d'empreintes actives, puis incrémente le compteur d'échecs de l'IP appelante
 * (et la place en quarantaine pré-D1 si le seuil de 20/min est franchi) ainsi que le disjoncteur
 * global `"echecs"`. N'est JAMAIS appelée sur une requête authentifiée avec succès (`S15`).
 */
export async function enregistrerEchecAuth(options: OptionsEchecAuth): Promise<{
  ipQuarantaine: boolean;
  disjoncteurGlobal: boolean;
}> {
  if (options.quarantaine && options.candidatsJetons && options.candidatsJetons.length > 0) {
    const vus = new Set<string>();
    for (const c of options.candidatsJetons) {
      if (typeof c !== "string" || c.length === 0 || c.length > MAX_LONGUEUR_PORTEUR) continue;
      if (vus.has(c)) continue;
      vus.add(c);
      options.quarantaine.retirerEmpreinteValide(await empreinte(c));
      if (vus.size >= MAX_CANDIDATS_PORTEUR_PREAUTH) break;
    }
  }
  const ip = options.ip.trim() || "sans-ip";
  const [ipOk, globalOk] = await Promise.all([
    debitAcceptable(options.limiteurEchecIp, ip),
    debitAcceptable(options.limiteurEchecsGlobal, CLE_DISJONCTEUR_ECHECS),
  ]);
  if (!ipOk) {
    options.quarantaine?.placerEnQuarantaine(ip, options.maintenantMs);
  }
  return {
    ipQuarantaine: !ipOk,
    disjoncteurGlobal: !globalOk,
  };
}

export interface OptionsDebitTitulaire {
  titulaireId: string;
  etat: EtatTitulaireServi;
  limiteurActif?: Limiteur;
  limiteurLimite?: Limiteur;
  origin?: string | null;
  retryAfterActifSec?: number;
  retryAfterLimiteSec?: number;
}

/**
 * Contrôle le débit d'arête post-authentification par `titulaireId` (jamais par IP, `S15`).
 *
 * Renvoie `null` lorsque le débit est accepté, ou une `Response` HTTP `429` + `Retry-After`.
 */
export async function verifierDebitTitulaire(
  options: OptionsDebitTitulaire,
): Promise<Response | null> {
  const estLimite = options.etat === "limite";
  const limiteur = estLimite ? options.limiteurLimite : options.limiteurActif;
  const retryAfter = estLimite
    ? (options.retryAfterLimiteSec ?? 300)
    : (options.retryAfterActifSec ?? 60);
  const ok = await debitAcceptable(limiteur, options.titulaireId);
  return ok ? null : tropDeRequetes(retryAfter, options.origin ?? null);
}

// ── Télémétrie technique sans contenu et durées de rétention (S13, S20, G13, G16, G18, G25)

/** Durée de conservation impérative de `evenement_technique` : 90 jours (§7.1). */
export const RETENTION_EVENEMENTS_JOURS = 90;

/** Durée de conservation impérative de `compteur_jour` : 90 jours (§4 / §10). */
export const RETENTION_COMPTEURS_JOURS = 90;

/** Durée de validité d'une demande d'admission non confirmée (`demande_acces`) : 30 minutes. */
export const DUREE_DEMANDE_ACCES_MINUTES = 30;

/** Durée de validité d'un lien à usage unique (`session_portail` hors session active) : 30 minutes. */
export const DUREE_LIEN_PORTAIL_MINUTES = 30;

/** Durée de validité d'une session interactive `/moi` (`session_portail.type_lien = 'session_moi'`) : 12 h. */
export const DUREE_SESSION_MOI_HEURES = 12;

/** Durée de validité maximale d'un code d'autorisation OAuth 2.1 (`code_oauth`) : 300 secondes. */
export const DUREE_CODE_OAUTH_SECONDES = 300;

export const ISSUES_TECHNIQUES = [
  "ok",
  "introuvable",
  "erreur_usager",
  "erreur_amont",
  "refus",
  "quota",
] as const;

export type IssueTechnique = (typeof ISSUES_TECHNIQUES)[number];

export const CODES_ERREUR_TECHNIQUES = [
  "ARGUMENTS_INVALIDES",
  "OUTIL_INCONNU",
  "CLEF_ABSENTE",
  "CLEF_REFUSEE",
  "QUOTA_EPUISE",
  "HORS_SERVICE",
  "AMONT_HORS_SERVICE",
  "AMONT_ERREUR",
  "HYBRIDE_DESACTIVE",
  "ERREUR_INTERNE",
] as const;

export type CodeErreurTechnique = (typeof CODES_ERREUR_TECHNIQUES)[number];

/** Format UTC au jour (`AAAA-MM-JJ`), sans heure. */
export function jourUtc(date = new Date()): string {
  return date.toISOString().slice(0, 10);
}

/** Format UTC à la minute (`AAAA-MM-JJTHH:MM`), jamais à la seconde (§7.1). */
export function minuteUtc(date = new Date()): string {
  return date.toISOString().slice(0, 16);
}

/**
 * Format ISO 8601 UTC canonique (`AAAA-MM-JJTHH:MM:SS.sssZ`, 24 caractères) garantissant que
 * l'ordre lexicographique des index B-tree SQLite (`expire_le <= ?1`) coïncide avec l'ordre
 * chronologique exact.
 */
export function horodatageIsoUtc(date = new Date()): string {
  return date.toISOString();
}

export interface EntreeEvenementTechnique {
  readonly titulaireId: string;
  readonly jetonId: string;
  readonly service: string;
  readonly horodatage?: Date;
  readonly outil: string;
  readonly classe: ClasseOutil;
  readonly issue: IssueTechnique;
  readonly code?: CodeErreurTechnique;
  readonly ms?: number;
  readonly sortants?: number;
  readonly clientInfo?: InfoClient;
}

export interface EvenementTechnique {
  readonly titulaire_id: string;
  readonly jeton_id: string;
  readonly service: string;
  readonly minute: string;
  readonly outil: string;
  readonly classe: ClasseOutil;
  readonly issue: IssueTechnique;
  readonly code: CodeErreurTechnique | null;
  readonly ms: number | null;
  readonly sortants: number;
  readonly client: string | null;
}

const MOTIF_IDENTIFIANT_SUR = /^[A-Za-z0-9_.:-]{1,80}$/;

function nettoyerClient(info?: InfoClient): string | null {
  const brut = clientLisible(info);
  if (!brut) return null;
  let propre = "";
  for (let i = 0; i < brut.length && propre.length < 120; i++) {
    const code = brut.charCodeAt(i);
    if (code >= 0x20 && code !== 0x7f) propre += brut[i];
  }
  return propre.length > 0 ? propre : null;
}

/**
 * Construit et valide un enregistrement `EvenementTechnique` garanti sans texte libre de requête
 * (`S13` porté par le type et vérifié à l'exécution).
 */
export function formaterEvenementTechnique(entree: EntreeEvenementTechnique): EvenementTechnique {
  if (
    !MOTIF_IDENTIFIANT_SUR.test(entree.titulaireId) ||
    !MOTIF_IDENTIFIANT_SUR.test(entree.jetonId) ||
    !MOTIF_IDENTIFIANT_SUR.test(entree.service) ||
    !MOTIF_IDENTIFIANT_SUR.test(entree.outil)
  ) {
    throw new Error("Identifiant d'événement technique hors format autorisé.");
  }
  if (!(CLASSES_OUTIL as readonly string[]).includes(entree.classe)) {
    throw new Error("Classe d'outil inconnue.");
  }
  if (!(ISSUES_TECHNIQUES as readonly string[]).includes(entree.issue)) {
    throw new Error("Issue technique inconnue.");
  }
  if (
    entree.code !== undefined &&
    !(CODES_ERREUR_TECHNIQUES as readonly string[]).includes(entree.code)
  ) {
    throw new Error("Code d'erreur technique hors énumération fermée.");
  }

  const ms =
    typeof entree.ms === "number" && Number.isFinite(entree.ms) && entree.ms >= 0
      ? Math.round(entree.ms)
      : null;
  const sortants =
    typeof entree.sortants === "number" && Number.isFinite(entree.sortants) && entree.sortants > 0
      ? Math.round(entree.sortants)
      : 0;

  return {
    titulaire_id: entree.titulaireId,
    jeton_id: entree.jetonId,
    service: entree.service,
    minute: minuteUtc(entree.horodatage ?? new Date()),
    outil: entree.outil,
    classe: entree.classe,
    issue: entree.issue,
    code: entree.code ?? null,
    ms,
    sortants,
    client: nettoyerClient(entree.clientInfo),
  };
}

const SQL_LIRE_COMPTEURS_JOUR = `
SELECT classe, appels
FROM compteur_jour
WHERE titulaire_id = ?1 AND jour = ?2
`.trim();

/**
 * `INSERT ... ON CONFLICT DO UPDATE`, jamais `INSERT OR REPLACE` (§6.2).
 */
const SQL_INCREMENTER_COMPTEUR_JOUR = `
INSERT INTO compteur_jour (titulaire_id, jour, classe, appels, erreurs, introuvables, sortants)
VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6)
ON CONFLICT(titulaire_id, jour, classe) DO UPDATE SET
  appels = compteur_jour.appels + 1,
  erreurs = compteur_jour.erreurs + excluded.erreurs,
  introuvables = compteur_jour.introuvables + excluded.introuvables,
  sortants = compteur_jour.sortants + excluded.sortants
`.trim();

const SQL_INSERER_EVENEMENT_TECHNIQUE = `
INSERT INTO evenement_technique (
  titulaire_id, jeton_id, service, minute, outil, classe, issue, code, ms, sortants, client
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
`.trim();

const SQL_PURGER_EVENEMENTS_TECHNIQUES = `
DELETE FROM evenement_technique
WHERE minute < ?1
`.trim();

const SQL_PURGER_COMPTEURS_JOUR = `
DELETE FROM compteur_jour
WHERE jour < ?1
`.trim();

const SQL_PURGER_DEMANDES_ACCES_EXPIREES = `
DELETE FROM demande_acces
WHERE expire_le <= ?1
`.trim();

const SQL_PURGER_DEMANDES_ACCES_CONSOMMEES = `
DELETE FROM demande_acces
WHERE consomme_le IS NOT NULL AND consomme_le <= ?1
`.trim();

const SQL_PURGER_INVITATIONS_ACCES = `
DELETE FROM invitation_acces
WHERE titulaire_id IS NULL AND expire_le <= ?1
`.trim();

const SQL_RETIRER_ENTREE_COFFRE = `
DELETE FROM coffre_clef
WHERE titulaire_id = ?1 AND usage = ?2
`.trim();

const SQL_SUPPRIMER_EVENEMENTS_TITULAIRE = `
DELETE FROM evenement_technique
WHERE titulaire_id = ?1
`.trim();

const SQL_SUPPRIMER_TITULAIRE = `
DELETE FROM titulaire
WHERE id = ?1
`.trim();

const SQL_PURGER_SESSIONS_PORTAIL_EXPIREES = `
DELETE FROM session_portail
WHERE expire_le <= ?1
`.trim();

const SQL_PURGER_SESSIONS_PORTAIL_CONSOMMEES = `
DELETE FROM session_portail
WHERE consomme_le IS NOT NULL AND consomme_le <= ?1
`.trim();

const SQL_PURGER_CODES_OAUTH_EXPIRES = `
DELETE FROM code_oauth
WHERE expire_le <= ?1
`.trim();

const SQL_PURGER_CODES_OAUTH_CONSOMMES = `
DELETE FROM code_oauth
WHERE consomme_le IS NOT NULL AND consomme_le <= ?1
`.trim();

/** Lit en une seule requête indexée les compteurs journaliers UTC des trois classes d'outils. */
export async function lireCompteursJourD1(
  db: BaseD1Minimale,
  titulaireId: string,
  jour = jourUtc(),
): Promise<Record<ClasseOutil, number>> {
  const base: Record<ClasseOutil, number> = { local: 0, sortant: 0, semantique: 0 };
  const { results } = await db
    .prepare(SQL_LIRE_COMPTEURS_JOUR)
    .bind(titulaireId, jour)
    .all<{ classe: string; appels: number }>();

  for (const r of results) {
    if (r.classe === "local" || r.classe === "sortant" || r.classe === "semantique") {
      base[r.classe] = typeof r.appels === "number" && r.appels > 0 ? r.appels : 0;
    }
  }
  return base;
}

/** Incrémente atomiquement `compteur_jour` via `ON CONFLICT DO UPDATE` (jamais `REPLACE`). */
export async function incrementerCompteurJourD1(
  db: BaseD1Minimale,
  params: {
    titulaireId: string;
    jour?: string;
    classe: ClasseOutil;
    estErreur?: boolean;
    estIntrouvable?: boolean;
    sortants?: number;
  },
): Promise<void> {
  const sortants =
    typeof params.sortants === "number" && Number.isFinite(params.sortants) && params.sortants > 0
      ? Math.round(params.sortants)
      : 0;
  await db
    .prepare(SQL_INCREMENTER_COMPTEUR_JOUR)
    .bind(
      params.titulaireId,
      params.jour ?? jourUtc(),
      params.classe,
      params.estErreur ? 1 : 0,
      params.estIntrouvable ? 1 : 0,
      sortants,
    )
    .run();
}

/** Insère un événement technique sans contenu dans `DB_IDENTITE`. */
export async function ecrireEvenementTechniqueD1(
  db: BaseD1Minimale,
  evenement: EvenementTechnique,
): Promise<void> {
  await db
    .prepare(SQL_INSERER_EVENEMENT_TECHNIQUE)
    .bind(
      evenement.titulaire_id,
      evenement.jeton_id,
      evenement.service,
      evenement.minute,
      evenement.outil,
      evenement.classe,
      evenement.issue,
      evenement.code,
      evenement.ms,
      evenement.sortants,
      evenement.client,
    )
    .run();
}

/** Purge tous les événements techniques antérieurs à la fenêtre de rétention de 90 jours (`G16`). */
export async function purgerEvenementsTechniquesD1(
  db: BaseD1Minimale,
  maintenant = new Date(),
  joursRetention = RETENTION_EVENEMENTS_JOURS,
): Promise<string> {
  const seuilMs = maintenant.getTime() - joursRetention * 86_400_000;
  const minuteSeuil = minuteUtc(new Date(seuilMs));
  await db.prepare(SQL_PURGER_EVENEMENTS_TECHNIQUES).bind(minuteSeuil).run();
  return minuteSeuil;
}

/** Purge tous les compteurs journaliers antérieurs à la fenêtre de rétention de 90 jours (`cj_par_jour`). */
export async function purgerCompteursJourD1(
  db: BaseD1Minimale,
  maintenant = new Date(),
  joursRetention = RETENTION_COMPTEURS_JOURS,
): Promise<string> {
  const seuilMs = maintenant.getTime() - joursRetention * 86_400_000;
  const jourSeuil = jourUtc(new Date(seuilMs));
  await db.prepare(SQL_PURGER_COMPTEURS_JOUR).bind(jourSeuil).run();
  return jourSeuil;
}

/** Purge les demandes d'admission expirées ou déjà promues (`da_par_expiration` + `da_consommee`). */
export async function purgerDemandesAccesD1(
  db: BaseD1Minimale,
  maintenant = new Date(),
): Promise<string> {
  const seuilIso = horodatageIsoUtc(maintenant);
  await db.prepare(SQL_PURGER_DEMANDES_ACCES_EXPIREES).bind(seuilIso).run();
  await db.prepare(SQL_PURGER_DEMANDES_ACCES_CONSOMMEES).bind(seuilIso).run();
  return seuilIso;
}

/** Purge les codes d'invitation expirés qui ne sont rattachés à aucun compte titulaire (`ia_par_expiration`). */
export async function purgerInvitationsAccesD1(
  db: BaseD1Minimale,
  maintenant = new Date(),
): Promise<string> {
  const seuilIso = horodatageIsoUtc(maintenant);
  await db.prepare(SQL_PURGER_INVITATIONS_ACCES).bind(seuilIso).run();
  return seuilIso;
}

/** Retire immédiatement une entrée chiffrée du coffre pour un titulaire et un usage donné. */
export async function retirerEntreeCoffreD1(
  db: BaseD1Minimale,
  titulaireId: string,
  usage: string,
): Promise<void> {
  await db.prepare(SQL_RETIRER_ENTREE_COFFRE).bind(titulaireId, usage).run();
}

/**
 * Supprime un compte titulaire ainsi que l'intégralité de ses enregistrements rattachés dans
 * `DB_IDENTITE` (`evenement_technique` via `et_par_titulaire`, puis cascade FK indexée sur
 * `invitation_acces`, `jeton`, `coffre_clef`, `session_portail`, `code_oauth`, `compteur_jour`
 * et `registre_gouverne`).
 */
export async function supprimerCompteTitulaireD1(
  db: BaseD1Minimale,
  titulaireId: string,
): Promise<void> {
  await db.prepare(SQL_SUPPRIMER_EVENEMENTS_TITULAIRE).bind(titulaireId).run();
  await db.prepare(SQL_SUPPRIMER_TITULAIRE).bind(titulaireId).run();
}

/** Purge les liens et sessions de portail expirés ou déjà consommés (`sp_par_expiration` + `sp_consommee`). */
export async function purgerSessionsPortailD1(
  db: BaseD1Minimale,
  maintenant = new Date(),
): Promise<string> {
  const seuilIso = horodatageIsoUtc(maintenant);
  await db.prepare(SQL_PURGER_SESSIONS_PORTAIL_EXPIREES).bind(seuilIso).run();
  await db.prepare(SQL_PURGER_SESSIONS_PORTAIL_CONSOMMEES).bind(seuilIso).run();
  return seuilIso;
}

/** Purge les codes d'autorisation OAuth 2.1 expirés ou déjà échangés (`co_par_expiration` + `co_consomme`). */
export async function purgerCodesOAuthD1(
  db: BaseD1Minimale,
  maintenant = new Date(),
): Promise<string> {
  const seuilIso = horodatageIsoUtc(maintenant);
  await db.prepare(SQL_PURGER_CODES_OAUTH_EXPIRES).bind(seuilIso).run();
  await db.prepare(SQL_PURGER_CODES_OAUTH_CONSOMMES).bind(seuilIso).run();
  return seuilIso;
}

export interface BilanPurgeRetentions {
  readonly instantIso: string;
  readonly jourCompteursSeuil: string;
  readonly minuteEvenementsSeuil: string;
}

/**
 * Exécute l'ensemble des purges périodiques de rétention sur `DB_IDENTITE` dans un ordre sûr vis-à-vis
 * des clés étrangères (`demande_acces` avant `invitation_acces`, puis sessions, codes OAuth,
 * compteurs journaliers et événements techniques).
 */
export async function purgerRetentionsD1(
  db: BaseD1Minimale,
  maintenant = new Date(),
): Promise<BilanPurgeRetentions> {
  const instantIso = await purgerDemandesAccesD1(db, maintenant);
  await purgerInvitationsAccesD1(db, maintenant);
  await purgerSessionsPortailD1(db, maintenant);
  await purgerCodesOAuthD1(db, maintenant);
  const jourCompteursSeuil = await purgerCompteursJourD1(db, maintenant);
  const minuteEvenementsSeuil = await purgerEvenementsTechniquesD1(db, maintenant);
  return {
    instantIso,
    jourCompteursSeuil,
    minuteEvenementsSeuil,
  };
}

// ── Schéma D1 canonique `mcp-identite`, registre de rétention (G18) et garde (G13, G25) ──

// Cloudflare D1 plafonne SQLITE_LIMIT_LIKE_PATTERN_LENGTH à 50 octets : découper le contrôle
// canonique 24 car. `AAAA-MM-JJTHH:MM:SS.sssZ` en deux sous-motifs GLOB <= 33 octets reste
// déterministe dans toutes les versions de SQLite sans jamais franchir la limite D1.
const CHECK_JOUR_CANONIQUE = (col: string) =>
  `length(${col}) = 10 AND ${col} GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]'`;
const CHECK_MINUTE_CANONIQUE = (col: string) =>
  `length(${col}) = 16 AND substr(${col}, 1, 10) GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]' AND substr(${col}, 11, 6) GLOB 'T[0-2][0-9]:[0-5][0-9]'`;
const CHECK_ISO_MS_CANONIQUE = (col: string) =>
  `length(${col}) = 24 AND substr(${col}, 1, 10) GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]' AND substr(${col}, 11, 9) GLOB 'T[0-2][0-9]:[0-5][0-9]:[0-5][0-9]' AND substr(${col}, 20, 5) GLOB '.[0-9][0-9][0-9]Z'`;

/**
 * Construit le schéma SQL canonique de la base partagée `DB_IDENTITE` en paramétrant les noms de
 * portées de services propres au déploiement (en sus de `les_deux`), sans aucune table de contenu
 * de requête (`search_log` et `forme_requete` absentes).
 */
export function construireSchemaIdentiteD1(
  porteesServices: readonly string[] = ["service_a", "service_b"],
): string {
  const listePorteesSql = porteesCanoniques(porteesServices)
    .map((p) => `'${p}'`)
    .join(",");

  return `
CREATE TABLE titulaire (
  id                  TEXT PRIMARY KEY,
  cree_le             TEXT NOT NULL,
  etat                TEXT NOT NULL DEFAULT 'en_attente'
                      CHECK (etat IN ('en_attente','actif','surveille','limite','suspendu','revoque','refuse')),
  nom                 TEXT NOT NULL,
  numero_membre       TEXT NOT NULL UNIQUE,
  section             TEXT NOT NULL,
  courriel            TEXT NOT NULL UNIQUE,
  cabinet             TEXT,
  courriel_verifie_le TEXT,
  attestation_le      TEXT NOT NULL,
  attestation_ver     TEXT NOT NULL,
  cgu_ver             TEXT NOT NULL,
  hybride_permis      INTEGER NOT NULL DEFAULT 1 CHECK (hybride_permis IN (0, 1)),
  note_admission      TEXT
);

CREATE TABLE invitation_acces (
  id              TEXT PRIMARY KEY,
  empreinte_code  TEXT NOT NULL UNIQUE,
  courriel_cible  TEXT,
  cohorte         TEXT,
  cree_le         TEXT NOT NULL,
  expire_le       TEXT NOT NULL CHECK (${CHECK_ISO_MS_CANONIQUE("expire_le")}),
  consomme_le     TEXT CHECK (consomme_le IS NULL OR (${CHECK_ISO_MS_CANONIQUE("consomme_le")})),
  titulaire_id    TEXT REFERENCES titulaire(id) ON DELETE CASCADE
);
CREATE INDEX ia_par_expiration ON invitation_acces(titulaire_id, expire_le);

CREATE TABLE demande_acces (
  id               TEXT PRIMARY KEY,
  empreinte_jeton  TEXT NOT NULL UNIQUE,
  invitation_id    TEXT REFERENCES invitation_acces(id) ON DELETE SET NULL,
  nom              TEXT NOT NULL,
  numero_membre    TEXT NOT NULL,
  section          TEXT NOT NULL,
  courriel         TEXT NOT NULL,
  cabinet          TEXT,
  attestation_le   TEXT NOT NULL,
  attestation_ver  TEXT NOT NULL,
  cgu_ver          TEXT NOT NULL,
  coffre_version   INTEGER,
  coffre_iv        BLOB,
  coffre_chiffre   BLOB,
  coffre_repere    TEXT,
  coffre_empreinte TEXT,
  cree_le          TEXT NOT NULL,
  expire_le        TEXT NOT NULL CHECK (${CHECK_ISO_MS_CANONIQUE("expire_le")}),
  consomme_le      TEXT CHECK (consomme_le IS NULL OR (${CHECK_ISO_MS_CANONIQUE("consomme_le")})),
  CHECK (
    (coffre_version IS NULL AND coffre_iv IS NULL AND coffre_chiffre IS NULL AND coffre_repere IS NULL AND coffre_empreinte IS NULL)
    OR
    (coffre_version IS NOT NULL AND coffre_iv IS NOT NULL AND coffre_chiffre IS NOT NULL AND coffre_repere IS NOT NULL AND coffre_empreinte IS NOT NULL)
  )
);
CREATE INDEX da_par_expiration ON demande_acces(expire_le);
CREATE INDEX da_consommee ON demande_acces(consomme_le) WHERE consomme_le IS NOT NULL;
CREATE INDEX da_par_courriel ON demande_acces(courriel, cree_le);
CREATE INDEX da_par_invitation ON demande_acces(invitation_id);

CREATE TABLE jeton (
  id            TEXT PRIMARY KEY,
  titulaire_id  TEXT NOT NULL REFERENCES titulaire(id) ON DELETE CASCADE,
  empreinte     TEXT NOT NULL UNIQUE,
  queue         TEXT NOT NULL,
  libelle       TEXT NOT NULL,
  portee        TEXT NOT NULL DEFAULT 'les_deux'
                CHECK (portee IN (${listePorteesSql})),
  emis_le       TEXT NOT NULL,
  expire_le     TEXT,
  revoque_le    TEXT,
  motif_revoc   TEXT CHECK (motif_revoc IS NULL OR motif_revoc IN ('rotation','titulaire','exploitant','expiration','compromission')),
  vu_le         TEXT
);
CREATE INDEX jeton_actif ON jeton(empreinte) WHERE revoque_le IS NULL;
CREATE INDEX jeton_par_titulaire ON jeton(titulaire_id);

CREATE TABLE coffre_clef (
  titulaire_id   TEXT NOT NULL REFERENCES titulaire(id) ON DELETE CASCADE,
  usage          TEXT NOT NULL,
  version        INTEGER NOT NULL,
  iv             BLOB NOT NULL,
  chiffre        BLOB NOT NULL,
  repere         TEXT NOT NULL,
  empreinte_clef TEXT NOT NULL,
  pose_le        TEXT NOT NULL,
  eprouve_le     TEXT,
  etat           TEXT NOT NULL CHECK (etat IN ('valide','refusee','inconnue')),
  PRIMARY KEY (titulaire_id, usage)
);
CREATE INDEX cc_par_empreinte ON coffre_clef(usage, empreinte_clef);

CREATE TABLE session_portail (
  id            TEXT PRIMARY KEY,
  titulaire_id  TEXT REFERENCES titulaire(id) ON DELETE CASCADE,
  courriel      TEXT NOT NULL,
  type_lien     TEXT NOT NULL CHECK (type_lien IN ('verification_courriel','connexion_moi','session_moi')),
  empreinte     TEXT NOT NULL UNIQUE,
  cree_le       TEXT NOT NULL,
  expire_le     TEXT NOT NULL CHECK (${CHECK_ISO_MS_CANONIQUE("expire_le")}),
  consomme_le   TEXT CHECK (consomme_le IS NULL OR (${CHECK_ISO_MS_CANONIQUE("consomme_le")}))
);
CREATE INDEX sp_par_expiration ON session_portail(expire_le);
CREATE INDEX sp_consommee ON session_portail(consomme_le) WHERE consomme_le IS NOT NULL;
CREATE INDEX sp_par_titulaire ON session_portail(titulaire_id);

CREATE TABLE client_oauth (
  client_id             TEXT PRIMARY KEY,
  libelle               TEXT NOT NULL,
  empreinte_secret      TEXT,
  uris_redirection_json TEXT NOT NULL,
  portees_permises      TEXT NOT NULL DEFAULT 'les_deux',
  actif                 INTEGER NOT NULL DEFAULT 1 CHECK (actif IN (0, 1)),
  cree_le               TEXT NOT NULL
);

CREATE TABLE code_oauth (
  id                  TEXT PRIMARY KEY,
  titulaire_id        TEXT NOT NULL REFERENCES titulaire(id) ON DELETE CASCADE,
  empreinte_code      TEXT NOT NULL UNIQUE,
  client_id           TEXT NOT NULL,
  redirect_uri        TEXT NOT NULL,
  portee              TEXT NOT NULL CHECK (portee IN (${listePorteesSql})),
  defi_pkce           TEXT NOT NULL,
  methode_pkce        TEXT NOT NULL CHECK (methode_pkce IN ('S256')),
  cree_le             TEXT NOT NULL,
  expire_le           TEXT NOT NULL CHECK (${CHECK_ISO_MS_CANONIQUE("expire_le")}),
  consomme_le         TEXT CHECK (consomme_le IS NULL OR (${CHECK_ISO_MS_CANONIQUE("consomme_le")}))
);
CREATE INDEX co_par_expiration ON code_oauth(expire_le);
CREATE INDEX co_consomme ON code_oauth(consomme_le) WHERE consomme_le IS NOT NULL;
CREATE INDEX co_par_titulaire ON code_oauth(titulaire_id);

CREATE TABLE compteur_jour (
  titulaire_id  TEXT NOT NULL REFERENCES titulaire(id) ON DELETE CASCADE,
  jour          TEXT NOT NULL CHECK (${CHECK_JOUR_CANONIQUE("jour")}),
  classe        TEXT NOT NULL CHECK (classe IN ('local','sortant','semantique')),
  appels        INTEGER NOT NULL DEFAULT 0,
  erreurs       INTEGER NOT NULL DEFAULT 0,
  introuvables  INTEGER NOT NULL DEFAULT 0,
  sortants      INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (titulaire_id, jour, classe)
);
CREATE INDEX cj_par_jour ON compteur_jour(jour);

CREATE TABLE evenement_technique (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  titulaire_id  TEXT NOT NULL,
  jeton_id      TEXT NOT NULL,
  service       TEXT NOT NULL,
  minute        TEXT NOT NULL CHECK (${CHECK_MINUTE_CANONIQUE("minute")}),
  outil         TEXT NOT NULL,
  classe        TEXT NOT NULL CHECK (classe IN ('local','sortant','semantique')),
  issue         TEXT NOT NULL CHECK (issue IN ('ok','introuvable','erreur_usager','erreur_amont','refus','quota')),
  code          TEXT CHECK (code IS NULL OR code IN ('ARGUMENTS_INVALIDES','OUTIL_INCONNU','CLEF_ABSENTE','CLEF_REFUSEE','QUOTA_EPUISE','HORS_SERVICE','AMONT_HORS_SERVICE','AMONT_ERREUR','HYBRIDE_DESACTIVE','ERREUR_INTERNE')),
  ms            INTEGER,
  sortants      INTEGER NOT NULL DEFAULT 0,
  client        TEXT
);
CREATE INDEX et_par_titulaire ON evenement_technique(titulaire_id, minute);
CREATE INDEX et_par_minute ON evenement_technique(minute);

CREATE TABLE registre_gouverne (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  titulaire_id  TEXT NOT NULL REFERENCES titulaire(id) ON DELETE CASCADE,
  le            TEXT NOT NULL,
  de            TEXT NOT NULL CHECK (de IN ('en_attente','actif','surveille','limite','suspendu','revoque','refuse')),
  vers          TEXT NOT NULL CHECK (vers IN ('en_attente','actif','surveille','limite','suspendu','revoque','refuse')),
  motif         TEXT NOT NULL CHECK (motif IN ('admission','refus_admission','quota_repete','anomalie_debit','clef_invalide','demande_titulaire','manquement_cgu','retablissement')),
  auteur        TEXT NOT NULL CHECK (auteur IN ('automate','exploitant')),
  notifie_le    TEXT
);
CREATE INDEX rg_par_titulaire ON registre_gouverne(titulaire_id, le);
`.trim();
}

/** Instance par défaut du schéma canonique `DB_IDENTITE` pour validation hors ligne. */
export const SQL_SCHEMA_IDENTITE_D1 = construireSchemaIdentiteD1();

export type ModeRetentionTable = "purge_automatique" | "cycle_compte" | "configuration_service";

export interface PolitiqueRetentionTable {
  readonly table: string;
  readonly mode: ModeRetentionTable;
  readonly conservationMax: string;
  readonly purgeCode: string;
}

/**
 * Registre exhaustif de rétention des tables de `DB_IDENTITE` (`S20`, porte `G18`), servant de
 * source unique de vérité pour la page publique `/conformite`.
 */
export const POLITIQUES_RETENTION_IDENTITE: readonly PolitiqueRetentionTable[] = [
  {
    table: "titulaire",
    mode: "cycle_compte",
    conservationMax: "Durée de vie du compte vérifié ; suppression sur demande dans /moi",
    purgeCode: "supprimerCompteTitulaireD1",
  },
  {
    table: "invitation_acces",
    mode: "purge_automatique",
    conservationMax: "Jusqu'à expiration (sans compte rattaché) ou suppression du compte rattaché",
    purgeCode: "purgerInvitationsAccesD1",
  },
  {
    table: "demande_acces",
    mode: "purge_automatique",
    conservationMax: `${DUREE_DEMANDE_ACCES_MINUTES} minutes (ou dès confirmation du courriel)`,
    purgeCode: "purgerDemandesAccesD1",
  },
  {
    table: "jeton",
    mode: "cycle_compte",
    conservationMax: "Empreinte SHA-256 conservée jusqu'à suppression du compte",
    purgeCode: "supprimerCompteTitulaireD1",
  },
  {
    table: "coffre_clef",
    mode: "cycle_compte",
    conservationMax: "Jusqu'au retrait immédiat dans /moi ou suppression du compte",
    purgeCode: "retirerEntreeCoffreD1",
  },
  {
    table: "session_portail",
    mode: "purge_automatique",
    conservationMax: `Liens : ${DUREE_LIEN_PORTAIL_MINUTES} min ; session /moi : ${DUREE_SESSION_MOI_HEURES} h (ou dès consommation)`,
    purgeCode: "purgerSessionsPortailD1",
  },
  {
    table: "client_oauth",
    mode: "configuration_service",
    conservationMax: "Configuration déclarative des clients OAuth 2.1 pré-inscrits",
    purgeCode: "gestionExploitant",
  },
  {
    table: "code_oauth",
    mode: "purge_automatique",
    conservationMax: `${DUREE_CODE_OAUTH_SECONDES} secondes (ou dès échange contre jeton)`,
    purgeCode: "purgerCodesOAuthD1",
  },
  {
    table: "compteur_jour",
    mode: "purge_automatique",
    conservationMax: `${RETENTION_COMPTEURS_JOURS} jours UTC`,
    purgeCode: "purgerCompteursJourD1",
  },
  {
    table: "evenement_technique",
    mode: "purge_automatique",
    conservationMax: `${RETENTION_EVENEMENTS_JOURS} jours UTC (horodatage à la minute)`,
    purgeCode: "purgerEvenementsTechniquesD1",
  },
  {
    table: "registre_gouverne",
    mode: "cycle_compte",
    conservationMax: "Journal d'états en ajout seul jusqu'à suppression du compte",
    purgeCode: "supprimerCompteTitulaireD1",
  },
] as const;

/**
 * Porte `G18` : vérifie que chaque table déclarée dans un schéma SQL possède une politique de
 * rétention explicite et non vide dans `politiques`, et qu'aucune entrée orpheline ne subsiste.
 */
export function verifierCouvertureRetentionSchema(
  sql = SQL_SCHEMA_IDENTITE_D1,
  politiques: readonly PolitiqueRetentionTable[] = POLITIQUES_RETENTION_IDENTITE,
): string[] {
  const anomalies: string[] = [];
  const sansCommentaires = retirerCommentairesSql(sql);
  const tablesSql = new Set(extraireTablesSql(sansCommentaires).map((t) => t.nomTable));
  const tablesDeclarees = new Set<string>();

  for (const p of politiques) {
    const nom = p.table.trim().toLowerCase();
    if (tablesDeclarees.has(nom)) {
      anomalies.push(`G18 : politique de rétention dupliquée pour « ${nom} ».`);
    }
    tablesDeclarees.add(nom);
    if (p.conservationMax.trim().length === 0 || p.purgeCode.trim().length === 0) {
      anomalies.push(`G18 : politique de rétention incomplète pour « ${nom} ».`);
    }
    if (!tablesSql.has(nom)) {
      anomalies.push(`G18 : politique de rétention orpheline absente du schéma SQL (« ${nom} »).`);
    }
  }

  for (const t of tablesSql) {
    if (!tablesDeclarees.has(t)) {
      anomalies.push(`G18 : table SQL sans politique de rétention déclarée (« ${t} »).`);
    }
  }

  return anomalies;
}

const TABLES_CONTENU_INTERDITES = new Set([
  "search_log",
  "search_log_exploitant",
  "forme_requete",
  "journal_requetes",
]);
const TABLES_ADMINISTRATIVES_SANS_REQUETE = new Set([
  "titulaire",
  "invitation_acces",
  "demande_acces",
  "jeton",
  "coffre_clef",
  "session_portail",
  "client_oauth",
  "code_oauth",
]);
const COLONNES_TECHNIQUES_STRUCTURELLES = new Set([
  "id",
  "titulaire_id",
  "jeton_id",
  "service",
  "outil",
  "jour",
  "minute",
  "le",
  "notifie_le",
  "client",
]);
const COLONNES_CONTENU_REQUETE = new Set([
  "query",
  "requete",
  "forme",
  "prompt",
  "arguments",
  "corps",
  "citation",
  "texte_recherche",
  "url_requete",
]);
const COLONNES_IDENTITE = new Set(["titulaire_id", "jeton_id", "courriel", "numero_membre"]);
const COLONNES_SOUS_JOUR = new Set([
  "ts",
  "seconde",
  "second",
  "timestamp",
  "horodatage_sec",
  "minute",
  "cree_le",
]);

function estColonneSousJour(nomColonne: string): boolean {
  return (
    COLONNES_SOUS_JOUR.has(nomColonne) ||
    /(?:_at|_le|time|heure|horodatage|minute|sec)/i.test(nomColonne)
  );
}

const TYPES_STRICTEMENT_NUMERIQUES = new Set([
  "INTEGER",
  "INT",
  "SMALLINT",
  "BIGINT",
  "TINYINT",
  "REAL",
  "FLOAT",
  "DOUBLE",
  "NUMERIC",
]);

const MOTS_CLES_CONTRAINTE_COLONNE = new Set([
  "NOT",
  "NULL",
  "DEFAULT",
  "UNIQUE",
  "PRIMARY",
  "REFERENCES",
  "CHECK",
  "COLLATE",
  "GENERATED",
  "AS",
  "CONSTRAINT",
]);

interface ColonneSqlExtraite {
  nom: string;
  estTexte: boolean;
  aCheckIn: boolean;
}

/**
 * Vérifie statiquement qu'un script DDL SQL respecte l'absence totale de journalisation de
 * contenu de requête (`search_log`, `forme_requete` et colonnes de contenu interdites) ainsi que
 * les gardes `G13` et `G25` :
 * - aucune table ne déclare de colonne de contenu de requête (`query`, `requete`, `forme`, etc.) ;
 * - aucune table opérationnelle/télémétrique portant une identité ne déclare de colonne texte ou
 *   non typée sans contrainte `CHECK (... IN (...))` (`G13`) ;
 * - aucune table portant du texte libre ne déclare un horodatage plus fin que le jour (`G25`).
 *
 * Renvoie la liste des violations détectées (tableau vide si conforme).
 */
export function verifierSchemaSansContenuIdentifiant(sql: string): string[] {
  const violations: string[] = [];
  const sansCommentaires = retirerCommentairesSql(sql);

  for (const { nomTable, blocColonnes } of extraireTablesSql(sansCommentaires)) {
    if (TABLES_CONTENU_INTERDITES.has(nomTable)) {
      violations.push(`Table de journalisation de contenu interdite : « ${nomTable} ».`);
    }

    const defs = extraireDefinitionsColonnesSql(blocColonnes);
    const colonnes = defs.map((d) => d.nom);
    const porteIdentite =
      nomTable === "titulaire" || colonnes.some((c) => COLONNES_IDENTITE.has(c));
    const colonnesContenu = colonnes.filter((c) => COLONNES_CONTENU_REQUETE.has(c));
    const colonnesSousJour = colonnes.filter(estColonneSousJour);

    if (colonnesContenu.length > 0) {
      violations.push(
        `S13/G13 violée sur « ${nomTable} » : colonne de contenu de requête interdite (${colonnesContenu.join(", ")}).`,
      );
    }

    if (porteIdentite && !TABLES_ADMINISTRATIVES_SANS_REQUETE.has(nomTable)) {
      const textesLibres = defs
        .filter((d) => d.estTexte && !d.aCheckIn && !COLONNES_TECHNIQUES_STRUCTURELLES.has(d.nom))
        .map((d) => d.nom);
      if (textesLibres.length > 0) {
        violations.push(
          `G13 violée sur « ${nomTable} » : colonne TEXT ou non typée sans contrainte CHECK IN (${textesLibres.join(", ")}).`,
        );
      }
    }

    const porteTexteLibreQuelconque =
      colonnesContenu.length > 0 ||
      (!TABLES_ADMINISTRATIVES_SANS_REQUETE.has(nomTable) &&
        !porteIdentite &&
        defs.some((d) => d.estTexte && !d.aCheckIn && d.nom !== "jour" && d.nom !== "outil"));

    if (porteTexteLibreQuelconque && colonnesSousJour.length > 0) {
      violations.push(
        `G25 violée sur « ${nomTable} » : contenu combiné à un horodatage plus fin que le jour (${colonnesSousJour.join(", ")}).`,
      );
    }
  }

  return violations;
}

function retirerCommentairesSql(sql: string): string {
  let out = "";
  let i = 0;
  while (i < sql.length) {
    const ch = sql[i]!;
    if (ch === "'" || ch === '"' || ch === "`" || ch === "[") {
      const fin = avancerHorsLitteralSql(sql, i);
      out += sql.slice(i, fin);
      i = fin;
      continue;
    }
    if (ch === "-" && sql[i + 1] === "-") {
      const finLigne = sql.indexOf("\n", i + 2);
      i = finLigne >= 0 ? finLigne : sql.length;
      continue;
    }
    if (ch === "/" && sql[i + 1] === "*") {
      const finBloc = sql.indexOf("*/", i + 2);
      i = finBloc >= 0 ? finBloc + 2 : sql.length;
      out += " ";
      continue;
    }
    out += ch;
    i++;
  }
  return out;
}

function avancerHorsLitteralSql(sql: string, indexOuverture: number): number {
  const delim = sql[indexOuverture]!;
  const fermeture = delim === "[" ? "]" : delim;
  let i = indexOuverture + 1;
  while (i < sql.length) {
    if (sql[i] === fermeture) {
      if ((fermeture === "'" || fermeture === '"') && sql[i + 1] === fermeture) {
        i += 2;
        continue;
      }
      return i + 1;
    }
    i++;
  }
  return sql.length;
}

function extraireTablesSql(sql: string): Array<{ nomTable: string; blocColonnes: string }> {
  const tables: Array<{ nomTable: string; blocColonnes: string }> = [];
  const enTete =
    /CREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?\s+(?:["`[]?[A-Za-z0-9_]+["`\]]?\.)?["`[]?([A-Za-z0-9_]+)["`\]]?\s*\(/gi;

  for (const m of sql.matchAll(enTete)) {
    const nomTable = m[1]!.toLowerCase();
    const debutBloc = (m.index ?? 0) + m[0].length;
    let profondeur = 1;
    let i = debutBloc;
    while (i < sql.length && profondeur > 0) {
      const ch = sql[i]!;
      if (ch === "'" || ch === '"' || ch === "`" || ch === "[") {
        i = avancerHorsLitteralSql(sql, i);
        continue;
      }
      if (ch === "(") profondeur++;
      else if (ch === ")") profondeur--;
      i++;
    }
    if (profondeur === 0) {
      tables.push({ nomTable, blocColonnes: sql.slice(debutBloc, i - 1) });
    }
  }
  return tables;
}

function neutraliserLitterauxSql(segment: string): string {
  let out = "";
  let i = 0;
  while (i < segment.length) {
    const ch = segment[i]!;
    if (ch === "'") {
      const fin = avancerHorsLitteralSql(segment, i);
      out += "''";
      i = fin;
      continue;
    }
    out += ch;
    i++;
  }
  return out;
}

function aContrainteEnumerationFermee(ligneSansChaines: string, nomColonne: string): boolean {
  const nomEchappe = nomColonne.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const motifEnumSimple = new RegExp(`^["\`[]?${nomEchappe}["\`\\]]? IN \\([\\s'',]+\\)$`, "i");
  const motifEnumNullable = new RegExp(
    `^["\`[]?${nomEchappe}["\`\\]]? IS NULL OR ["\`[]?${nomEchappe}["\`\\]]? IN \\([\\s'',]+\\)$`,
    "i",
  );

  const enTeteCheck = /\bCHECK\s*\(/gi;
  for (const m of ligneSansChaines.matchAll(enTeteCheck)) {
    const debut = (m.index ?? 0) + m[0].length;
    let profondeur = 1;
    let i = debut;
    while (i < ligneSansChaines.length && profondeur > 0) {
      const ch = ligneSansChaines[i]!;
      if (ch === "(") profondeur++;
      else if (ch === ")") profondeur--;
      i++;
    }
    if (profondeur === 0) {
      const expr = ligneSansChaines
        .slice(debut, i - 1)
        .trim()
        .replace(/\s+/g, " ");
      if (motifEnumSimple.test(expr) || motifEnumNullable.test(expr)) {
        return true;
      }
    }
  }
  return false;
}

function extraireDefinitionsColonnesSql(bloc: string): ColonneSqlExtraite[] {
  const defs: ColonneSqlExtraite[] = [];
  let profondeur = 0;
  let courant = "";
  const segments: string[] = [];

  let i = 0;
  while (i < bloc.length) {
    const ch = bloc[i]!;
    if (ch === "'" || ch === '"' || ch === "`" || ch === "[") {
      const fin = avancerHorsLitteralSql(bloc, i);
      courant += bloc.slice(i, fin);
      i = fin;
      continue;
    }
    if (ch === "(") profondeur++;
    else if (ch === ")") profondeur = Math.max(0, profondeur - 1);

    if (ch === "," && profondeur === 0) {
      segments.push(courant);
      courant = "";
    } else {
      courant += ch;
    }
    i++;
  }
  if (courant.trim().length > 0) segments.push(courant);

  const motsClesContrainte = /^(?:PRIMARY|FOREIGN|UNIQUE|CHECK|CONSTRAINT)\b/i;
  for (const seg of segments) {
    const ligne = seg.trim();
    if (ligne.length === 0 || motsClesContrainte.test(ligne)) continue;
    const m = /^["`[]?([A-Za-z0-9_]+)["`\]]?(?:\s+([A-Za-z]+))?/.exec(ligne);
    if (!m?.[1]) continue;
    const nom = m[1].toLowerCase();
    const secondJeton = m[2]?.toUpperCase();
    const estNonType = secondJeton === undefined || MOTS_CLES_CONTRAINTE_COLONNE.has(secondJeton);
    // Liste blanche fermée par défaut : toute colonne non strictement numérique (TEXT, BLOB, JSON,
    // STRING, VARCHAR, ANY ou non typée) exige une énumération fermée dans les tables de télémétrie.
    const estTexte = estNonType || !TYPES_STRICTEMENT_NUMERIQUES.has(secondJeton);
    const sansChaines = neutraliserLitterauxSql(ligne);
    const aCheckIn = aContrainteEnumerationFermee(sansChaines, nom);
    defs.push({ nom, estTexte, aCheckIn });
  }
  return defs;
}
