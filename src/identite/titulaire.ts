/**
 * Identité multilocataire : résolution de jetons opaques par empreinte SHA-256, contrôle de
 * portée (`les_deux` ou par connecteur) et coexistence transitoire avec les secrets partagés.
 *
 * Invariants appliqués :
 * - **Fermé par défaut (`G21`)** : ni l'absence de base, ni une table vide, ni une liste de
 *   secrets vide, ni une exception D1 n'ouvre l'accès.
 * - **Zéro oracle d'état (`G7`)** : jeton inconnu, expiré, révoqué, portée étrangère ou
 *   titulaire non servi (`en_attente`, `suspendu`, `revoque`, `refuse`) produisent tous `null`
 *   sans requête conditionnelle secondaire.
 * - **Aucun porteur n'en masque un autre** : jusqu'à `MAX_CANDIDATS_JETON` candidats frappés
 *   distincts sont éprouvés afin qu'un en-tête résiduel périmé n'annule pas un `?key=` valide.
 * - **Horodatage `vu_le` au jour UTC** : mis à jour au plus une fois par jour et par jeton.
 */

import {
  empreinte,
  estCheminMontageAdmissible,
  estJetonFrappe,
  normaliserUrlMontage,
  type Porte,
  porteursPresentes,
  secretsAdmis,
  trouverPorteurApparie,
} from "./porteur";

/** États administratifs possibles d'un titulaire dans la base d'identité partagée. */
export const ETATS_TITULAIRE = [
  "en_attente",
  "actif",
  "surveille",
  "limite",
  "suspendu",
  "revoque",
  "refuse",
] as const;

export type EtatTitulaire = (typeof ETATS_TITULAIRE)[number];

/** Seuls ces trois états autorisent le service des appels authentifiés (§4.3 marche 7). */
export const ETATS_TITULAIRE_SERVIS = ["actif", "surveille", "limite"] as const;

export type EtatTitulaireServi = (typeof ETATS_TITULAIRE_SERVIS)[number];

/** Portée par défaut ouvrant l'ensemble des connecteurs authentifiés de la plateforme. */
export const PORTEE_UNIVERSELLE = "les_deux";

/** Nombre maximal de candidats de jeton frappés interrogés par requête HTTP. */
export const MAX_CANDIDATS_JETON = 4;

const JETON_FACTICE_TEMPS_CONSTANT = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/** Indique si l'état du titulaire autorise l'exécution de requêtes MCP. */
export function estEtatServi(etat: unknown): etat is EtatTitulaireServi {
  return etat === "actif" || etat === "surveille" || etat === "limite";
}

/**
 * Vérifie que la portée enregistrée sur le jeton couvre le connecteur courant.
 *
 * Fermé par défaut : une portée vide, absente ou restreinte à un autre connecteur est refusée.
 */
export function porteeAutorisee(porteeJeton: unknown, serviceAttendu?: string): boolean {
  if (typeof porteeJeton !== "string") return false;
  const jetonsPortee = porteeJeton
    .trim()
    .split(/[\s,]+/)
    .filter((s) => s.length > 0);
  if (jetonsPortee.length === 0) return false;
  if (jetonsPortee.includes(PORTEE_UNIVERSELLE)) return true;
  if (!serviceAttendu || serviceAttendu.trim().length === 0) return false;
  return jetonsPortee.includes(serviceAttendu.trim());
}

/** Ligne brute renvoyée par la jointure indexée `jeton` × `titulaire`. */
export interface EnregistrementJetonTitulaire {
  readonly jeton_id: string;
  readonly titulaire_id: string;
  readonly etat: string;
  readonly portee: string;
  readonly hybride_permis: number | boolean;
  readonly expire_le: string | null;
  readonly revoque_le: string | null;
  readonly vu_le: string | null;
}

/** Abstraction minimale du dépôt de jetons permettant les tests hors ligne sans réseau. */
export interface DepotJetons {
  trouverParEmpreinte(empreinteHex: string): Promise<EnregistrementJetonTitulaire | null>;
  marquerVuLe?(jetonId: string, jourUtc: string): Promise<void>;
}

/** Interface structurelle minimale compatible avec `D1Database` de Cloudflare Workers. */
export interface BaseD1Minimale {
  prepare(requeteSql: string): {
    bind(...valeurs: unknown[]): {
      first<T = Record<string, unknown>>(): Promise<T | null>;
      all<T = Record<string, unknown>>(): Promise<{ results: T[] }>;
      run(): Promise<unknown>;
    };
  };
}

const SQL_TROUVER_JETON_PAR_EMPREINTE = `
SELECT
  j.id AS jeton_id,
  j.titulaire_id AS titulaire_id,
  t.etat AS etat,
  j.portee AS portee,
  t.hybride_permis AS hybride_permis,
  j.expire_le AS expire_le,
  j.revoque_le AS revoque_le,
  j.vu_le AS vu_le
FROM jeton j
INNER JOIN titulaire t ON t.id = j.titulaire_id
WHERE j.empreinte = ?1
LIMIT 1
`.trim();

const SQL_MARQUER_JETON_VU_LE = `
UPDATE jeton
SET vu_le = ?2
WHERE id = ?1 AND (vu_le IS NULL OR vu_le <> ?2)
`.trim();

/** Fabrique un `DepotJetons` adossé à la base D1 partagée `DB_IDENTITE`. */
export function creerDepotJetonsD1(db: BaseD1Minimale): DepotJetons {
  return {
    async trouverParEmpreinte(empreinteHex: string): Promise<EnregistrementJetonTitulaire | null> {
      return await db
        .prepare(SQL_TROUVER_JETON_PAR_EMPREINTE)
        .bind(empreinteHex)
        .first<EnregistrementJetonTitulaire>();
    },
    async marquerVuLe(jetonId: string, jourIso: string): Promise<void> {
      await db.prepare(SQL_MARQUER_JETON_VU_LE).bind(jetonId, jourIso).run();
    },
  };
}

/** Titulaire actif résolu à partir d'un jeton individuel vérifié. */
export interface TitulaireResolu {
  readonly titulaireId: string;
  readonly jetonId: string;
  readonly etat: EtatTitulaireServi;
  readonly portee: string;
  readonly hybridePermis: boolean;
  readonly vuLe: string | null;
}

/** Identité authentifiée attachée à une requête MCP acceptée. */
export type Principal =
  | {
      readonly type: "titulaire";
      readonly titulaireId: string;
      readonly jetonId: string;
      readonly etat: EtatTitulaireServi;
      readonly portee: string;
      readonly hybridePermis: boolean;
    }
  | {
      readonly type: "secret_partage";
    };

export interface OptionsResolutionJeton {
  /** Identifiant du service hôte pour valider `jeton.portee` (outre `les_deux`). */
  service?: string;
  /** Horloge injectable pour tests déterministes d'expiration et de `vu_le`. */
  horloge?: () => Date;
  /** File d'arrière-plan (`ctx.waitUntil`) pour différer l'écriture quotidienne de `vu_le`. */
  planifierArrierePlan?: (tache: Promise<unknown>) => void;
  /**
   * Rappel optionnel recevant l'empreinte SHA-256 hexadécimale d'un jeton validé afin d'alimenter
   * le laissez-passer pré-authentification des IP infonuagiques partagées (`S15`).
   */
  surEmpreinteValide?: (empreinteHex: string) => void;
}

function formaterJourUtc(d: Date): string {
  return d.toISOString().slice(0, 10);
}

const MOTIF_ISO_HORODATAGE =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|([+-])(\d{2}):(\d{2}))$/;
const MOTIF_SQLITE_HORODATAGE_UTC =
  /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?$/;
const MOTIF_ISO_JOUR = /^(\d{4})-(\d{2})-(\d{2})$/;

function dateCalendaireValide(annee: number, mois: number, jour: number): boolean {
  if (mois < 1 || mois > 12 || jour < 1 || jour > 31) return false;
  const temoin = new Date(0);
  temoin.setUTCFullYear(annee, mois - 1, jour);
  return (
    temoin.getUTCFullYear() === annee &&
    temoin.getUTCMonth() === mois - 1 &&
    temoin.getUTCDate() === jour
  );
}

/**
 * Convertit un horodatage stocké (`RFC 3339` avec ou sans millisecondes, `SQLite UTC`
 * `AAAA-MM-JJ HH:MM:SS` ou jour `AAAA-MM-JJ`) en époque millisecondes UTC.
 *
 * Valide explicitement les composantes calendaires, horaires et de décalage horaire avant toute
 * conversion UTC et rend `null` sur toute chaîne mal formée ou date calendaire inexistante afin
 * que le contrôle d'expiration échoue systématiquement fermé.
 */
export function horodatageUtcMs(brut: string): number | null {
  if (typeof brut !== "string" || brut.length === 0 || brut !== brut.trim()) return null;

  let annee: number;
  let mois: number;
  let jour: number;
  let heure = 0;
  let minute = 0;
  let seconde = 0;
  let msFrac = 0;
  let decalageMs = 0;

  const mIso = MOTIF_ISO_HORODATAGE.exec(brut);
  if (mIso) {
    annee = Number(mIso[1]);
    mois = Number(mIso[2]);
    jour = Number(mIso[3]);
    heure = Number(mIso[4]);
    minute = Number(mIso[5]);
    seconde = Number(mIso[6]);
    msFrac = mIso[7] ? Number(mIso[7].slice(0, 3).padEnd(3, "0")) : 0;
    if (mIso[9]) {
      const decH = Number(mIso[10]);
      const decM = Number(mIso[11]);
      if (decH > 23 || decM > 59) return null;
      const signe = mIso[9] === "+" ? 1 : -1;
      decalageMs = signe * (decH * 60 + decM) * 60_000;
    }
  } else {
    const mSqlite = MOTIF_SQLITE_HORODATAGE_UTC.exec(brut);
    if (mSqlite) {
      annee = Number(mSqlite[1]);
      mois = Number(mSqlite[2]);
      jour = Number(mSqlite[3]);
      heure = Number(mSqlite[4]);
      minute = Number(mSqlite[5]);
      seconde = Number(mSqlite[6]);
      msFrac = mSqlite[7] ? Number(mSqlite[7].slice(0, 3).padEnd(3, "0")) : 0;
    } else {
      const mJour = MOTIF_ISO_JOUR.exec(brut);
      if (!mJour) return null;
      annee = Number(mJour[1]);
      mois = Number(mJour[2]);
      jour = Number(mJour[3]);
    }
  }

  if (!dateCalendaireValide(annee, mois, jour)) return null;
  if (heure > 23 || minute > 59 || seconde > 59) return null;

  const d = new Date(0);
  d.setUTCFullYear(annee, mois - 1, jour);
  d.setUTCHours(heure, minute, seconde, msFrac);
  const ms = d.getTime() - decalageMs;
  return Number.isFinite(ms) ? ms : null;
}

/**
 * Résout une liste de porteurs candidats contre le dépôt D1 des jetons individuels.
 *
 * Effectue systématiquement au moins un condensé SHA-256 même lorsqu'aucun candidat n'a la
 * forme d'un jeton frappé ou que le dépôt est absent, résout l'intégralité des candidats retenus
 * sans court-circuit (`Promise.all`), et évalue révocation, expiration numérique, état et portée
 * sur l'unique ligne lue sans requête secondaire discriminante (`G7`, `G21`).
 */
export async function resoudreJeton(
  depot: DepotJetons | undefined,
  candidats: readonly string[],
  options: OptionsResolutionJeton = {},
): Promise<TitulaireResolu | null> {
  const retenus = candidatosFrappesUniques(candidats);
  if (!depot || retenus.length === 0) {
    await empreinte(JETON_FACTICE_TEMPS_CONSTANT);
    return null;
  }

  const maintenant = (options.horloge ?? (() => new Date()))();
  const maintenantMs = maintenant.getTime();
  const jourIso = formaterJourUtc(maintenant);

  let erreurLecture = false;
  const evaluations = await Promise.all(
    retenus.map(async (candidat) => {
      const empreinteHex = await empreinte(candidat);
      let ligne: EnregistrementJetonTitulaire | null = null;
      try {
        ligne = await depot.trouverParEmpreinte(empreinteHex);
      } catch {
        erreurLecture = true;
        return null;
      }

      if (!ligne) return null;
      if (ligne.revoque_le !== null && ligne.revoque_le !== undefined) return null;
      if (ligne.expire_le !== null && ligne.expire_le !== undefined) {
        if (typeof ligne.expire_le !== "string") return null;
        const expMs = horodatageUtcMs(ligne.expire_le);
        if (expMs === null || expMs <= maintenantMs) return null;
      }
      if (!estEtatServi(ligne.etat)) return null;
      if (!porteeAutorisee(ligne.portee, options.service)) return null;

      const hybridePermis = ligne.hybride_permis === true || ligne.hybride_permis === 1;
      const resolu: TitulaireResolu = {
        titulaireId: ligne.titulaire_id,
        jetonId: ligne.jeton_id,
        etat: ligne.etat,
        portee: ligne.portee,
        hybridePermis,
        vuLe: ligne.vu_le,
      };
      return { empreinteHex, resolu };
    }),
  );

  // Fermé par défaut sur toute erreur D1, sans journaliser le candidat ni l'empreinte.
  if (erreurLecture) return null;

  const gagnant = evaluations.find((e) => e !== null);
  if (!gagnant) return null;

  options.surEmpreinteValide?.(gagnant.empreinteHex);

  if (gagnant.resolu.vuLe !== jourIso && depot.marquerVuLe && options.planifierArrierePlan) {
    options.planifierArrierePlan(
      depot.marquerVuLe(gagnant.resolu.jetonId, jourIso).catch(() => {}),
    );
  }

  return gagnant.resolu;
}

function candidatosFrappesUniques(candidats: readonly string[]): string[] {
  const uniques: string[] = [];
  for (const c of candidats) {
    if (!estJetonFrappe(c)) continue;
    if (!uniques.includes(c)) {
      uniques.push(c);
      if (uniques.length >= MAX_CANDIDATS_JETON) break;
    }
  }
  return uniques;
}

export interface OptionsOuverturePrincipal extends OptionsResolutionJeton {
  /** Dépôt D1 des jetons par titulaire (`DB_IDENTITE`). */
  depot?: DepotJetons;
}

export interface ResultatOuverturePrincipal {
  readonly requete: Request;
  readonly principal: Principal;
}

/**
 * Authentifie une requête entrante par jeton individuel D1 (`titulaire`) et, si la `Porte`
 * déclare encore des `nomsSecrets` actifs (bascule graduée ou veille CI), en coexistence avec
 * les secrets partagés d'instance.
 *
 * Rend `null` dès qu'aucun mécanisme configuré n'authentifie la requête (fermé par défaut).
 */
export async function ouvrirPrincipal(
  request: Request,
  url: URL,
  env: Record<string, unknown>,
  porte: Porte,
  options: OptionsOuverturePrincipal = {},
): Promise<ResultatOuverturePrincipal | null> {
  const presentes = porteursPresentes(request, url, porte);
  const secrets = secretsAdmis(env, porte);
  const cheminAdmissible = estCheminMontageAdmissible(url.pathname, porte);
  const optionsJeton: OptionsResolutionJeton = cheminAdmissible
    ? options
    : {
        ...options,
        surEmpreinteValide: undefined,
        planifierArrierePlan: undefined,
      };

  const [titulaire, secretApparie] = await Promise.all([
    resoudreJeton(options.depot, presentes, optionsJeton),
    trouverPorteurApparie(presentes, secrets),
  ]);

  if (!cheminAdmissible) {
    return null;
  }

  if (titulaire) {
    return {
      requete: normaliserUrlMontage(request, url, porte),
      principal: {
        type: "titulaire",
        titulaireId: titulaire.titulaireId,
        jetonId: titulaire.jetonId,
        etat: titulaire.etat,
        portee: titulaire.portee,
        hybridePermis: titulaire.hybridePermis,
      },
    };
  }

  if (secretApparie !== null) {
    if (options.surEmpreinteValide) {
      options.surEmpreinteValide(await empreinte(secretApparie));
    }
    return {
      requete: normaliserUrlMontage(request, url, porte),
      principal: { type: "secret_partage" },
    };
  }

  return null;
}
