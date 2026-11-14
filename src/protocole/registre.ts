/**
 * Registre d'outils : le TYPE d'un descripteur, et la mécanique de listage.
 *
 * Ce que ce fichier porte est générique. Ce qu'il ne porte pas, et ne portera jamais : les
 * descripteurs eux-mêmes, `INSTRUCTIONS`, `SERVER_INFO`, et `callTool`. La §11 marche 1 de
 * la spécification les laisse expressément dans chaque dépôt — ce sont douze lignes de
 * répartition, et les monter ici ferait entrer la connaissance du domaine par la porte du
 * type de contexte.
 *
 * Repris de `MCP-Jurisprudence` (`src/mcp/registry.ts`), généralisé sur DEUX points et
 * pas un de plus :
 *
 *   1. **Le contexte est un paramètre de type.** Là-bas, `ToolContext` porte `client:
 *      CanliiClient` — un type du domaine. Ici, `TCtx` est ce que le dépôt consommateur
 *      décide. Aucune signature de gestionnaire ne change de forme pour autant.
 *   2. **`annotations` devient un champ REQUIS du descripteur.** Là-bas, `listToolDescriptors`
 *      estampillait une constante `READONLY` de portée module, la même pour les treize
 *      outils. Les deux connecteurs n'ont pas les mêmes indices — `legislation` déclare
 *      `idempotentHint` et `openWorldHint: false`, `jurisprudence` non — donc le socle ne
 *      peut pas posséder cette valeur. La rendre explicite par outil a un effet secondaire
 *      utile : elle fait apparaître que `jurisprudence` estampille aujourd'hui
 *      `openWorldHint: true` sur ses trois outils hors ligne, ce qu'aucune relecture
 *      n'avait relevé.
 */

import { err, type ToolResult } from "./rpc";
import { type JsonSchema, validateArgs } from "./valide";

/**
 * Indices de comportement (MCP « tool annotations »).
 *
 * ⚠ Un client DOIT les tenir pour non fiables s'ils viennent d'un serveur non approuvé :
 *   ce sont des déclarations du serveur sur lui-même, que rien ne vérifie. Ils servent à
 *   l'interface, jamais à une décision de sécurité.
 */
export interface Annotations {
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
}

export type SupportTache = "forbidden" | "optional" | "required";

export interface ExecutionOutil {
  taskSupport: SupportTache;
}

export type ToolHandler<TCtx> = (args: Record<string, unknown>, ctx: TCtx) => Promise<ToolResult>;

/** Descripteur public d'un outil (sans gestionnaire), utilisé par `tools/list`. */
export interface DescripteurOutil {
  /**
   * Libellé lisible, distinct de `name`.
   *
   * C'est ce que le praticien lit dans l'invite d'AUTORISATION, au moment précis où il
   * décide de laisser l'outil s'exécuter. Une réserve portée par le titre se lit AVANT
   * l'appel plutôt qu'après. Un client qui ignore ce champ retombe sur `name` : rien ne
   * casse.
   */
  title: string;
  description: string;
  inputSchema: JsonSchema;
  /** Requis, et propre à chaque dépôt : le socle n'a pas d'avis sur ces indices. */
  annotations: Annotations;
  execution?: ExecutionOutil;
}

export interface ToolDescriptor<TCtx> extends DescripteurOutil {
  handler: ToolHandler<TCtx>;
}

export type Registre<TCtx> = Record<string, ToolDescriptor<TCtx>>;

/**
 * Descripteurs rendus à `tools/list`.
 *
 * ⚠ L'ORDRE DES CLEFS DE L'OBJET ÉMIS EST UN CONTRAT. `JSON.stringify` conserve l'ordre
 *   d'insertion : `name, title, description, inputSchema, annotations` (puis `execution`
 *   s'il est défini). Ne pas réordonner.
 *
 * ⚠ L'ORDRE DES OUTILS est celui d'insertion dans le registre, comme auparavant.
 */
export function listToolDescriptors(
  tools: Record<string, DescripteurOutil>,
): Array<Record<string, unknown>> {
  return Object.entries(tools).map(([name, t]) => ({
    name,
    title: t.title,
    description: t.description,
    inputSchema: t.inputSchema,
    annotations: { ...t.annotations },
    ...(t.execution !== undefined ? { execution: { ...t.execution } } : {}),
  }));
}

export interface OptionsAppelOutil {
  /**
   * Transformation explicite et facultative appliquée aux arguments validés comme objet avant
   * validation de schéma (par exemple table `COERCITIONS` explicite d'un dépôt).
   */
  normaliser?: (nom: string, args: Record<string, unknown>) => Record<string, unknown>;
  /** Rappel facultatif lorsqu'un gestionnaire lève une exception inattendue. */
  surErreur?: (nom: string, erreur: unknown) => void;
  /** Inclure la liste des outils disponibles dans le message d'outil inconnu. Défaut : `false`. */
  listerDisponiblesSiInconnu?: boolean;
}

/**
 * Résout, valide et exécute un outil d'un registre, à l'épreuve de la pollution de prototype.
 *
 * Toute faute métier (outil inconnu, arguments invalides, échec interne du gestionnaire) est
 * rendue sous forme de `ToolResult` avec `isError: true`, jamais en erreur JSON-RPC.
 */
export async function appelerOutil<TCtx>(
  outils: Registre<TCtx>,
  nom: unknown,
  argsBruts: unknown,
  ctx: TCtx,
  options: OptionsAppelOutil = {},
): Promise<ToolResult> {
  if (typeof nom !== "string" || !Object.hasOwn(outils, nom)) {
    const libelle = typeof nom === "string" && nom.length > 0 ? nom.slice(0, 80) : "(sans nom)";
    if (options.listerDisponiblesSiInconnu) {
      return err(
        `Outil inconnu : « ${String(nom).slice(0, 80)} ». Outils disponibles : ${Object.keys(outils).join(", ")}.`,
      );
    }
    return err(`Outil inconnu : ${libelle}.`);
  }

  const raw = argsBruts ?? {};
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return err("« arguments » doit être un objet.");
  }

  const descriptor = outils[nom]!;
  const args = options.normaliser
    ? options.normaliser(nom, raw as Record<string, unknown>)
    : (raw as Record<string, unknown>);

  const erreurs = validateArgs(descriptor.inputSchema, args);
  if (erreurs.length > 0) {
    return err(`Arguments invalides pour ${nom} : ${erreurs.join(" ")}`);
  }

  try {
    return await descriptor.handler(args, ctx);
  } catch (e) {
    options.surErreur?.(nom, e);
    return err(
      "L'outil a échoué pour une raison interne. Réessayer ; si l'échec persiste, le signaler.",
    );
  }
}
