import { err, type ToolResult } from "./rpc";
import { type JsonSchema, validateArgs } from "./valide";

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

export interface DescripteurOutil {
  title: string;
  description: string;
  inputSchema: JsonSchema;
  annotations: Annotations;
  execution?: ExecutionOutil;
}

export interface ToolDescriptor<TCtx> extends DescripteurOutil {
  handler: ToolHandler<TCtx>;
}

export type Registre<TCtx> = Record<string, ToolDescriptor<TCtx>>;

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
  normaliser?: (nom: string, args: Record<string, unknown>) => Record<string, unknown>;
  surErreur?: (nom: string, erreur: unknown) => void;
  listerDisponiblesSiInconnu?: boolean;
}

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
