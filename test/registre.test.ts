import { describe, expect, it } from "vitest";
import {
  type Annotations,
  appelerOutil,
  type DescripteurOutil,
  listToolDescriptors,
  type Registre,
  type ToolDescriptor,
} from "../src/protocole/registre";
import { ok } from "../src/protocole/rpc";

/** Contexte factice : le socle ne sait pas ce qu'un dépôt y met, et c'est le point. */
interface CtxFactice {
  db: string;
  client: { appeler: () => void };
}

const outil = (
  title: string,
  annotations: Annotations = { readOnlyHint: true },
): ToolDescriptor<CtxFactice> => ({
  title,
  description: `description de ${title}`,
  inputSchema: { type: "object", additionalProperties: false },
  annotations,
  handler: async () => ok("fait"),
});

const registre: Registre<CtxFactice> = {
  zebre: outil("Zèbre"),
  alpha: outil("Alpha"),
};

describe("listToolDescriptors", () => {
  it("émet les cinq champs, et RIEN d'autre", () => {
    const [premier] = listToolDescriptors(registre);
    expect(Object.keys(premier ?? {})).toEqual([
      "name",
      "title",
      "description",
      "inputSchema",
      "annotations",
    ]);
  });

  it("l'ORDRE DES CLEFS est un contrat — tools/list doit rester octet pour octet", () => {
    // `JSON.stringify` suit l'ordre d'insertion. Réordonner ces cinq champs changerait la
    // charge utile sans changer sa valeur, ce qui invaliderait le critère de la marche 1
    // et le cache d'invite des clients.
    const json = JSON.stringify(listToolDescriptors(registre)[0]);
    expect(json.indexOf('"name"')).toBeLessThan(json.indexOf('"title"'));
    expect(json.indexOf('"title"')).toBeLessThan(json.indexOf('"description"'));
    expect(json.indexOf('"description"')).toBeLessThan(json.indexOf('"inputSchema"'));
    expect(json.indexOf('"inputSchema"')).toBeLessThan(json.indexOf('"annotations"'));
  });

  it("conserve l'ordre d'INSERTION, et ne trie pas par nom", () => {
    // Le tri alphabétique arrive à la marche 3, sur un champ `ordre` : trier ici
    // rétrograderait l'outil pivot que les INSTRUCTIONS désignent comme point de départ.
    expect(listToolDescriptors(registre).map((d) => d.name)).toEqual(["zebre", "alpha"]);
  });

  it("n'expose JAMAIS le gestionnaire", () => {
    for (const d of listToolDescriptors(registre)) expect(d).not.toHaveProperty("handler");
  });

  it("copie les annotations au lieu de partager la référence", () => {
    const partagees = { readOnlyHint: true };
    const r: Registre<CtxFactice> = { a: outil("A", partagees) };
    const [d] = listToolDescriptors(r);
    (d?.annotations as Record<string, unknown>).readOnlyHint = false;
    expect(partagees.readOnlyHint).toBe(true);
  });

  it("chaque outil porte SES annotations — le socle n'en impose aucune", () => {
    const r: Registre<CtxFactice> = {
      sortant: outil("Sortant", { readOnlyHint: true, openWorldHint: true }),
      local: outil("Local", { readOnlyHint: true, openWorldHint: false, idempotentHint: true }),
    };
    const [a, b] = listToolDescriptors(r);
    expect(a?.annotations).toEqual({ readOnlyHint: true, openWorldHint: true });
    expect(b?.annotations).toEqual({
      readOnlyHint: true,
      openWorldHint: false,
      idempotentHint: true,
    });
  });

  it("un registre vide rend un tableau vide", () => {
    expect(listToolDescriptors({} as Registre<CtxFactice>)).toEqual([]);
  });
});

describe("execution optionnel et DescripteurOutil public", () => {
  it("émet execution comme sixième clef seulement lorsqu'il est défini", () => {
    const publicOnly: Record<string, DescripteurOutil> = {
      avec_exec: {
        title: "Avec tâche",
        description: "Test",
        inputSchema: { type: "object" },
        annotations: { readOnlyHint: true },
        execution: { taskSupport: "forbidden" },
      },
      sans_exec: {
        title: "Sans tâche",
        description: "Test",
        inputSchema: { type: "object" },
        annotations: { readOnlyHint: true },
      },
    };
    const res = listToolDescriptors(publicOnly);
    expect(Object.keys(res[0]!)).toEqual([
      "name",
      "title",
      "description",
      "inputSchema",
      "annotations",
      "execution",
    ]);
    expect(res[0]!.execution).toEqual({ taskSupport: "forbidden" });
    expect(Object.keys(res[1]!)).toEqual([
      "name",
      "title",
      "description",
      "inputSchema",
      "annotations",
    ]);
  });
});

describe("appelerOutil", () => {
  const registre: Registre<{ coef: number }> = {
    echo: {
      title: "Écho",
      description: "Renvoie q",
      inputSchema: {
        type: "object",
        properties: { q: { type: "string", minLength: 1 } },
        required: ["q"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true },
      handler: async (args, ctx) => ok(`${String(args.q)}:${ctx.coef}`),
    },
    explose: {
      title: "Explose",
      description: "Lève une erreur interne",
      inputSchema: { type: "object" },
      annotations: { readOnlyHint: true },
      handler: async () => {
        throw new Error("boom secret");
      },
    },
  };

  it("rejette les clefs de prototype comme outil inconnu", async () => {
    for (const nom of ["toString", "constructor", "__proto__", "valueOf"]) {
      const r = await appelerOutil(registre, nom, {}, { coef: 1 });
      expect(r.isError).toBe(true);
      expect(r.content[0]!.text).toContain("Outil inconnu");
    }
  });

  it("liste les outils disponibles lorsque listerDisponiblesSiInconnu est actif", async () => {
    const r = await appelerOutil(
      registre,
      "absent",
      {},
      { coef: 1 },
      { listerDisponiblesSiInconnu: true },
    );
    expect(r.isError).toBe(true);
    expect(r.content[0]!.text).toContain("echo, explose");
  });

  it("rejette des arguments non-objet sans atteindre le gestionnaire", async () => {
    const r = await appelerOutil(registre, "echo", ["pas", "un", "objet"], { coef: 1 });
    expect(r.isError).toBe(true);
    expect(r.content[0]!.text).toContain("objet");
  });

  it("applique normaliser avant la validation du schéma", async () => {
    const r = await appelerOutil(
      registre,
      "echo",
      { q: 123 },
      { coef: 2 },
      { normaliser: (_nom, args) => ({ ...args, q: String(args.q) }) },
    );
    expect(r.isError).toBe(false);
    expect(r.content[0]!.text).toBe("123:2");
  });

  it("intercepte une exception interne et appelle surErreur sans fuite", async () => {
    const captures: string[] = [];
    const r = await appelerOutil(
      registre,
      "explose",
      {},
      { coef: 1 },
      { surErreur: (nom) => captures.push(nom) },
    );
    expect(r.isError).toBe(true);
    expect(r.content[0]!.text).not.toContain("boom secret");
    expect(captures).toEqual(["explose"]);
  });
});
