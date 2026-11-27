export const TYPES_CONNUS = ["object", "string", "integer", "number", "boolean", "array"] as const;

export type TypeConnu = (typeof TYPES_CONNUS)[number];

export interface JsonSchema {
  $schema?: string;
  type?: TypeConnu;
  properties?: Record<string, JsonSchema>;
  required?: string[];
  enum?: unknown[];
  minimum?: number;
  maximum?: number;
  minLength?: number;
  maxLength?: number;
  minItems?: number;
  maxItems?: number;
  items?: JsonSchema;
  additionalProperties?: boolean;
  description?: string;
  default?: unknown;
}

function typeOk(expected: TypeConnu | string, value: unknown): boolean {
  switch (expected) {
    case "object":
      return typeof value === "object" && value !== null && !Array.isArray(value);
    case "string":
      return typeof value === "string";
    case "integer":
      return typeof value === "number" && Number.isInteger(value);
    case "number":
      return typeof value === "number" && Number.isFinite(value);
    case "boolean":
      return typeof value === "boolean";
    case "array":
      return Array.isArray(value);
    default:
      return false;
  }
}

const NOM_TYPE: Record<string, string> = {
  object: "un objet",
  string: "une chaîne de caractères",
  integer: "un entier",
  number: "un nombre",
  boolean: "un booléen",
  array: "un tableau",
};

function estPresente(obj: Record<string, unknown>, clef: string): boolean {
  return Object.hasOwn(obj, clef) && obj[clef] !== undefined;
}

function validateValue(schema: JsonSchema, value: unknown, nom: string): string[] {
  const erreurs: string[] = [];

  if (schema.type !== undefined && !typeOk(schema.type, value)) {
    if (schema.type === "integer" && schema.minimum !== undefined && schema.maximum !== undefined) {
      erreurs.push(
        `« ${nom} » doit être un entier compris entre ${schema.minimum} et ${schema.maximum}.`,
      );
    } else {
      const libelle = Object.hasOwn(NOM_TYPE, schema.type) ? NOM_TYPE[schema.type] : schema.type;
      erreurs.push(`« ${nom} » doit être ${libelle}.`);
    }
    return erreurs;
  }

  if (schema.enum !== undefined && !schema.enum.includes(value as never)) {
    const permis = schema.enum.map((v) => JSON.stringify(v)).join(", ");
    erreurs.push(`« ${nom} » doit valoir l'une de ces valeurs : ${permis}.`);
    return erreurs;
  }

  if (typeof value === "boolean") return erreurs;

  if (typeof value === "number") {
    if (schema.minimum !== undefined && value < schema.minimum) {
      erreurs.push(`« ${nom} » doit être supérieur ou égal à ${schema.minimum}.`);
    }
    if (schema.maximum !== undefined && value > schema.maximum) {
      erreurs.push(`« ${nom} » doit être inférieur ou égal à ${schema.maximum}.`);
    }
  }

  if (typeof value === "string") {
    if (schema.maxLength !== undefined && value.length > schema.maxLength) {
      erreurs.push(`« ${nom} » doit compter au plus ${schema.maxLength} caractères.`);
    }
    if (schema.minLength !== undefined && value.trim().length < schema.minLength) {
      erreurs.push(`« ${nom} » doit compter au moins ${schema.minLength} caractères non blancs.`);
    }
  }

  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) {
      erreurs.push(`« ${nom} » doit contenir au moins ${schema.minItems} élément(s).`);
    }
    if (schema.maxItems !== undefined && value.length > schema.maxItems) {
      erreurs.push(`« ${nom} » doit contenir au plus ${schema.maxItems} élément(s).`);
    }
    if (schema.items !== undefined) {
      value.forEach((item, i) => {
        erreurs.push(...validateValue(schema.items!, item, `${nom}[${i}]`));
      });
    }
  }

  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    const obj = value as Record<string, unknown>;
    const props = schema.properties ?? {};
    if (schema.additionalProperties === false) {
      for (const clef of Object.keys(obj)) {
        if (obj[clef] !== undefined && !Object.hasOwn(props, clef)) {
          erreurs.push(`« ${clef} » n'est pas un argument reconnu.`);
        }
      }
    }
    for (const clef of schema.required ?? []) {
      if (!estPresente(obj, clef)) erreurs.push(`« ${clef} » est obligatoire.`);
    }
    for (const [clef, sous] of Object.entries(props)) {
      if (estPresente(obj, clef)) erreurs.push(...validateValue(sous, obj[clef], clef));
    }
  }

  return erreurs;
}

export function validateArgs(schema: JsonSchema, args: unknown): string[] {
  return validateValue(schema, args, "arguments");
}
