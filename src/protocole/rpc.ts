export const PARSE_ERROR = -32700;
export const INVALID_REQUEST = -32600;
export const METHOD_NOT_FOUND = -32601;
export const INVALID_PARAMS = -32602;
export const INTERNAL_ERROR = -32603;

export type RequestId = string | number | null;

export interface JsonRpcMessage {
  jsonrpc: "2.0";
  method: string;
  id?: RequestId;
  params?: Record<string, unknown>;
}

export class JsonRpcError extends Error {
  readonly code: number;
  readonly requestId: RequestId;

  constructor(code: number, message: string, requestId: RequestId = null) {
    super(message);
    this.name = "JsonRpcError";
    this.code = code;
    this.requestId = requestId;
  }
}

export function resultResponse(id: RequestId, result: unknown): Record<string, unknown> {
  return { jsonrpc: "2.0", id, result };
}

export function errorResponse(
  id: RequestId,
  code: number,
  message: string,
  data?: unknown,
): Record<string, unknown> {
  const error: Record<string, unknown> = { code, message };
  if (data !== undefined) error.data = data;
  return { jsonrpc: "2.0", id, error };
}

function idValide(m: Record<string, unknown>): RequestId {
  if (!Object.hasOwn(m, "id")) return null;
  if (
    m.id === null ||
    typeof m.id === "string" ||
    (typeof m.id === "number" && Number.isFinite(m.id))
  ) {
    return m.id;
  }
  return null;
}

export function parseMessage(raw: string): JsonRpcMessage {
  let message: unknown;
  try {
    message = JSON.parse(raw);
  } catch {
    throw new JsonRpcError(PARSE_ERROR, "Erreur d'analyse syntaxique (JSON invalide).");
  }

  if (Array.isArray(message)) {
    throw new JsonRpcError(INVALID_REQUEST, "Les requêtes groupées ne sont pas prises en charge.");
  }
  if (message === null || typeof message !== "object") {
    throw new JsonRpcError(INVALID_REQUEST, "Requête invalide.");
  }

  const m = message as Record<string, unknown>;
  const id = idValide(m);
  if (m.jsonrpc !== "2.0") {
    throw new JsonRpcError(
      INVALID_REQUEST,
      'Requête invalide : « jsonrpc » doit valoir "2.0".',
      id,
    );
  }
  if (typeof m.method !== "string" || m.method.length === 0) {
    throw new JsonRpcError(
      INVALID_REQUEST,
      "Requête invalide : « method » doit être une chaîne non vide.",
      id,
    );
  }
  if (
    Object.hasOwn(m, "id") &&
    m.id !== null &&
    typeof m.id !== "string" &&
    !(typeof m.id === "number" && Number.isFinite(m.id))
  ) {
    throw new JsonRpcError(
      INVALID_REQUEST,
      "Requête invalide : « id » doit être une chaîne ou un nombre.",
    );
  }
  if (
    m.params !== undefined &&
    m.params !== null &&
    (typeof m.params !== "object" || Array.isArray(m.params))
  ) {
    throw new JsonRpcError(
      INVALID_REQUEST,
      "Requête invalide : « params » doit être un objet.",
      id,
    );
  }

  return {
    jsonrpc: "2.0",
    method: m.method,
    id: (Object.hasOwn(m, "id") ? m.id : undefined) as RequestId | undefined,
    params: (m.params ?? undefined) as Record<string, unknown> | undefined,
  };
}

export function isNotification(m: JsonRpcMessage): boolean {
  return m.id === undefined || m.id === null;
}

export interface ToolResult {
  content: Array<{ type: "text"; text: string }>;
  isError: boolean;
  structuredContent?: Record<string, unknown>;
}

export function ok(text: string, structured?: Record<string, unknown>): ToolResult {
  return {
    content: [{ type: "text", text }],
    isError: false,
    ...(structured && Object.keys(structured).length > 0 ? { structuredContent: structured } : {}),
  };
}

export function err(text: string): ToolResult {
  return { content: [{ type: "text", text }], isError: true };
}
