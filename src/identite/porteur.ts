export interface Porte {
  mount: string;
  queryKey?: string;
  nomsSecrets: readonly string[];
  segmentBorne?: boolean;
  autoriserChemin?: boolean;
}

export async function memeSecret(presente: string, attendu: string): Promise<boolean> {
  const enc = new TextEncoder();
  const [a, b] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(presente)),
    crypto.subtle.digest("SHA-256", enc.encode(attendu)),
  ]);
  const subtle = crypto.subtle as SubtleCrypto & {
    timingSafeEqual?: (a: BufferSource, b: BufferSource) => boolean;
  };
  if (typeof subtle.timingSafeEqual === "function") {
    return subtle.timingSafeEqual(a, b);
  }
  const va = new Uint8Array(a);
  const vb = new Uint8Array(b);
  if (va.byteLength !== vb.byteLength) return false;
  let diff = 0;
  for (let i = 0; i < va.byteLength; i++) {
    diff |= va[i]! ^ vb[i]!;
  }
  return diff === 0;
}

export function decodeOrNull(segment: string): string | null {
  try {
    return decodeURIComponent(segment);
  } catch {
    return null;
  }
}

export function sansBarresFinales(s: string): string {
  let fin = s.length;
  while (fin > 0 && s.charCodeAt(fin - 1) === 47) fin--;
  return fin === s.length ? s : s.slice(0, fin);
}

export const MAX_LONGUEUR_PORTEUR = 512;

export function bearerOf(request: Request): string | null {
  const raw = request.headers.get("Authorization");
  if (!raw || raw.length > MAX_LONGUEUR_PORTEUR * 2) return null;
  const m = /^Bearer\s+(.+)$/i.exec(raw.trim());
  const jeton = m?.[1]?.trim();
  return jeton && jeton.length <= MAX_LONGUEUR_PORTEUR ? jeton : null;
}

export type ResultatPorteurEntete =
  | { readonly etat: "absent" }
  | { readonly etat: "valide"; readonly valeur: string }
  | { readonly etat: "invalide" };

export function lirePorteurEntete(request: Request, nomEntete: string): ResultatPorteurEntete {
  if (!nomEntete || nomEntete.trim().length === 0) return { etat: "absent" };
  const raw = request.headers.get(nomEntete);
  if (raw === null) return { etat: "absent" };
  if (raw.length > MAX_LONGUEUR_PORTEUR * 2) return { etat: "invalide" };
  const valeur = raw.trim();
  if (valeur.length === 0 || valeur.length > MAX_LONGUEUR_PORTEUR) {
    return { etat: "invalide" };
  }
  return { etat: "valide", valeur };
}

export function porteursPresentes(request: Request, url: URL, porte: Porte): string[] {
  const candidats: (string | null)[] = [bearerOf(request)];

  const prefixe = `${porte.mount}/`;
  if (porte.autoriserChemin !== false && url.pathname.startsWith(prefixe)) {
    const brut = url.pathname.slice(prefixe.length);
    const rogne = sansBarresFinales(brut);
    const profond = rogne.includes("/");
    if (brut.length > 0 && !(porte.segmentBorne === true && profond)) {
      for (const forme of rogne === brut ? [brut] : [brut, rogne]) {
        candidats.push(forme);
        candidats.push(decodeOrNull(forme));
      }
    }
  }

  if (porte.queryKey !== undefined) candidats.push(url.searchParams.get(porte.queryKey));

  return [
    ...new Set(
      candidats.filter(
        (c): c is string => c !== null && c.length > 0 && c.length <= MAX_LONGUEUR_PORTEUR,
      ),
    ),
  ];
}

export function secretsAdmis(env: Record<string, unknown>, porte: Porte): string[] {
  return porte.nomsSecrets
    .map((nom) => env[nom])
    .map((v) => (typeof v === "string" ? v.trim() : undefined))
    .filter((v): v is string => v !== undefined && v.length > 0);
}

export async function trouverPorteurApparie(
  presentes: readonly string[],
  attendus: readonly string[],
): Promise<string | null> {
  const paires = attendus.flatMap((attendu) =>
    presentes.map((presente) => ({ presente, promesse: memeSecret(presente, attendu) })),
  );
  const verdicts = await Promise.all(paires.map((p) => p.promesse));
  for (let i = 0; i < verdicts.length; i++) {
    if (verdicts[i]) return paires[i]!.presente;
  }
  return null;
}

export async function apparie(
  presentes: readonly string[],
  attendus: readonly string[],
): Promise<boolean> {
  return (await trouverPorteurApparie(presentes, attendus)) !== null;
}

export function estCheminMontageAdmissible(pathname: string, porte: Porte): boolean {
  const rogne = pathname.length > 1 ? sansBarresFinales(pathname) : pathname;
  if (rogne === porte.mount) return true;
  const prefixe = `${porte.mount}/`;
  if (!pathname.startsWith(prefixe)) return false;
  if (porte.autoriserChemin === false) return false;
  if (porte.segmentBorne === true) {
    const reste = sansBarresFinales(pathname.slice(prefixe.length));
    if (reste.includes("/")) return false;
  }
  return true;
}

export function normaliserUrlMontage(request: Request, url: URL, porte: Porte): Request {
  const query = porte.queryKey === undefined ? null : url.searchParams.get(porte.queryKey);
  if (url.pathname === porte.mount && query === null) return request;

  const normalise = new URL(url);
  normalise.pathname = porte.mount;
  if (porte.queryKey !== undefined) normalise.searchParams.delete(porte.queryKey);
  return new Request(normalise.toString(), request);
}

export async function ouvrir(
  request: Request,
  url: URL,
  env: Record<string, unknown>,
  porte: Porte,
): Promise<Request | null> {
  const presentes = porteursPresentes(request, url, porte);
  const ok = await apparie(presentes, secretsAdmis(env, porte));
  if (!ok || !estCheminMontageAdmissible(url.pathname, porte)) return null;
  return normaliserUrlMontage(request, url, porte);
}

export const LONGUEUR_JETON = 43;

export const LONGUEUR_QUEUE_JETON = 6;

const MOTIF_JETON_FRAPPE = /^[A-Za-z0-9_-]{43}$/;

export function estJetonFrappe(candidat: string): boolean {
  return candidat.length === LONGUEUR_JETON && MOTIF_JETON_FRAPPE.test(candidat);
}

export function queueJeton(jeton: string): string {
  if (!estJetonFrappe(jeton)) {
    throw new Error("Format de jeton invalide pour extraction de queue.");
  }
  return jeton.slice(-LONGUEUR_QUEUE_JETON);
}

export function encoderBase64Url(octets: Uint8Array): string {
  let binaire = "";
  for (const o of octets) binaire += String.fromCharCode(o);
  return btoa(binaire).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function frapperJeton(): string {
  const octets = new Uint8Array(32);
  crypto.getRandomValues(octets);
  return encoderBase64Url(octets);
}

export async function empreinte(jeton: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(jeton));
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
