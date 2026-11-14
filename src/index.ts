// Socle commun des connecteurs juridiques — surface publique.
//
// RIEN D'EXÉCUTABLE ICI : uniquement des réexports. Le socle est consommé comme dépendance
// de DÉVELOPPEMENT et empaqueté par esbuild au déploiement (S2), ce qui préserve la
// décision D2 — zéro dépendance d'exécution — au sens qui compte : du code à soi, versionné
// et signé, et non une surface Dependabot.
//
// CE QUE LE SOCLE NE PORTE JAMAIS : l'analyseur de citations, les tables du Québec, le
// pipeline EPUB, les descripteurs d'outils, `INSTRUCTIONS`, `SERVER_INFO`, `callTool`, les
// gabarits de rendu du domaine. Le socle ne connaît pas le droit. S'il faut y écrire le mot
// « article », c'est qu'on s'est trompé de dépôt.

export {
  apparie,
  bearerOf,
  decodeOrNull,
  empreinte,
  frapperJeton,
  LONGUEUR_JETON,
  MAX_LONGUEUR_PORTEUR,
  memeSecret,
  ouvrir,
  type Porte,
  porteursPresentes,
  secretsAdmis,
  trimTrailingSlash,
} from "./identite/porteur";
export {
  type FormeRefus,
  methodeNonPermise,
  origineInterdite,
  refuser,
  tropDeRequetes,
} from "./identite/refus";
export {
  type CarteServeur,
  construireCarteServeur,
  type EnteteCarteServeur,
  type IdentiteServeur,
  type OptionsCarteServeur,
  type OptionsDecouverte,
  type PointDistantCarteServeur,
  repondreCarteServeur,
  resultatDecouverte,
  SERVER_CARD_CONTENT_TYPE,
  SERVER_CARD_SCHEMA,
} from "./protocole/decouverte";
export {
  type CorpsAValider,
  decoderSentinelle,
  HEADER_MISMATCH,
  type OptionsValidationEntetes,
  validerEntetes,
} from "./protocole/entetes";
export {
  corsHeaders,
  debitAcceptable,
  drapeau,
  jsonResponse,
  type Limiteur,
  type OptionsSante,
  ORIGINES_PAR_DEFAUT,
  origineAutorisee,
  origineRefusee,
  originesAdmises,
  preflight,
  reponseSante,
} from "./protocole/http";
export {
  avecCache,
  avecServerInfo,
  CLEF_CAPACITES,
  CLEF_CLIENT,
  CLEF_SERVEUR,
  CLEF_VERSION,
  clientLisible,
  complet,
  estCachable,
  habillerResultat,
  type InfoClient,
  lireMeta,
  type MetaRequete,
  type OptionsHabillage,
  type PorteeCache,
  RESULTATS_CACHABLES,
} from "./protocole/meta";
export {
  type Annotations,
  appelerOutil,
  type DescripteurOutil,
  type ExecutionOutil,
  listToolDescriptors,
  type OptionsAppelOutil,
  type Registre,
  type SupportTache,
  type ToolDescriptor,
  type ToolHandler,
} from "./protocole/registre";
export {
  err,
  errorResponse,
  INTERNAL_ERROR,
  INVALID_PARAMS,
  INVALID_REQUEST,
  isNotification,
  JsonRpcError,
  type JsonRpcMessage,
  METHOD_NOT_FOUND,
  ok,
  PARSE_ERROR,
  parseMessage,
  type RequestId,
  resultResponse,
  type ToolResult,
} from "./protocole/rpc";
export {
  lireCorpsBorne,
  MAX_OCTETS_CORPS_MCP,
  type OptionsServeurMcp,
  servirRequeteMcp,
} from "./protocole/serveur";
export { type JsonSchema, TYPES_CONNUS, type TypeConnu, validateArgs } from "./protocole/valide";
export {
  erreurVersion,
  estModerne,
  negocier,
  negocierInitialize,
  PREMIERE_MODERNE,
  UNSUPPORTED_PROTOCOL_VERSION,
  VERSION_SANS_ENTETE,
  versionAbsenteAdmise,
} from "./protocole/versions";
