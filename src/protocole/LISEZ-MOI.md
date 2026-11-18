# `protocole/`

Enveloppe JSON-RPC 2.0, transport Streamable HTTP **sans état**, validation d'en-têtes, `_meta`, négociation de versions, découverte (`server/discover` et fiche SEP-2127 `/mcp/server-card`), validation de schémas fermée par défaut, registre d'outils et répartiteur HTTP unifié.

| Fichier | Contenu |
|---|---|
| `rpc.ts` | Enveloppe JSON-RPC 2.0 (`parseMessage` avec propagation de `id` valide et rejet des `params` tableaux, `isNotification`, `ok`, `err`, `JsonRpcError`). |
| `valide.ts` | Validateur JSON Schema en sous-ensemble : type `TypeConnu`, `typeOk` **fermé par défaut**, sûreté prototype via `Object.hasOwn` et gestion explicite de `undefined`. |
| `registre.ts` | `DescripteurOutil`, `ToolDescriptor<TCtx>`, `ExecutionOutil`, `listToolDescriptors`, et `appelerOutil` (résolution propre à l'épreuve du prototype, normalisation optionnelle, capture sûre des exceptions). |
| `versions.ts` | Négociation de version (`negocier`, `-32022`), `estModerne` (`>= 2026-07-28`), `versionAbsenteAdmise`, et pont sans état `negocierInitialize`. |
| `entetes.ts` | Validation `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`, sentinelle `=?base64?…?=`, `TextDecoder` UTF-8 fatal, contrôle `_meta["io.modelcontextprotocol/protocolVersion"]` non contournable et `exigerVersionMeta`. |
| `meta.ts` | Extraction durcie de `_meta` (`lireMeta`, `clientLisible`), `avecServerInfo`, indices de cache (`avecCache`, `complet`) et `habillerResultat`. |
| `decouverte.ts` | `resultatDecouverte` (`server/discover`), et fiche SEP-2127 (`/mcp/server-card`) via `SERVER_CARD_SCHEMA`, `SERVER_CARD_CONTENT_TYPE`, `construireCarteServeur` et `repondreCarteServeur`. |
| `http.ts` | CORS, `ORIGINES_PAR_DEFAUT` (`claude.ai`, `claude.com`, `gemini.google.com`, `aistudio.google.com`), `originesAdmises` normalisé, `preflight` (extensible par en-têtes supplémentaires validés), limitation de débit `debitAcceptable` (échoue ouvert), `drapeau` et `reponseSante`. |
| `serveur.ts` | Lecteur de corps borné `lireCorpsBorne` (`MAX_OCTETS_CORPS_MCP = 65_536`) et répartiteur HTTP sans état `servirRequeteMcp`. |
