# MCP-Socle — Architecture, principes et consignes de travail

Socle commun d'infrastructure logicielle partagée pour les serveurs MCP et le portail d'accès du cabinet (`@poirierlavoie/mcp-socle`). Ce document définit le rôle architectural du socle au sein du cadre global, ses contrats opérationnels stricts (ouverture multilocataire, pipeline à 12 étapes, compatibilité Deep Research, coffre HKDF/AAD, portes `G1–G38` et `S20`) et les invariants à maintenir pour prévenir toute dérive architecturale. Il s'applique de manière identique à Claude et à Gemini / Antigravity (`CLAUDE.md` et `GEMINI.md` doivent rester identiques octet pour octet et sous 24 000 octets UTF-8 LF).

---

## 1. Rôle architectural et intégration dans le cadre global

Le cadre `droit-civil-quebecois` (`v3.4.0`, anciennement `pratique-civile-quebecoise`) repose sur une architecture découplée en trois couches complétée par le portail d'admission et d'autorisation `MCP-Acces` :

```
          ┌──────────────────────────────────────────────────────────────┐
          │         droit-civil-quebecois (Plugin Cadre v3.4.0)          │
          │ 10 compétences · 60 feuilles · 6 personas · 4 scripts stdlib │
          └─────────┬───────────────────────┬──────────────────┬─────────┘
                    │                       │                  │
        (serveur `lois`, 10 outils)  (serveur `juris`, 12)  (serveur `outils`, 15)
                    │                       │                  │
                    ▼                       ▼                  ▼
         ┌─────────────────────┐ ┌─────────────────────┐ ┌──────────────────────────┐
         │   MCP-Legislation   │ │  MCP-Jurisprudence  │ │        MCP-Outils        │
         │ `/mcp` (404) &      │ │ `/mcp` (404) &      │ │   `/mcp` (404) &         │
         │ `/mcp/oauth` (401)  │ │ `/mcp/oauth` (401)  │ │   `/mcp/oauth` (401)     │
         │  D1 + Vectorize +   │ │  D1 cache partagé   │ │   4 D1 lecture seule,    │
         │  Workers AI opt-out │ │  BYOK strict coffre │ │   sans clé CanLII        │
         └──────────┬──────────┘ └──────────┬──────────┘ └────────────┬─────────────┘
                    │                       │                         │
                    ├───────────┬───────────┴────┬────────────────────┘
                    │           ▼ (base D1 `DB_IDENTITE`)             ▼
                    │    ┌──────────────┐          ┌────────────────────┐
                    │    │ mcp-identite │◄─────────┤     MCP-Acces      │
                    │    │  (D1 partagé)│          │ acces.poirier...ca │
                    │    └──────────────┘          │ /demande /moi OAuth│
                    │                              └────────┬───────────┘
                    └───────────┬───────────────────────────┘
                                ▼ (dépendance de dev `#v0.8.8`, zéro runtime dep)
                 ┌─────────────────────────────┐
                 │          MCP-Socle          │
                 │  Transport JSON-RPC 2.0     │
                 │  Streamable HTTP sans état  │
                 │  Identité D1, Coffre, OAuth │
                 │  Débit Deep Research & Quotas│
                 │  Zéro concept juridique     │
                 └─────────────────────────────┘
```

### Place du socle dans l'écosystème
- **Bibliothèque (`@poirierlavoie/mcp-socle`)** : Transport MCP Streamable HTTP sans état (`2026-07-28`), JSON-RPC 2.0, auth porteur partagé et jeton D1 (`titulaire`/`jeton`), coffre (`HKDF-SHA256` + `AES-256-GCM`), OAuth 2.1 / RFC 9728 / RFC 8414 / PKCE `S256` / CIMD anti-SSRF, débit Deep Research à deux étages, télémétrie technique sans contenu et SEP-2127 (`/mcp/server-card`, `/.well-known/mcp/server-card.json`).
- **Consommateurs directs** : `MCP-Legislation`, `MCP-Jurisprudence`, `MCP-Outils` et `MCP-Acces` via `devDependencies` (`github:jpoirierlavoie/MCP-Socle#v0.8.8`), empaquetés par `esbuild` / Wrangler.
- **Surfaces clientes** : OAuth 2.1 sur `/mcp/oauth` (`401` + `WWW-Authenticate` RFC 9728) pour Claude Code/Desktop, Antigravity, Gemini CLI/App/Enterprise, ChatGPT Web/Desktop, Codex, `claude.ai`/Research ; jeton direct sur `/mcp` (`404` vide) pour CLI/CI (`Bearer`), repli `?key=` (`claude.ai`), API OpenAI Responses et Gemini API Deep Research.

---

## 2. ⛔ La règle de frontière absolue : « Le socle ne connaît pas le droit »

**Le socle ne connaît aucun concept juridique.** S'il faut y écrire un identifiant ou un concept du domaine juridique (`article`, `loi`, `décision`, `greffe`, `palais`, `tribunal`, `canlii`, `mjq`, `cqlr`, `rlrq`, `juridique`, `legislation_`, `jurisprudence_`), c'est une violation de frontière et une erreur de dépôt.

- **Ne montent JAMAIS ici** : L'analyseur de citations, les tables judiciaires ou de greffe, le pipeline d'ingestion législative, les descripteurs d'outils, les constantes `INSTRUCTIONS`, `SERVER_INFO`, `COERCITIONS`, les gabarits de rendu en français, la sortie structurée et les mises en garde légales (`GARDE_*`).
- **Montent UNIQUEMENT ici** : L'identité cryptographique, le chiffrement par enveloppe générique, la découverte et validation OAuth 2.1 / PKCE, la gouverne de débit et de quotas par classes abstraites, la télémétrie technique sans contenu, le transport réseau MCP Streamable HTTP sans état, le routage JSON-RPC 2.0, la validation de schémas et la découverte de service.
- **Garde automatisée** : Le test `test/doc.test.ts` vérifie formellement qu'aucun terme de domaine juridique n'apparaît dans `src/`, qu'aucun `Math.random` n'est utilisé, et qu'aucune fonction exportée ne divulgue de secret déchiffré en clair (`G10`, `G33`).

---

## 3. Architecture des modules (`src/`)

Le code source est strictement partitionné en deux sous-systèmes réexportés par un point d'entrée unique (`src/index.ts`) :

| Sous-système | Fichiers | Responsabilités et contrats |
|---|---|---|
| `src/identite/` | `porteur.ts`<br>`refus.ts`<br>`titulaire.ts`<br>`coffre.ts`<br>`oauth.ts`<br>`gouverne.ts` | **Contrôle d'accès, crypto, OAuth 2.1 et gouverne** :<br>- `porteur.ts` : 3 porteurs (`Bearer`, `?key=`, `/mcp/<jeton>`), `lirePorteurEntete`, `estCheminMontageAdmissible`, SHA-256 à temps constant (`memeSecret`, `apparie`, `trouverPorteurApparie`), `MAX_LONGUEUR_PORTEUR = 512`, `encoderBase64Url`, `frapperJeton` (`43` car. `base64url`), `queueJeton`.<br>- `refus.ts` : `404` vide (`/mcp`), `401` + `WWW-Authenticate` RFC 9728 (`/mcp/oauth`), `403`, `429`, `405` (`Cache-Control: no-store`).<br>- `titulaire.ts` : `resoudreJeton`, `ouvrirPrincipal` (`surEmpreinteValide`, fermé sur `expire_le === ""`), `horodatageUtcMs`, `jourUtc`, états (`actif`, `surveille`, `limite`), portée `tous`/`les_deux`/connecteur, `vu_le`.<br>- `coffre.ts` : `HKDF-SHA256` + `AES-256-GCM`, `ouvrirCoffre` fermé (`G10`), `empreinteCoffre`, `repereCoffre` (`HMAC-SHA256`), `expurger` (`G9`).<br>- `oauth.ts` : RFC 9728 / RFC 8414 / RFC 9207 `iss`, PKCE `S256` (`verifierDefiPkceS256`), `porteesCanoniques`, `normaliserPorteeOAuth`, `redirect_uri` (`URIS_REDIRECTION_CLAUDE`, boucle locale `/oauth-callback`), `validerMetadonneesInscriptionDcr`, `estClientIdMetadonneesValide`, `validerMetadonneesClientCimd`.<br>- `gouverne.ts` : `resoudreModeAdmission`, `demande_acces`/`invitation_acces`, quarantaine IP + laissez-passer SHA-256 (`S15`), débit `titulaireId`, quotas (`local`, `sortant`, `semantique`), `EvenementTechnique` (90 j), `CHECK GLOB`, `purgerRetentionsD1`, `supprimerCompteTitulaireD1`, `retirerEntreeCoffreD1`, `POLITIQUES_RETENTION_IDENTITE`, `jourUtc` (réexporté depuis `titulaire.ts`), `verifierSchemaSansContenuIdentifiant` (`G13`, `G25`). |
| `src/protocole/` | `rpc.ts`<br>`valide.ts`<br>`registre.ts`<br>`versions.ts`<br>`entetes.ts`<br>`meta.ts`<br>`decouverte.ts`<br>`http.ts`<br>`serveur.ts` | **Transport MCP Streamable HTTP et protocole** :<br>- `rpc.ts` : enveloppe JSON-RPC 2.0 (`parseMessage` avec propagation de `id` valide et rejet des `params` tableaux, `isNotification`, `ok`, `err`, `JsonRpcError`).<br>- `valide.ts` : validateur JSON Schema en sous-ensemble (`TypeConnu`, `typeOk` **fermé par défaut**, sûreté prototype `Object.hasOwn`, gestion explicite d'`undefined`).<br>- `registre.ts` : `DescripteurOutil`, `ToolDescriptor<TCtx>`, `ExecutionOutil`, `listToolDescriptors`, `appelerOutil` (résolution à l'épreuve du prototype, normalisation optionnelle, capture sûre des exceptions).<br>- `versions.ts` : négociation (`negocier`, `-32022` `UNSUPPORTED_PROTOCOL_VERSION` avec `{ supported, requested }`), `PREMIERE_MODERNE = "2026-07-28"`, `VERSION_SANS_ENTETE = "2025-03-26"`, `estModerne`, `versionAbsenteAdmise` (`initialize` toujours exempté), pont `negocierInitialize`.<br>- `entetes.ts` : validation `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`, `HEADER_MISMATCH` (`-32020`), sentinelle `=?base64?…?=`, `TextDecoder` UTF-8 fatal (`{ fatal: true, ignoreBOM: false }`), contrôle `_meta` non contournable et `exigerVersionMeta`.<br>- `meta.ts` : extraction durcie de `_meta` (`lireMeta`, `clientLisible`), `avecServerInfo`, indices de cache (`avecCache`, `complet`, `RESULTATS_CACHABLES`) et `habillerResultat`.<br>- `decouverte.ts` : `resultatDecouverte` (`server/discover`), fiche SEP-2127 `/mcp/server-card` et `/.well-known/mcp/server-card.json` (`CHEMIN_WELL_KNOWN_CARTE_SERVEUR`, `SERVER_CARD_CONTENT_TYPE`, `construireCarteServeur`, `repondreCarteServeur`).<br>- `http.ts` : CORS (`ORIGINES_PAR_DEFAUT`, `originesAdmises`, `origineRefusee`, `preflight` extensible), `debitAcceptable` (échoue ouvert), `drapeau`, `JSON_HEADERS`, `NO_STORE_HEADERS`, `jsonResponse`, `reponseSante` (tous deux avec `Cache-Control: no-store`) et `repondreDocumentJsonPublic`.<br>- `serveur.ts` : lecteur de corps borné `lireCorpsBorne` (`MAX_OCTETS_CORPS_MCP = 65_536`) et répartiteur HTTP sans état `servirRequeteMcp`. |
| `src/index.ts` | `index.ts` | Point d'entrée unique réexportant la totalité des interfaces publiques. |
| `scripts/verifier-audit.mjs` | `./verifier-audit` | Exécuteur d'audit partagé (`executerAudit`, `lireExemptionsOsvToml`, `extraireAvisDirects`, `evaluerConformiteAudit`, `autoVerifierLogiqueAudit`) vérifiant `npm audit` prod/dev et la parité stricte `osv-scanner.toml`. |

### Contrats opérationnels, pipeline à 12 étapes, coffre et portes `G1–G38`

1. **Préséance des routes avant `/mcp/<jeton>` et RFC 9728 racine `404`** : `/mcp/server-card`, `/.well-known/mcp/server-card.json` et `/mcp/oauth` sont interceptés **avant** `/mcp/<jeton>` ; `/mcp/oauth/<x>` est rejeté (`estCheminMontageAdmissible`). Seul `GET /.well-known/oauth-protected-resource/mcp/oauth` est servi ; la racine `GET /.well-known/oauth-protected-resource` reste `404` (évite la bascule OAuth sur faute `?key=`).
2. **Pipeline MCP en 12 étapes** : (1) `MCP_ENABLED !== "true"` -> `404` sur `/mcp*`, `/.well-known/oauth-protected-resource*`, `/health` (jamais `/` ni pages publiques `MCP-Acces`) ; (2) `origineRefusee` -> `403` sans CORS ; (3) `OPTIONS` -> `204` (`preflight`, incl. `X-Clef-CanLII` sur `juris`), sans limite (`G6`) ; (4) `verifierDebitPreAuth` avec laissez-passer SHA-256 (`quarantaine.marquerEmpreinteValide`, jetons 43 car. et secrets 64 hex) -> `404` (`/mcp`) ou `429` (`/mcp/oauth`) ; (5) `ouvrirPrincipal` (`resoudreJeton` + `trouverPorteurApparie`, `surEmpreinteValide` ssi `estCheminMontageAdmissible`) ; échec -> `enregistrerEchecAuth` (éviction empreintes + IP `20/min` + `"echecs"` `300/min`) -> `404` vide (`/mcp`) ou `401` RFC 9728 (`/mcp/oauth`) ; (6) `POST` requis APRÈS identité sur `/mcp` (`G23` -> `405` auth, `404` anon) ; (7) `verifierDebitTitulaire` -> `429` + `Retry-After` (`60s` `actif`/`surveille`, `300s` `limite`) ; (8) `lireCompteursJourD1(titulaire_id, jour)` ; (9) corps `64 Kio`, version et en-têtes (`servirRequeteMcp`) ; (10) `verifierQuotaJour` sur l'outil du **corps** (jamais `Mcp-Name` seul) -> `200` `erreurQuotaEpuise` (`isError: true`) ; (11) garde BYOK `MCP-Jurisprudence` avant cache D1 `cases`/`citator_*` : `ouvrirCoffre` (`lirePorteurEntete(req, "X-Clef-CanLII")` -> `coffre_clef`, fermé `[CLEF_REFUSEE]` si en-tête invalide) -> `200` (`[CLEF_ABSENTE]`/`[CLEF_REFUSEE]`) ; (12) exécution + écritures différées `ctx.waitUntil` (`compteur_jour`, `evenement_technique`).
3. **Invariance `tools/list` et annotations Deep Research** : `tools/list` et `server/discover` émettent `resultType: "complete"`, `ttlMs: 3_600_000`, `cacheScope: "public"` sous `2026-07-28`. Les descripteurs ne varient JAMAIS par `titulaire` (l'état du titulaire va dans la **sortie**). Attributs : `additionalProperties: false`, `readOnlyHint: true`, `destructiveHint: false`, `idempotentHint: true` (et `openWorldHint: false` hors réseau).
4. **Allocations `namespace_id` et quotas UTC (`G34`, `G12`)** : `namespace_id` distincts (jamais `"1001"`) : `MCP-Legislation` `1011` (`RL_PRE_AUTH_IP` `600/60s`), `1012` (`RL_ECHEC_IP` `20/60s`), `1013` (`RL_ECHECS_GLOBAL` `300/60s`), `1014` (`RL_TITULAIRE` `300/60s`), `1015` (`RL_TITULAIRE_LIMITE` `20/60s`) ; `MCP-Jurisprudence` `1021–1023`, `1024` (`180/60s`, `CANLII_MIN_INTERVAL_MS=600`), `1025` (`20/60s`) ; `MCP-Acces` `1031` (`RL_DEMANDE_IP` `10/60s`), `1032` (`RL_OAUTH_IP` `60/60s`) ; `MCP-Outils` `1041–1043`, `1044` (`300/60s`), `1045` (`20/60s`). Quotas (`actif`/`limite`) : `local` (`3 000`/`300`), `sortant` (`200`/`20`), `semantique` (`150`/`15`) ; `registre_gouverne` ajout seul (`G12`).
5. **Coffre HKDF/AAD et secrets** : `DEK = HKDF-SHA256(COFFRE_MAITRE_V{n}, titulaireId, "${usage}/v1")`, `AES-256-GCM` (IV 12 o, `aad = "${titulaireId}:${usage}:${version}"`). `COFFRE_MAITRE_V1` (>= 32 car.) est provisionné UNIQUEMENT sur `MCP-Acces` et `MCP-Jurisprudence` (jamais `MCP-Legislation`). `empreinteCoffre` (`HMAC-SHA256`, index non unique `cc_par_empreinte`) signale sans bloquer ; `repereCoffre` masque (`0` `< 16`, `2` `16..23`, `4` `>= 24`, `+ #<8 hex>`).
6. **Asymétrie `debitAcceptable` et JSON-RPC** : `debitAcceptable` échoue **ouvert** (coût uniquement) vs auth/schémas **fermés** (`G21`). Codes : `HEADER_MISMATCH = -32020` (HTTP `400`), `UNSUPPORTED_PROTOCOL_VERSION = -32022` (HTTP `400`, `{ supported, requested }`), `INVALID_PARAMS = -32602` inutilisé pour arguments d'outil (HTTP `200` `ToolResult` `isError: true`).
7. **Portes `G1–G38` et `S20`** : `G1–G4` (build/doc/déterminisme), `G6` (pré-vol sans limite / `403` pré-auth), `G7` (sans oracle), `G8` (BYOK fermé, bloque D1), `G9` (`expurger`, zéro `console.*`), `G10` (aucune clé en clair), `G12` (`registre_gouverne` ajout seul), `G13`/`G25` (zéro contenu / zéro horodatage sous-journalier sur texte libre), `G16`/`G18` (purges indexées Loi 25, `POLITIQUES_RETENTION_IDENTITE`), `G19` (zéro `x-mcp-header`), `G21` (auth/D1/schémas fermés), `G22–G24` (`MCP_ENABLED`, `GET /mcp` anon `404`, `SERT_AVANT_2025_06_18`), `G32` (quarantaine IP vs laissez-passer Deep Research), `G33` (`frapperJeton` CSPRNG, zéro `Math.random`), `G34` (`namespace_id` distincts), `G35`/`G36` (PKCE `S256` et anti-SSRF), `G37` (`observability.enabled: false`), `G38` (zéro `fetched_at` `juris`), `S20` (`/conformite` et `/gouverne` dérivés du code).

---

## 4. Surfaces de synchronisation du greffon cadre (`droit-civil-quebecois`)

Toute modification d'interfaces, de transport, d'authentification ou de version dans le socle ou ses Workers aval doit maintenir la cohérence du greffon cadre `droit-civil-quebecois` :
1. **Manifestes clients et places de marché (9)** : `.mcp.json`, `mcp_config.json`, `gemini-extension.json`, `.antigravity-plugin/plugin.json`, `plugin.json`, `.codex-plugin/plugin.json`, `.agents/plugins/marketplace.json`, `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`.
2. **Compétences (`skills/`) et personas (`agents/`)** : 5 orchestrateurs `phase-*`, 5 services (`recherche-juridique`, `analyse-et-strategie`, `redaction-juridique`, `production-et-conformite`, `gestion-du-mandat`, 60 feuilles, noyau `SAFETY-KERNEL` identique au bit près) et 6 personas de contre-épreuve (`agents/*.md`).
3. **Scripts de synchronisation et validation** :
   - `python verifier.py`
   - `python evals/executer_evals.py --auto-test`
   - `python verifier_tout.py --mode mock` / `python verifier_tout.py --mode live`
   - `python scripts/synchroniser_plugin_gemini.py --apply`

---

## 5. Invariants critiques et règles anti-dérive

1. **Zéro dépendance d'exécution** : `package.json` ne doit comporter aucune section `dependencies`. Tout le code de production réside dans `src/` sur les API Web Standards de Cloudflare Workers.
2. **Consommation par étiquette git immuable** : Le socle est consommé par tag semver immuable (`#v0.8.8`). Interdiction absolue de `git push --force` ou de réécriture d'étiquette publiée. Toute évolution de contrat impose une incrémentation de version.
3. **`queryKey` optionnel dans `Porte`** : L'acceptation de `?key=` reste un choix explicite sur `/mcp`, tandis que `/mcp/oauth` n'accepte que `Authorization: Bearer` conformément à OAuth 2.1.
4. **Fermé par défaut, sans exception** :
   - Authentification et D1 : aucune défaillance de configuration ou de lecture ne doit ouvrir un point d'accès (`G21`).
   - Coffre : aucune fonction exportée ne retourne un secret déchiffré en clair (`G10`) ; aucune retombée sur une clé d'exploitant (`G8`).
   - OAuth 2.1 : seul PKCE `S256` est accepté ; tout littéral IP ou hôte interne est rejeté sur les URLs CIMD.
   - Schémas, prototype (`Object.hasOwn`), en-têtes UTF-8 fatals et corps borné à `65 536` octets.
5. **Exécution des tests sous `workerd` (Miniflare)** : Les tests tournent exclusivement dans Cloudflare Workers via `@cloudflare/vitest-plugin` (`test/fumee.test.ts`).
6. **Intégrité des tests de garde** : Lorsqu'un test de garde échoue, on rétablit la garantie dans le code ; on n'abaisse jamais l'exigence du test.
7. **Discipline documentaire multi-dépôts** :
   - `GEMINI.md` et `CLAUDE.md` sont identiques octet pour octet sous le plafond de 24 000 octets UTF-8 (> 1 000 octets).
   - Doivent obligatoirement mentionner `# MCP-Socle` et l'étiquette courante `#v0.8.8`.
   - Proscription absolue de toute référence aux anciens identifiants de dépôts retirés.
8. **Zéro journalisation de contenu** : Ni le socle ni les Workers consommateurs n'enregistrent le texte des requêtes (`search_log` et `forme_requete` interdites par `verifierSchemaSansContenuIdentifiant`).
9. **Secrets locaux** : Ne jamais lire, consigner, journaliser ni committer de secrets (`cf.token`, `*.token`, `.dev.vars`, `mcp.url`, `.env*`).
10. **Gouvernance Git (`main-pr-and-ci`)** : Le contournement administrateur du ruleset `main-pr-and-ci` est restreint à `pull_request` — **ne jamais pousser directement sur `main`** ; travailler sur une branche dédiée, ouvrir une Pull Request, attendre le passage des contrôles requis (`CI`, `CodeQL`, `OSV-Scanner`, `Trivy`), puis fusionner par *squash* (`gh pr merge --squash --delete-branch`).

---

## 6. Commandes de vérification (PowerShell Windows)

Avec la politique d'exécution Windows restreinte, utiliser les commandes `.cmd` :

```powershell
npm.cmd ci
npm.cmd run type-check    # npx.cmd tsc --noEmit
npm.cmd run lint          # npx.cmd biome check .
npm.cmd test              # npx.cmd vitest run (environnement workerd)
npm.cmd run audit         # 0 vulnérabilité d'exécution + parité stricte osv-scanner.toml
```

## 7. Évaluation d'impact obligatoire (4 axes)

**Aucune tâche touchant `@poirierlavoie/mcp-socle` n'est terminée tant que son impact n'a pas été évalué et explicitement rapporté sur chacun des quatre axes ci-dessous** (« non touché » doit être énoncé avec justification, jamais passé sous silence) :

| # | Axe d'impact | Éléments à inspecter | Ce qui impose une action |
|---|---|---|---|
| 1 | **Code, contrats et gardes (`src/`, `test/`)** | `src/identite/`, `src/protocole/`, `src/index.ts`, `scripts/verifier-audit.mjs`, `test/` (`workerd`), `test/doc.test.ts` | Toute évolution d'API, de coffre, d'OAuth 2.1, de quotas/débit, de validation JSON Schema, d'en-têtes MCP, de porteurs ou de refus (`404`/`401`/`403`/`429`) |
| 2 | **`README.md` et gouvernance du dépôt** | `README.md`, `SECURITY.md`, `LICENSE` (`Apache-2.0`), `NOTICE`, `package.json`, `CLAUDE.md`, `GEMINI.md` | Tout changement de version (`#v0.8.8`), de module, de propriété de sécurité/confidentialité, de licence ou d'étiquette |
| 3 | **Page publique HTML (`GET /`) et découverte SEP-2127 / RFC 9728** | `construireCarteServeur`, `repondreCarteServeur` (`/mcp/server-card`), `construireRessourceProtegee` (`/.well-known/oauth-protected-resource`) ; sections `#acces` des pages `GET /` de `MCP-Legislation`, `MCP-Jurisprudence`, `MCP-Outils` et pages publiques de `MCP-Acces` | Tout changement touchant les porteurs, la double monture `/mcp` + `/mcp/oauth`, les statuts de refus, CORS, SEP-2127 ou RFC 9728 oblige à vérifier la prose HTML publique des Workers aval |
| 4 | **Impacts inter-dépôts (`Cross-repository`)** | **`MCP-Acces`** (`acces.poirierlavoie.ca`), **`MCP-Legislation`**, **`MCP-Jurisprudence`**, **`MCP-Outils`** et **`droit-civil-quebecois`** (`verifier.py`, `verifier_tout.py`, `synchroniser_plugin_gemini.py`) | Avant publication et consommation d'un nouveau tag semver, vérifier l'ordre de déploiement inter-dépôts (Phases 1 -> 2 -> 3 -> 4), les `README.md` et les suites de tests |
