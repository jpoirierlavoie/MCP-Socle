# MCP-Socle — Architecture, principes et consignes de travail

Socle commun d'infrastructure logicielle partagée pour les serveurs MCP et le portail d'accès du cabinet (`@poirierlavoie/mcp-socle`). Les contrats détaillés d'ouverture multilocataire et de compatibilité Deep Research (Claude & Gemini) sont spécifiés dans [`SPEC-SOCLE-COMMUN.md`](SPEC-SOCLE-COMMUN.md) ; les notes historiques d'arbitrage et de planification sont archivées sous [`docs/archive/`](docs/archive/). Ce document définit le rôle architectural du socle au sein du cadre global, ses contrats stricts et les invariants à maintenir pour prévenir toute dérive architecturale. Il s'applique de manière identique à Claude et à Gemini / Antigravity (`CLAUDE.md` et `GEMINI.md` doivent rester identiques octet pour octet et sous 24 000 octets UTF-8 LF).

---

## 1. Rôle architectural et intégration dans le cadre global

Le cadre `droit-civil-quebecois` (`v3.3.1`, anciennement `pratique-civile-quebecoise`) repose sur une architecture découplée en trois couches complétée par le portail d'admission et d'autorisation `MCP-Acces` :

```
          ┌──────────────────────────────────────────────────────────────┐
          │         droit-civil-quebecois (Plugin Cadre v3.3.1)          │
          │ 10 compétences · 60 feuilles · 6 personas · 4 scripts stdlib │
          └─────────┬───────────────────────┬──────────────────┬─────────┘
                    │                       │                  │
        (serveur `lois`, 10 outils)  (serveur `juris`, 12)  (serveur `outils`, 15)
                    │                       │                  │
                    ▼                       ▼                  ▼
         ┌─────────────────────┐ ┌─────────────────────┐ ┌──────────────────────────┐
         │   MCP-Legislation   │ │  MCP-Jurisprudence  │ │        MCP-Outils        │
         │ `/mcp` (404) &      │ │ `/mcp` (404) &      │ │    (Worker Cloudflare    │
         │ `/mcp/oauth` (401)  │ │ `/mcp/oauth` (401)  │ │   public, D1 lecture     │
         │  D1 + Vectorize +   │ │  D1 cache partagé   │ │   seule, zéro secret)    │
         │  Workers AI opt-out │ │  BYOK strict coffre │ └──────────────────────────┘
         └──────────┬──────────┘ └──────────┬──────────┘
                    │                       │
                    ├───────────┬───────────┴───────────────┐
                    │           ▼ (base D1 `DB_IDENTITE`)   ▼
                    │    ┌──────────────┐          ┌────────────────────┐
                    │    │ mcp-identite │◄─────────┤     MCP-Acces      │
                    │    │  (D1 partagé)│          │ acces.poirier...ca │
                    │    └──────────────┘          │ /demande /moi OAuth│
                    │                              └────────┬───────────┘
                    └───────────┬───────────────────────────┘
                                ▼ (dépendance de dev `#v0.8.6`, zéro runtime dep)
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
- **Bibliothèque d'infrastructure partagée (`@poirierlavoie/mcp-socle`)** : Fournit le transport MCP Streamable HTTP sans état (`2026-07-28` et versions compatibles), l'enveloppe JSON-RPC 2.0, l'authentification cryptographique par porteur partagé et par jeton individuel D1 (`titulaire`/`jeton` avec portées), le coffre chiffré par enveloppe (`HKDF-SHA256` + `AES-256-GCM`), les primitives OAuth 2.1 / RFC 9728 / RFC 8414 / PKCE `S256` / validation CIMD anti-SSRF, la limitation de débit à deux étages adaptée aux rafales Deep Research, la télémétrie technique sans contenu et la fiche SEP-2127 (`/mcp/server-card` et `/.well-known/mcp/server-card.json`).
- **Consommateurs directs** : `MCP-Legislation`, `MCP-Jurisprudence` et `MCP-Acces`. Ils intègrent le socle via `devDependencies` (`github:jpoirierlavoie/MCP-Socle#v0.8.6`). Le code du socle est empaqueté à la compilation par `esbuild` / Wrangler.
- **Indépendance de `MCP-Outils`** : Le troisième serveur MCP (`MCP-Outils`, alias `outils`) est public, sans état et sans authentification ; il ne dépend pas du socle.
- **Surfaces clientes et modes Deep Research pris en charge** :
  - Clients OAuth 2.1 sur `/mcp/oauth` par défaut (refus `401` + `WWW-Authenticate: Bearer resource_metadata="..."` selon RFC 9728) : **Claude Code**, **Claude Desktop**, **Google Antigravity**, **Gemini CLI**, **ChatGPT Web/Desktop**, **OpenAI Codex**, **Gemini App** (`gemini.google.com`), **Gemini Enterprise** (Vertex AI) et connecteurs OAuth multilocataires **`claude.ai` / Claude Research**.
  - Clients à jeton direct sur `/mcp` (refus uniforme `404` à corps vide) : scripts CLI/CI sans navigateur (`Authorization: Bearer`), repli `?key=` (`claude.ai`), **API OpenAI Responses**, et agents **Gemini API Deep Research** (`deep-research-preview-04-2026`, `deep-research-max-preview-04-2026`).

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
| `src/identite/` | `porteur.ts`<br>`refus.ts`<br>`titulaire.ts`<br>`coffre.ts`<br>`oauth.ts`<br>`gouverne.ts` | **Contrôle d'accès, cryptographie, OAuth 2.1 et gouverne** :<br>- `porteur.ts` : extraction des 3 porteurs (`Bearer`, `?key=` optionnel, `/mcp/<jeton>`) + `lirePorteurEntete` / `porteurEntete` distinguant `absent` vs `invalide`, garde de chemin (`estCheminMontageAdmissible`), comparaison SHA-256 `timingSafeEqual` (`apparie`, `trouverPorteurApparie`), plafond `MAX_LONGUEUR_PORTEUR = 512`, fabrique CSPRNG `frapperJeton` (`43` car. `base64url`) et `queueJeton`.<br>- `refus.ts` : `404` à corps vide sur `/mcp` et `401` + `WWW-Authenticate` RFC 9728 nettoyé contre l'injection sur `/mcp/oauth`, `403`, `429`, `405`, tous émis avec `Cache-Control: no-store`.<br>- `titulaire.ts` : résolution D1 sans court-circuit ni tolérance sur `expire_le === ""` (`resoudreJeton`, `ouvrirPrincipal` alimentant `surEmpreinteValide` tant pour les jetons D1 que pour les secrets partagés transitoires/CI, `horodatageUtcMs` validant date calendaire, heure et décalage, fermé par défaut), états servis (`actif`, `surveille`, `limite`), portée `les_deux` ou par connecteur, `vu_le` quotidien.<br>- `coffre.ts` : enveloppe `HKDF-SHA256` + `AES-256-GCM` avec AAD liée (`titulaireId:usage:version`), `ouvrirCoffre` en fermeture stricte (échouant fermé sur surcharge vide ou `{ etat: "invalide" }`, sans retour de texte clair `G10`), `empreinteCoffre` et `repereCoffre` à clé maître `HMAC-SHA256` (zéro condensé non salé, masquage resserré), `expurger` (`G9`, décodant les noms de paramètres encodés en pourcentage).<br>- `oauth.ts` : fiches RFC 9728 et RFC 8414, PKCE `S256` obligatoire (`verifierDefiPkceS256`), `porteesCanoniques` et `normaliserPorteeOAuth` cohérents avec D1 `CHECK`, validation stricte des `redirect_uri` (Claude, Google/Vertex/Antigravity, boucle locale élargie dont `/oauth-callback`), validation RFC 7591 DCR hors réseau (`validerMetadonneesInscriptionDcr`) et validation anti-SSRF CIMD (`estClientIdMetadonneesValide`, `validerMetadonneesClientCimd`).<br>- `gouverne.ts` : modes d'admission (`resoudreModeAdmission`), sas anti-squattage `demande_acces` + `invitation_acces`, quarantaine des IP fautives avec laissez-passer d'empreintes SHA-256 actives (jetons 43 car. et secrets 64 hex, évincés dès le premier échec d'authentification) pour les IP partagées Deep Research (`S15`), débit par `titulaireId`, quotas journaliers (`local`, `sortant`, `semantique`), `EvenementTechnique` à la minute (90 jours), contraintes SQLite `CHECK GLOB` sur les horodatages canoniques, purges indexées et suppression de compte en cascade Loi 25 (`purgerRetentionsD1`, `supprimerCompteTitulaireD1`, `retirerEntreeCoffreD1`, `POLITIQUES_RETENTION_IDENTITE`, `G16`, `G18`) et garde SQL `verifierSchemaSansContenuIdentifiant` (`G13`, `G25`). |
| `src/protocole/` | `rpc.ts`<br>`valide.ts`<br>`registre.ts`<br>`versions.ts`<br>`entetes.ts`<br>`meta.ts`<br>`decouverte.ts`<br>`http.ts`<br>`serveur.ts` | **Transport MCP Streamable HTTP et protocole** :<br>- Négociation de version générique (`PREMIERE_MODERNE = "2026-07-28"`, `VERSION_SANS_ENTETE = "2025-03-26"`, `initialize` toujours exempté d'en-tête).<br>- Enveloppe JSON-RPC 2.0 (`server/discover`, `initialize`, `tools/list`, `tools/call`, `ping`).<br>- Validation JSON Schema fermée par défaut (`TypeConnu`, sûreté prototype `Object.hasOwn`).<br>- Décodage d'en-têtes UTF-8 strict et fatal (`{ fatal: true, ignoreBOM: false }`).<br>- Fiche publique SEP-2127 `/mcp/server-card` et `/.well-known/mcp/server-card.json`.<br>- Répartiteur `servirRequeteMcp` borné à `MAX_OCTETS_CORPS_MCP = 65_536`.<br>- Origines CORS par défaut (`claude.ai`, `claude.com`, `gemini.google.com`, `aistudio.google.com`) et `preflight` extensible. |
| `src/index.ts` | `index.ts` | Point d'entrée unique réexportant la totalité des interfaces publiques. |

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
2. **Consommation par étiquette git immuable** : Le socle est consommé par tag semver immuable (`#v0.8.6`). Interdiction absolue de `git push --force` ou de réécriture d'étiquette publiée. Toute évolution de contrat impose une incrémentation de version.
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
   - Doivent obligatoirement mentionner `# MCP-Socle` et l'étiquette courante `#v0.8.6`.
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
| 1 | **Code, contrats et gardes (`src/`, `SPEC`, `test/`)** | `src/identite/`, `src/protocole/`, `src/index.ts`, `SPEC-SOCLE-COMMUN.md`, `test/` (`workerd`), `test/doc.test.ts` | Toute évolution d'API, de coffre, d'OAuth 2.1, de quotas/débit, de validation JSON Schema, d'en-têtes MCP, de porteurs ou de refus (`404`/`401`/`403`/`429`) |
| 2 | **`README.md` et gouvernance du dépôt** | `README.md`, `src/identite/LISEZ-MOI.md`, `src/protocole/LISEZ-MOI.md`, `SECURITY.md`, `LICENSE` (`Apache-2.0`), `NOTICE`, `package.json`, `CLAUDE.md`, `GEMINI.md` | Tout changement de version (`#v0.8.6`), de module, de propriété de sécurité/confidentialité, de licence ou d'étiquette |
| 3 | **Page publique HTML (`GET /`) et découverte SEP-2127 / RFC 9728** | `construireCarteServeur`, `repondreCarteServeur` (`/mcp/server-card`), `construireRessourceProtegee` (`/.well-known/oauth-protected-resource`) ; sections `#acces` des pages `GET /` de `MCP-Legislation`, `MCP-Jurisprudence` et pages publiques de `MCP-Acces` | Tout changement touchant les porteurs, la double monture `/mcp` + `/mcp/oauth`, les statuts de refus, CORS, SEP-2127 ou RFC 9728 oblige à vérifier la prose HTML publique des Workers aval |
| 4 | **Impacts inter-dépôts (`Cross-repository`)** | **`MCP-Acces`** (`acces.poirierlavoie.ca`), **`MCP-Legislation`**, **`MCP-Jurisprudence`**, **`MCP-Outils`** et **`droit-civil-quebecois`** (`verifier.py`, `verifier_tout.py`, `synchroniser_plugin_gemini.py`) | Avant publication et consommation d'un nouveau tag semver, vérifier l'ordre de déploiement inter-dépôts (Phases 1 -> 2 -> 3 -> 4), les `README.md` et les suites de tests |
