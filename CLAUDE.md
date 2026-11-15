# MCP-Socle-Juridique — Architecture, principes et consignes de travail

Socle commun d'infrastructure logicielle partagée pour les serveurs MCP du cabinet (`@poirierlavoie/socle-juridique`). Les contrats détaillés sont spécifiés dans [`SPEC-SOCLE-COMMUN.md`](SPEC-SOCLE-COMMUN.md) ; les notes historiques d'arbitrage et de planification sont archivées sous [`docs/archive/`](docs/archive/). Ce document définit le rôle architectural du socle au sein du cadre global, ses contrats stricts et les invariants à maintenir pour prévenir toute dérive architecturale. Il s'applique de manière identique à Claude et à Gemini / Antigravity.

---

## 1. Rôle architectural et intégration dans le cadre global

Le système d'assistance en litige civil québécois (`pratique-civile-quebecoise`) repose sur une architecture découplée en trois couches :

```
             ┌────────────────────────────────────────────────────────┐
             │       pratique-civile-quebecoise (Plugin Cadre)        │
             │   5 compétences : recherche-juridique, analyse-doc,     │
             │  calendrier-proc, redaction-juridique, déontologie     │
             └──────┬───────────────────────┬──────────────────┬──────┘
                    │                       │                  │
   (10 outils `legislation_*`)    (10 outils `jurisprudence_*`) (6 outils `calendrier_*`,
                    │                       │           `interets_*`, `greffe_*`, `palais_*`)
                    ▼                       ▼                  ▼
         ┌─────────────────────┐ ┌─────────────────────┐ ┌──────────────────────────┐
         │   MCP-Legislation   │ │  MCP-Jurisprudence  │ │  pratique-civile-outils  │
         │  (Worker Cloudflare │ │ (Worker Cloudflare  │ │    (Worker Cloudflare    │
         │  D1 + Vectorize +   │ │  D1 cache CanLII    │ │    public, sans état,    │
         │    Workers AI)      │ │  authentifié Bearer │ │    zéro secret, Zod)     │
         └──────────┬──────────┘ └──────────┬──────────┘ └──────────────────────────┘
                    │                       │
                    └───────────┬───────────┘
                                ▼ (dépendance de dev `#v0.6.0`, zéro runtime dep)
                 ┌─────────────────────────────┐
                 │    MCP-Socle-Juridique      │
                 │  Transport JSON-RPC 2.0     │
                 │  Streamable HTTP sans état  │
                 │  Auth SHA-256 temps constant│
                 │  Zéro concept juridique     │
                 └─────────────────────────────┘
```

### Place du socle dans l'écosystème
- **Bibliothèque d'infrastructure partagée (`@poirierlavoie/socle-juridique`)** : Fournit le protocole de transport MCP Streamable HTTP révision `2026-07-28`, le protocole JSON-RPC 2.0, l'authentification cryptographique par jeton d'instance à temps constant, la validation de schémas fermée par défaut, et la fiche de découverte publique SEP-2127 (`/mcp/server-card`).
- **Consommateurs directs** : `MCP-Legislation` et `MCP-Jurisprudence`. Ils intègrent le socle via `devDependencies` (`github:jpoirierlavoie/MCP-Socle-Juridique#v0.6.0`). Le code du socle est empaqueté à la compilation par `esbuild` / Wrangler.
- **Indépendance de `pratique-civile-outils`** : Le troisième serveur MCP (`pratique-civile-outils`) est public, sans état et sans authentification ; il utilise directement le SDK standard `@modelcontextprotocol/server` et ne dépend pas du socle.
- **Consommation aval par les compétences du plugin (`pratique-civile-quebecoise`)** :
  - `skills/recherche-juridique` : Consomme les 10 outils `legislation_*`, les 10 outils `jurisprudence_*`, ainsi que `greffe_parse_court_file_number`, `palais_list`, `palais_get` et `interets_compute_1619` (besoins `TEXTE`, `CALCUL`, `GREFFE`, `INSCRIPTION`).
  - `skills/calendrier-procedural` : Consomme `calendrier_compute_deadlines` et `calendrier_list_holidays` (avec repli local `scripts/calcul_delai.py`, besoins `CALCUL`, `INSCRIPTION`, `TEXTE`). N'appelle aucun outil `legislation_*` directement (délègue la recherche législative et la prescription à `recherche-juridique`).
  - `skills/redaction-juridique` : Consomme `legislation_get_article` (dont `lang="en"` pour la terminologie officielle anglaise), `legislation_search_text`, `calendrier_compute_deadlines` et `interets_compute_1619` (besoins `CALCUL`, `GREFFE`).
  - `skills/analyse-documentaire` : Ne nomme AUCUN outil MCP directement ; exprime des besoins d'aptitude abstraits `GREFFE`, `TEXTE` et `INSCRIPTION`, en déléguant la recherche juridique et la vérification de citations à `recherche-juridique` et les échéances à `calendrier-procedural`.
  - `skills/deontologie-professionnelle` : Ne nomme AUCUN outil MCP directement ; délègue le droit substantiel et procédural hors déontologie à `recherche-juridique` et les délais à `calendrier-procedural`.

---

## 2. ⛔ La règle de frontière absolue : « Le socle ne connaît pas le droit »

**Le socle ne connaît aucun concept juridique.** S'il faut y écrire un identifiant ou un concept du domaine juridique (`article`, `loi`, `décision`, `greffe`, `palais`, `tribunal`, `canlii`, `mjq`, `cqlr`, `rlrq`, `juridique`, `legislation_`, `jurisprudence_`), c'est une violation de frontière et une erreur de dépôt.

- **Ne montent JAMAIS ici** : L'analyseur de citations, les tables judiciaires ou de greffe, le pipeline d'ingestion législative, les descripteurs d'outils, les constantes `INSTRUCTIONS`, `SERVER_INFO`, `COERCITIONS`, les gabarits de rendu en français, la sortie structurée et les mises en garde légales (`GARDE_*`).
- **Montent UNIQUEMENT ici** : L'identité cryptographique, le transport réseau MCP Streamable HTTP sans état, le routage JSON-RPC 2.0, la validation de schémas, et la découverte de service.
- **Garde automatisée** : Le test `test/doc.test.ts` vérifie formellement qu'aucun terme de domaine juridique n'apparaît dans `src/`.

---

## 3. Architecture des modules (`src/`)

Le code source est strictement partitionné en deux sous-systèmes réexportés par un point d'entrée unique (`src/index.ts`) :

| Sous-système | Fichiers | Responsabilités et contrats |
|---|---|---|
| `src/identite/` | `porteur.ts`<br>`refus.ts` | **Contrôle d'accès et authentification** :<br>- Extraction du jeton porteur sous 3 formes : `Authorization: Bearer <jeton>`, `?key=<jeton>`, ou segment de chemin `/mcp/<jeton>`.<br>- Comparaison cryptographique SHA-256 à temps constant (`crypto.subtle.timingSafeEqual`) éprouvée sous `workerd`.<br>- Porteur borné : `MAX_LONGUEUR_PORTEUR = 512`.<br>- Réponses de refus fermées par défaut sans fuite d'oracle d'existence (`404` sans corps pour Législation, `401 Bearer` pour Jurisprudence, `403`, `429`, `405`). |
| `src/protocole/` | `rpc.ts`<br>`valide.ts`<br>`registre.ts`<br>`versions.ts`<br>`entetes.ts`<br>`meta.ts`<br>`decouverte.ts`<br>`http.ts`<br>`serveur.ts` | **Transport MCP Streamable HTTP et protocole** :<br>- Négociation de version générique (`versions.ts`) : constante moderne `PREMIERE_MODERNE = "2026-07-28"`, repli sans en-tête `VERSION_SANS_ENTETE = "2025-03-26"`. Les fonctions `negocier` et `negocierInitialize` négocient de manière générique sur le tableau `servies` fourni par le serveur hôte (ex. `["2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"]`) ; aucune version intermédiaire n'est figée en dur dans le socle.<br>- Enveloppe JSON-RPC 2.0 (`initialize`, `tools/list`, `tools/call`, `ping`).<br>- Validation JSON Schema fermée par défaut (`TypeConnu`, `typeOk` rend `false` sur type inconnu, protection prototype `Object.hasOwn`).<br>- Décodage d'en-têtes UTF-8 strict et fatal (`{ fatal: true, ignoreBOM: false }`).<br>- Fiche de découverte publique SEP-2127 `/mcp/server-card` et `server/discover`.<br>- Gestionnaire de requêtes sans état `servirRequeteMcp` avec corps borné à `MAX_OCTETS_CORPS_MCP = 65_536`.<br>- Origines CORS autorisées par défaut pour Anthropic (`claude.ai`, `claude.com`) et Google (`gemini.google.com`, `aistudio.google.com`). |
| `src/index.ts` | `index.ts` | Point d'entrée unique réexportant la totalité des interfaces publiques. |

---

## 4. Surfaces de synchronisation du plugin cadre (`pratique-civile-quebecoise`)

Toute modification d'interfaces, de transport, de schémas ou de version dans le socle ou ses serveurs hôtes aval doit maintenir la cohérence des surfaces du greffon cadre `pratique-civile-quebecoise` :
1. **Manifestes clients** : `.mcp.json`, `mcp_config.json`, `gemini-extension.json`, `.claude-plugin/plugin.json`, `plugin.json`.
2. **Définitions de compétences sous `skills/`** : Références d'outils manuelles dans `skills/recherche-juridique`, `skills/calendrier-procedural` et `skills/redaction-juridique`.
3. **Scripts de synchronisation et validation** :
   - `scripts/regenerer_cache_mcp.py --apply`
   - `scripts/synchroniser_plugin_gemini.py --apply`
   - `python verifier.py`
   - `python verifier_tout.py --mode mock` / `python verifier_tout.py --mode live`

---

## 5. Invariants critiques et règles anti-dérive

1. **Zéro dépendance d'exécution** : `package.json` ne doit comporter aucune section `dependencies` (`dependencies: {}`). Tout le code de production réside dans `src/` ou s'appuie exclusivement sur les API Web Standards du runtime Cloudflare Workers.
2. **Consommation par étiquette git immuable** : Le socle est consommé par tag semver immuable (`#v0.6.0`). Interdiction absolue de `git push --force` ou de réécriture d'étiquette publiée. Toute évolution de contrat impose une incrémentation de version.
3. **`queryKey` optionnel dans `Porte`** : L'acceptation du paramètre d'URL `?key=` reste un choix explicite de chaque connecteur hôte via sa configuration `PORTE`, sans jamais être imposé par défaut.
4. **Fermé par défaut, sans exception** :
   - Authentification : aucune défaillance de configuration ne doit ouvrir un point d'accès.
   - Schémas : les types inconnus sont rejetés par défaut (`typeOk` -> `false`).
   - Sûreté prototype : utilisation systématique de `Object.hasOwn` sur les dictionnaires indexés par des entrées client.
   - En-têtes : rejet fatal des séquences UTF-8 mal formées (`{ fatal: true, ignoreBOM: false }`).
   - Lecture de corps : plafonnée à `MAX_OCTETS_CORPS_MCP = 65_536`.
5. **Exécution des tests sous `workerd` (Miniflare)** : `crypto.subtle.timingSafeEqual` n'existe pas dans la WebCrypto native de Node.js. Les tests doivent tourner exclusivement dans l'environnement Cloudflare Workers via `@cloudflare/vitest-pool-workers` (`test/fumee.test.ts`).
6. **Intégrité des tests de garde** : Lorsqu'un test de garde échoue, on rétablit la garantie dans le code ; on n'abaisse jamais l'exigence du test.
7. **Discipline documentaire multi-dépôts** :
   - `GEMINI.md` et `CLAUDE.md` partagent un contenu unifié identique sous le plafond de 24 000 octets UTF-8 (> 1 000 octets).
   - Doit obligatoirement mentionner `# MCP-Socle-Juridique` et l'étiquette courante `#v0.6.0`.
   - Proscription absolue de toute référence aux anciens identifiants de dépôts retirés.
8. **Statut de l'ouverture multilocataire** : L'authentification individuelle multilocataire (OAuth 2.1 / RFC 9728, tables D1 `titulaire`/`jeton`) spécifiée dans `SPEC-SOCLE-COMMUN.md` (Phase 2) est reportée. Le socle en production opère en mode jeton partagé d'instance.
9. **Secrets locaux** : Ne jamais lire, consigner, journaliser ni committer de secrets (`cf.token`, `*.token`, `.dev.vars`, `mcp.url`, `.env*`).

---

## 6. Commandes de vérification (PowerShell Windows)

Avec la politique d'exécution Windows restreinte, utiliser les commandes `.cmd` :

```powershell
npm.cmd ci
npm.cmd run type-check    # npx.cmd tsc --noEmit
npm.cmd run lint          # npx.cmd biome check .
npm.cmd test              # npx.cmd vitest run (environnement workerd)
npm.cmd audit             # 0 vulnérabilité attendue
```

## 7. Propagation et impact sur les dépôts dépendants

Toute modification apportée au socle nécessite d'évaluer l'impact sur les deux connecteurs dépendants avant publication d'un nouveau tag semver :
1. **`MCP-Legislation`** : Utilise le socle sous `"SOCLE": "true"` via `servirRequeteMcp` et `src/routeur.ts`. Refuse en HTTP 404 sans corps.
2. **`MCP-Jurisprudence`** : Utilise le socle pour l'authentification Bearer, la validation d'arguments et le transport JSON-RPC. Refuse en HTTP 401 Bearer.
