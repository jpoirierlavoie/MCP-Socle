# SPEC — Socle commun des connecteurs MCP, ouverture à la confraternité et modes Deep Research

> **Destinataire : agents de développement.** Document d'architecture et de spécification maître. Il
> gouverne quatre dépôts d'infrastructure — `MCP-Socle`, `MCP-Acces` (`acces.poirierlavoie.ca`),
> `MCP-Legislation` (`legislation.poirierlavoie.ca`, alias `lois`) et `MCP-Jurisprudence`
> (`jurisprudence.poirierlavoie.ca`, alias `juris`) — en cohérence avec `MCP-Outils`
> (`outils.poirierlavoie.ca`, alias `outils`) et le greffon cadre `droit-civil-quebecois` (`v2.0.2`).
> Les considérations historiques initiales sont archivées dans `docs/archive/NOTE-OUVERTURE-PUBLIQUE.md`.
> Ici figurent les contrats exécutoires.
>
> **Statut d'implémentation (`@poirierlavoie/mcp-socle` `v0.8.1` — Phase 1 livrée le 2026-11-18, correctif `no-store` le 2026-11-19) :**
> - **Livré dans `MCP-Socle` (`v0.8.1`) :** transport MCP `Streamable HTTP` sans état (`2026-07-28`,
>   `2025-11-25`, `2025-06-18`, `2025-03-26`), porteurs à temps constant (`Bearer`, `?key=`,
>   `/mcp/<jeton>`, `porteurEntete`), résolution multilocataire D1 (`titulaire` / `jeton` avec
>   portée unifiée `les_deux` ou par connecteur), coffre chiffré par enveloppe (`HKDF-SHA256` +
>   `AES-256-GCM` à fermeture stricte sans retour du texte clair), double posture de refus (`404`
>   sur `/mcp` et `401` RFC 9728 sur `/mcp/oauth`), primitives OAuth 2.1 (RFC 9728, RFC 8414,
>   PKCE `S256` obligatoire, validation `redirect_uri` et CIMD anti-SSRF), gouverne à deux étages
>   compatible avec les rafales **Deep Research** (quarantaine des IP en échec séparée du trafic
>   authentifié + débit par `titulaire_id` + quotas journaliers par classe), télémétrie technique
>   sans contenu (minute UTC, rétention 90 jours, garde SQL `verifierSchemaSansContenuIdentifiant`)
>   et autorisation complémentaire de pratique professionnelle du droit dans `LICENSE`.
> - **À livrer dans les dépôts aval (Phases 2 à 4, §13) :** Worker portail `MCP-Acces` et base D1
>   partagée `mcp-identite` (Phase 2), branchement multilocataire + double monture `/mcp` &
>   `/mcp/oauth` + BYOK strict dans `MCP-Legislation` et `MCP-Jurisprudence` (Phase 3), puis
>   alignement documentaire et validation E2E en direct dans `droit-civil-quebecois` et
>   `MCP-Outils` (Phase 4).
>
> **Paramètres arrêtés.** Service gratuit réservé exclusivement aux membres actifs en règle du
> Barreau du Québec. Admission par demande préalable avec vérification automatisée du courriel,
> épreuve en direct obligatoire d'une clé API CanLII valide du demandeur, puis revue humaine
> manuelle au *Bottin des avocats*. Aucune facturation, aucune revente commerciale.

---

## 0. État des lieux et matrice des surfaces clientes (incluant Deep Research)

> ⚠ **RELEVÉ DU 2026-11-18.** Une ligne d'état sans date de relevé ne se croit pas — elle se
> vérifie contre le disque avant usage (leçon du 2026-09-18 où cinq lignes non datées avaient
> dérivé en silence).

### 0.1 État technique comparé des Workers MCP avant bascule aval (Phase 3)

| Dimension | `MCP-Legislation` (`lois`, 10 outils) | `MCP-Jurisprudence` (`juris`, 10 outils) | Cible Phase 3 (`v0.8.0`) |
|---|---|---|---|
| Transport | `Streamable HTTP` sans état via `MCP-Socle` (`#v0.7.0`) | `Streamable HTTP` sans état via `MCP-Socle` (`#v0.7.0`) | `#v0.8.0` sur les deux + `MCP-Acces` |
| Versions servies | `2026-07-28`, `2025-11-25`, `2025-06-18`, `2025-03-26` | `2026-07-28`, `2025-11-25`, `2025-06-18`, `2025-03-26` | Inchangé (`initialize` toujours exempté d'en-tête) |
| Porteurs `/mcp` | `Bearer`, `?key=`, `/mcp/<jeton>` (`MCP_TOKEN`, `MCP_TOKEN_VEILLE`) | `Bearer`, `?key=`, `/mcp/<jeton>` (`MCP_SHARED_SECRET`) | Jetons D1 `DB_IDENTITE` (`les_deux` ou dédiés) + `MCP_TOKEN_VEILLE` CI |
| Monture OAuth 2.1 | Absente | Absente | `/mcp/oauth` (`Bearer` seul, `401` + RFC 9728 vers `acces.poirierlavoie.ca`) |
| Refus sur `/mcp` | `404` à corps vide, sans `WWW-Authenticate` | `401` + `WWW-Authenticate: Bearer` | **Uniformisé en `404` à corps vide** sur `/mcp` ; `401` RFC 9728 sur `/mcp/oauth` |
| Clé CanLII | Sans objet | `CANLII_API_KEY` de l'exploitant | **BYOK strict** (`X-Clef-CanLII` -> `coffre_clef` -> `CLEF_ABSENTE` HTTP `200` `isError: true`), zéro repli exploitant |
| Cache D1 métier | D1 `legislation` + Vectorize + Workers AI (`HYBRID_SEARCH`) | D1 `canlii` (`cases`, `cases_fts`, `citator_*`) | Cache D1 global partagé sous garde BYOK active, `fetched_at` exact masqué au rendu ; `hybride_permis` désarmable par titulaire |
| Journaux & observabilité | `search_log` en clair + `observability` | `search_log` + `api_usage` + `observability` | **`search_log` retirée/archivée**, `forme_requete` abandonnée, `observability` / `invocation_logs` **désactivées** (`false`) ; seuls `compteur_jour` et `evenement_technique` (minute, 90 j) dans `DB_IDENTITE` |
| Débit d'arête | `RATE_LIMITER` sur `CF-Connecting-IP` (`300/min`, `namespace_id` `"1001"`) | `RATE_LIMITER` sur `CF-Connecting-IP` (`60/min`, `namespace_id` `"1001"`) | 4 liaisons à `namespace_id` distincts par Worker : quarantaine d'échecs IP (`20/min`) + plafond rafale pré-D1 (`600/min`) + disjoncteur `"echecs"` (`300/min`) + débit par `titulaire_id` (`300/min` `lois`, `180/min` `juris`) |

### 0.2 Matrice des plateformes clientes et modes de recherche approfondie (*Deep Research*)

Ni **Claude Research** ni **Gemini Deep Research** n'exigent de façades d'outils `search`/`fetch`
artificielles : tous deux découvrent et invoquent directement les **32 outils existants** (`10`
`lois`, `10` `juris`, `12` `outils`, bien en deçà du plafond de `100` outils/serveur de Gemini
Enterprise et sous la limite stricte de `<= 64` caractères d'identifiant composé).

| Surface cliente / Mode | Monture cible | Mécanisme d'authentification | Compétences (`SKILL.md`) | Exigences spécifiques d'infrastructure |
|---|---|---|---|---|
| **Claude Code & Claude Desktop** (`.mcp.json`) | `/mcp` (`404` sur échec) | `Authorization: Bearer <jeton>` (`les_deux` = 1 secret possible) + `X-Clef-CanLII` optionnel | Actives (greffon local) | Réglage WAF de zone pour rafales `POST` serveur à serveur |
| **Google Antigravity** (`/boost`, `/goal`, sous-agent `research`) & **Gemini CLI** | `/mcp` (`404` sur échec) | `Authorization: Bearer <jeton>` (`sensitive: true`, `contextFileName: []`) + `X-Clef-CanLII` optionnel | Actives (`droit-civil-quebecois`) | Plafond composé max `52/64` car. (zéro troncature) |
| **Claude Research** (`claude.ai` / Claude for Work — connecteur `?key=`) | `/mcp?key=<jeton>` (`404` sur échec) | Paramètre `?key=<jeton>` (poser l'URL complète **avant** la première sonde) | Actives (importer `skills/`) | Outils en lecture seule réglés sur *Always allow* ; rafales depuis IP partagées Anthropic |
| **Claude Research** (`claude.ai` — ouverture multilocataire OAuth) | `/mcp/oauth` (`401` RFC 9728) | **OAuth 2.1 + PKCE `S256`** via `acces.poirierlavoie.ca` (`URIS_REDIRECTION_CLAUDE`, CIMD ou client pré-inscrit) | Actives | Émet un `jeton` standard dans `DB_IDENTITE` |
| **Gemini API Deep Research** (`deep-research-preview-04-2026`, `deep-research-max-preview-04-2026`) & **Sandboxes** (`antigravity-preview-09-2026`) | `/mcp` (`404` sur échec) | `"type": "mcp_server"` + `Authorization: Bearer` ou `POST /credentials` | Préambule `SAFETY-KERNEL` injecté dans `input` (§3.4) | Exige `store=True` avec `background=True` (requêtes anonymisées uniquement) ; rafales depuis IP partagées Google |
| **Gemini App** (`gemini.google.com`) & **Gemini Enterprise** (Vertex AI) | `/mcp/oauth` (`401` RFC 9728) | **OAuth 2.1 + PKCE `S256`** obligatoire (aucun support de `?key=` ni de `Bearer` statique utilisateur) | Configuration d'espace de travail | Découverte `/.well-known/oauth-protected-resource/mcp/oauth` -> `acces.poirierlavoie.ca/.well-known/oauth-authorization-server` |

---

## 1. Décisions d'architecture (`S1` à `S23`)

| # | Décision | Motif |
|---|---|---|
| S1 | Un dépôt partagé, **`MCP-Socle`** (`@poirierlavoie/mcp-socle`), source unique du **protocole MCP sans état**, de l'**identité / OAuth 2.1 / coffre** et des **primitives de gouverne et de télémétrie sans contenu**, sans aucun concept juridique. | **AMENDÉE les 2026-09-17 et 2026-11-18.** Trois Workers (`MCP-Acces`, `MCP-Legislation`, `MCP-Jurisprudence`) partagent la même base D1 `DB_IDENTITE`, la même enveloppe cryptographique de coffre et les mêmes contrats OAuth 2.1 / quotas : dupliquer ces primitives dans trois dépôts garantirait une dérive de sécurité. Le socle reste 100 % agnostique du domaine juridique (vérifié par `test/doc.test.ts`). |
| S2 | Le socle est une **dépendance de développement**, empaquetée par `esbuild` au déploiement, par étiquette git immuable (`#v0.8.1`). Jamais une dépendance d'exécution. | Zéro dépendance `dependencies` dans les Workers déployés ; code audité, versionné et figé par tag semver immuable. |
| S3 | Les Workers servent **`2026-07-28` en tête**, puis `2025-11-25`, `2025-06-18` et `2025-03-26` (tant qu'un client ou script de veille omet l'en-tête). | Protocole sans état : ni session, ni `Mcp-Session-Id`, ni Durable Object routé. |
| S4 | `MCP-Legislation` opère hors `McpAgent`, `@modelcontextprotocol/sdk` et Durable Object. | Supprime l'état par session et le coût de stockage par poignée. |
| S5 | **Sortie double partout — ABANDONNÉE le 2026-09-17 sur mesure.** | Mesuré en production : `tools/list` passait de 12 279 à 43 145 octets (~3 070 à ~10 786 jetons par session). `MCP-Jurisprudence` demeure en prose seule ; `MCP-Legislation` conserve sa `structuredContent` plate existante sans `outputSchema`. |
| S6 | **Identité par titulaire dans une base D1 unique (`mcp-identite` / `DB_IDENTITE`)**, liée à `MCP-Acces`, `MCP-Legislation` et `MCP-Jurisprudence`, avec **portée de jeton (`portee`)**. | **AMENDÉE le 2026-11-18.** Une seule base D1 d'identité évite toute désynchronisation de révocation ou de quota entre connecteurs. La portée vaut **`les_deux` par défaut** (un seul secret suffit dans les greffons locaux) avec option de cloisonnement par connecteur (`legislation` ou `jurisprudence`) à l'émission dans `/moi` ou via `scope` OAuth 2.1. |
| S7 | Sur `/mcp`, le jeton voyage par `Authorization: Bearer`, `?key=` **et** segment de chemin `/mcp/<jeton>` ; sur `/mcp/oauth`, seul `Authorization: Bearer` est admis. | Préserve les connecteurs `?key=` existants de `claude.ai` et les greffons CLI sur `/mcp`, tout en respectant l'interdiction OAuth 2.1 des jetons en paramètre d'URL sur `/mcp/oauth`. |
| S8 | **Double monture et parité de refus (`404` sur `/mcp`, `401` RFC 9728 sur `/mcp/oauth`), tous avec `Cache-Control: no-store`.** | **AMENDÉE le 2026-11-18 (`no-store` ajouté le 2026-11-19 en `v0.8.1`).** Sur `/mcp`, les deux connecteurs sont **uniformisés en HTTP `404` à corps vide sans `WWW-Authenticate`** pour tout jeton absent, inconnu, expiré, révoqué, hors portée ou rattaché à un titulaire non servi : zéro oracle d'existence et zéro bascule OAuth intempestive dans les CLI/API à jeton statique. Sur `/mcp/oauth`, tout défaut d'authentification répond **HTTP `401` + `WWW-Authenticate: Bearer resource_metadata="https://<hote>/.well-known/oauth-protected-resource/mcp/oauth"`**, débloquant la découverte standard exigée par Gemini App, Gemini Enterprise et Claude Research multilocataire. Tous ces refus (`404`/`401`/`403`/`405`/`429`), les réponses JSON-RPC et `/health` portent `Cache-Control: no-store` pour empêcher toute mise en cache négative au CDN d'arête (Cloudflare). Les refus métier (`CLEF_ABSENTE`, `CLEF_REFUSEE`, `QUOTA_EPUISE`) voyagent toujours en **HTTP `200` (`isError: true`)** pour rester lisibles par l'agent. |
| S9 | **OAuth 2.1 + PKCE `S256` + RFC 9728 / RFC 8414** servis par `MCP-Acces` (`acces.poirierlavoie.ca`), avec **CIMD** et clients pré-inscrits (sans DCR ouvert). | **AMENDÉE le 2026-11-18.** Obligatoire pour **Gemini App (`gemini.google.com`)** et **Gemini Enterprise (Vertex AI)**, et recommandé pour l'ouverture multilocataire de `claude.ai`. L'usage de *Client ID Metadata Documents* (`estClientIdMetadonneesValide`, protégé contre le SSRF) et de clients pré-inscrits évite l'enregistrement dynamique ouvert (DCR). Le flux OAuth émet un jeton opaque `frapperJeton()` standard stocké dans `DB_IDENTITE.jeton`. |
| S10 | **Clé API CanLII obligatoire dès `/demande`**, éprouvée en direct et chiffrée par enveloppe (`HKDF-SHA256` + `AES-256-GCM`) dans `DB_IDENTITE.coffre_clef`. **Jamais** en paramètre d'outil MCP. | **AMENDÉE le 2026-11-18.** Tout candidat doit fournir une clé API CanLII fonctionnelle lors de sa demande initiale avant d'obtenir accès à Législation ou Jurisprudence, garantissant d'emblée le respect du modèle BYOK individuel. |
| S11 | En-tête `X-Clef-CanLII` accepté en **variante zéro-connaissance** sur `/mcp` pour les clients locaux maîtrisés ; prime sur le coffre quand les deux sont présents. | Permet la rotation ou l'usage local direct depuis un gestionnaire de secrets poste sans transit additionnel. |
| S12 | **Aucune retombée** sur une clé de l'exploitant (`CANLII_API_KEY` retirée du chemin d'exécution). L'exploitant est un `titulaire` ordinaire dans `DB_IDENTITE`. | Uniformité stricte et protection absolue contre toute mutualisation involontaire d'une clé personnelle. |
| S13 | **Zéro journalisation de contenu de requête.** Seuls `compteur_jour` et `evenement_technique` (minute UTC, codes d'erreur fermés, rétention 90 jours) existent. | **AMENDÉE le 2026-11-18.** Protection maximale du secret professionnel (art. 9 *Charte*) et élimination de tout risque de corrélation ou de lecture par l'exploitant plaideur. Vérifié statiquement par `verifierSchemaSansContenuIdentifiant` (`G13`, `G25`). |
| S14 | ~~Plan de contenu expurgé (`forme_requete`)~~ — **ABANDONNÉE le 2026-11-18.** `search_log` est retirée/archivée et **Cloudflare `observability` / `invocation_logs` sont désactivées (`enabled: false`)** sur les Workers MCP. | Même expurgée, une table de requêtes accroît la surface d'exposition lors de recherches approfondies autonomes. Aucune trace d'invocation ni aucun argument JSON-RPC n'est conservé. |
| S15 | **Gouverne pragmatique à deux étages au lancement, adaptée aux rafales Deep Research** : (1) débit d'arête séparant les IP en échec du trafic authentifié par `titulaire_id`, (2) quotas journaliers D1 par classe (`local`, `sortant`, `semantique`), plus indicateurs d'anomalies en lecture seule dans `/exploitant`. | **AMENDÉE le 2026-11-18.** Les modes Deep Research d'Anthropic et de Google émettent des rafales parallèles depuis des adresses IP infonuagiques partagées : imputer un plafond bas (`20/min`) sur `CF-Connecting-IP` avant authentification bloquerait tous les titulaires légitimes. La quarantaine IP (`20/min`) n'est donc imputée **qu'en cas d'échec d'authentification** (`enregistrerEchecAuth`), doublée d'un plafond brut pré-D1 élevé (`600/min`) et d'un débit post-auth par `titulaire_id` (`300/min` `lois`, `180/min` `juris`). Le score comportemental nocturne automatisé est reporté après observation réelle. |
| S16 | Les changements d'état (`actif`, `limite`, `suspendu`, `revoque`) sont **humains**, motivés par code fermé dans `registre_gouverne`, notifiés par courriel avec voie de rétablissement écrite. | Pas de coupure algorithmique opaque en cours de mandat professionnel au lancement. |
| S17 | **Cache D1 CanLII global partagé entre titulaires actifs vérifiés**, sous deux gardes strictes : (1) **masquage de l'horodatage exact `fetched_at`** dans la provenance rendue, et (2) **blocage complet de la lecture du cache (`CLEF_ABSENTE` / `CLEF_REFUSEE`)** si la clé CanLII du titulaire est absente ou révoquée. | **AMENDÉE le 2026-11-18.** Évite de frapper inutilement l'API CanLII pour les mêmes arrêts phares lors des rafales Deep Research (`verify_citations`, `citator`, `get_case`), tout en empêchant qu'un titulaire sans clé valide ne profite du cache et qu'un confrère ne déduise à la seconde près qu'un autre cabinet vient de consulter un arrêt précis. |
| S18 | Identifiants législatifs frappés sous le domaine du cabinet sur le patron FRBR d'Akoma Ntoso ; identifiants jurisprudentiels repris tels quels de CanLII. | Inchangée (§8). |
| S19 | La recherche hybride (`Workers AI` + Vectorize) est **activée par défaut (`hybride_permis = 1`), divulguée dans `/conformite` et désarmable à tout moment par chaque titulaire dans `/moi`** (repli lexical FTS5 annoncé dans la réponse). | Transparence complète sur le sous-traitant d'inférence vectorielle et maîtrise individuelle par l'avocat. |
| S20 | Toute documentation publique de gouverne et de conformité (`/conformite`, `/gouverne`) **dérive des constantes du code** (`QUOTAS_ACTIF_PAR_DEFAUT`, `QUOTAS_LIMITE_PAR_DEFAUT`, `RETENTION_EVENEMENTS_JOURS`). | Élimine toute dérive silencieuse entre le code exécuté et les engagements publiés aux confrères. |
| S21 | **Portail dédié `MCP-Acces` (`https://acces.poirierlavoie.ca`)** et **Cloudflare Email Sending** (`noreply@acces.poirierlavoie.ca` via liaison `send_email`). | **NOUVELLE (2026-11-18).** Isole les sessions HTML, liens magiques, formulaires `/demande` et `/moi`, console `/exploitant`, flux OAuth 2.1 et envois courriel hors des Workers MCP JSON-RPC sans état. |
| S22 | **Hygiène Deep Research et garde `SAFETY-KERNEL`.** Descripteurs fermés (`additionalProperties: false`), annotations exactes (`readOnlyHint: true`, `idempotentHint: true`, `destructiveHint: false`, `openWorldHint: false` sur tous les outils hors ligne), WAF de zone ouvert aux rafales `POST /mcp*` authentifiées, et préambule `SAFETY-KERNEL` obligatoire pour les appels autonomes de l'API Gemini Deep Research (`store=True`). | **NOUVELLE (2026-11-18).** Empêche les boucles de recherche autonome de se bloquer sur des invites d'approbation d'écriture, d'être coupées par le WAF Cloudflare de `poirierlavoie.ca`, ou de divulguer des faits clients vers la recherche web ouverte des planificateurs autonomes. |
| S23 | **Licence `CC-BY-NC-SA-4.0` + Autorisation complémentaire de pratique professionnelle du droit** dans `LICENSE` et `/cgu`. | **NOUVELLE (2026-11-18).** Conserve l'identifiant SPDX uniforme `CC-BY-NC-SA-4.0` sur tous les dépôts tout en levant explicitement (au titre des sections 6(c) et 7(b) CC) toute ambiguïté sur l'usage rémunéré en dossier client par les avocats en règle du Barreau du Québec, sans autoriser la revente commerciale LegalTech/SaaS, avec clauses « tel quel », zéro SLA et divulgation du statut d'avocat plaideur de l'exploitant. |

---

## 2. Arborescence livrée de `MCP-Socle` (`v0.8.0` — relevé du 2026-11-18)

```text
MCP-Socle/
├── src/
│   ├── identite/
│   │   ├── porteur.ts        extraction Bearer | ?key= | /mcp/<jeton> | porteurEntete ;
│   │   │                     SHA-256 + timingSafeEqual ; frapperJeton (43 car. base64url) ;
│   │   │                     estJetonFrappe, queueJeton (6 car.), normaliserUrlMontage
│   │   ├── refus.ts          404 à corps vide (/mcp) ; 401 + WWW-Authenticate RFC 9728 (/mcp/oauth) ;
│   │   │                     403 sans CORS, 429 + Retry-After, 405 + Allow
│   │   ├── titulaire.ts      Principal, TitulaireResolu, DepotJetons, creerDepotJetonsD1 ;
│   │   │                     resoudreJeton à travail constant, porteeAutorisee (les_deux | service),
│   │   │                     ouvrirPrincipal, mise à jour quotidienne de vu_le
│   │   ├── coffre.ts         scellerCoffre & ouvrirCoffre (HKDF-SHA256 + AES-256-GCM, AAD liée,
│   │   │                     fermeture stricte sans retour du clair), empreinteCoffre & repereCoffre
│   │   │                     (HMAC-SHA256 à clé maître), expurger
│   │   ├── oauth.ts          RFC 9728 (/.well-known/oauth-protected-resource), RFC 8414
│   │   │                     (/.well-known/oauth-authorization-server), PKCE S256 obligatoire,
│   │   │                     porteesCanoniques, estUriRedirectionAutorisee, CIMD anti-SSRF
│   │   └── gouverne.ts       quotas journaliers (local/sortant/semantique), quarantaine IP d'échecs
│   │                         + débit Deep Research, EvenementTechnique (minute UTC, 90 j), purges
│   │                         indexées Loi 25 & suppression en cascade (supprimerCompteTitulaireD1,
│   │                         POLITIQUES_RETENTION_IDENTITE, G18), schéma D1 typé GLOB & G13/G25
│   ├── protocole/
│   │   ├── rpc.ts            enveloppe JSON-RPC 2.0
│   │   ├── http.ts           CORS, ORIGINES_PAR_DEFAUT, preflight extensible, debitAcceptable,
│   │   │                     drapeau, reponseSante
│   │   ├── entetes.ts        MCP-Protocol-Version, Mcp-Method, Mcp-Name, sentinelle =?base64?…?=
│   │   ├── meta.ts           _meta, clientLisible, avecServerInfo, avecCache, habillerResultat
│   │   ├── decouverte.ts     server/discover et fiche SEP-2127 (/mcp/server-card)
│   │   ├── versions.ts       négociation, -32022, pont initialize sans état
│   │   ├── valide.ts         validateur JSON Schema fermé par défaut (sûreté prototype)
│   │   ├── registre.ts       DescripteurOutil, listToolDescriptors, appelerOutil
│   │   └── serveur.ts        lireCorpsBorne (64 Kio, UTF-8 fatal) et servirRequeteMcp
│   └── index.ts              réexports purs de toute la surface publique
├── scripts/
│   └── verifier-audit.mjs    contrôle 0 vulnérabilité prod + parité bidirectionnelle osv-scanner.toml
├── test/                     suite Vitest hors ligne exécutée dans workerd (Miniflare)
├── LICENSE                   CC-BY-NC-SA-4.0 + autorisation complémentaire de pratique professionnelle
├── osv-scanner.toml          registre daté et motivé des exemptions OSV de devDependencies
└── package.json              "type": "module", version 0.8.1, zéro dépendance d'exécution
```

**Frontière infranchissable :** `MCP-Socle` ne contient aucun concept juridique (`test/doc.test.ts`).

---

## 3. Protocole `2026-07-28`, compatibilité descendante et Deep Research

### 3.1 Invariants de transport sans état

- **`server/discover`** et **`/mcp/server-card`** (SEP-2127) sont servis sur les deux connecteurs.
- **Pont de versions (`protocole/versions.ts`) :**
  1. `initialize` est **toujours exempté** de l'en-tête `MCP-Protocol-Version` (conformément à `2025-06-18`+).
  2. Tant que `2025-03-26` figure dans `VERSIONS` (`SERT_AVANT_2025_06_18 = true`), une requête hors `initialize` sans en-tête est traitée en `2025-03-26` afin de préserver les scripts de veille.
- **`resultType: "complete"`** et indices de cache (`ttlMs`, `cacheScope`) sous `2026-07-28` (`tools/list` et `server/discover` : `3 600 000` ms, `public`, d'où l'interdiction absolue de faire varier les descripteurs `tools/list` selon le titulaire : ce qui dépend de `hybride_permis` ou de la clé CanLII s'exprime dans la **sortie** de l'outil, jamais dans `tools/list`).
- **Zéro `x-mcp-header`** dans les registres d'outils (`G19`).

### 3.2 Annotations d'outils pour l'exécution autonome Deep Research (`S22`)

Les boucles autonomes de **Claude Research** et **Gemini Deep Research** inspectent `annotations`
pour décider si un appel exige une confirmation humaine d'écriture ou d'accès extérieur :

- Tous les outils déclarent `additionalProperties: false`, `readOnlyHint: true`,
  `destructiveHint: false` et `idempotentHint: true`.
- En Phase 3 dans `MCP-Jurisprudence`, les outils purement locaux hors réseau (`parse_citation`,
  `list_tribunals`, etc.) doivent déclarer **`openWorldHint: false`** (corrigeant l'estampille
  uniforme `openWorldHint: true` relevée lors de l'extraction du registre).

### 3.3 Réglage WAF Cloudflare de zone (`poirierlavoie.ca`)

Les agents autonomes (`claude.ai` Research, `deep-research-preview-04-2026`, Claude Code,
Antigravity) émettent des rafales rapides de `POST /mcp` et `POST /mcp/oauth` sans empreinte TLS
de navigateur interactif. Avant l'ouverture (Phase 3), vérifier et maintenir une règle WAF de zone
sur `legislation.poirierlavoie.ca`, `jurisprudence.poirierlavoie.ca` et `acces.poirierlavoie.ca`
exemptant des défis gérés (*Managed Challenge* / blocage *Bot Fight*) les requêtes `POST` vers
`/mcp`, `/mcp/*` et `/oauth/token` portant `Content-Type: application/json` ou
`application/x-www-form-urlencoded`, afin que la gouverne applicative (§6) soit seule juge.

### 3.4 Garde `SAFETY-KERNEL` pour les exécutions autonomes Gemini API Deep Research

Dans `claude.ai`, Antigravity et Gemini CLI, les 5 fichiers `SKILL.md` du greffon injectent le
noyau `SAFETY-KERNEL`. En revanche, un appel direct à l'API Interactions de Google
(`agent="deep-research-preview-04-2026"` ou `deep-research-max-preview-04-2026`, qui impose
`store=True` en mode `background=True`) n'embarque pas automatiquement `skills/` et active la
recherche web ouverte du planificateur. Toute documentation d'intégration API et les extraits
générés dans `/moi` doivent imposer :

1. **Anonymisation intégrale préalable** (aucun nom de partie, numéro de dossier ni fait identifiant).
2. **Préambule `SAFETY-KERNEL` obligatoire** collé en tête du champ `input` :

```text
CONTRAINTES IMPÉRATIVES (DROIT CIVIL QUÉBÉCOIS — PALIER 2/3) :
1. Confidentialité : Requête entièrement anonymisée; n'inclure aucun nom de partie, numéro de dossier ni fait identifiant dans aucune recherche web ou requête `query`.
2. Sources primaires obligatoires : Ne citer aucun article de loi sans l'avoir lu via le serveur `lois` (`get_article` / `get_articles`) en relevant sa date de consolidation. Ne citer aucun arrêt sans l'authentifier via `juris` (`verify_citations`, `citator` / `subsequent_history`).
3. Étanchéité bijuridique : Exclure tout droit étranger (`.fr`, Belgique, Suisse; art. 1240, 2224, 1641) et tout calque de common law (*duty of care*, *consideration*, *estoppel*, dommages punitifs sans loi habilitante sous l'art. 1621 C.c.Q.).
4. Lecture intégrale des arrêts : N'énoncer un ratio ou paragraphe d'arrêt que si le texte intégral officiel a été consulté en session. Sinon, laisser explicitement le marqueur :
   [RATIO / PAR. X À INSÉRER APRÈS LECTURE DE <citation + lien CanLII>]
5. Méthode : Vérifier d'abord les verrous préalables (prescription, déchéance, avis préalable, compétence), puis exposer le fondement législatif, la jurisprudence vérifiée avec statut de lecture, et l'attaque adverse la plus forte.

QUESTION JURIDIQUE ANONYMISÉE :
<Insérer ici la question de droit abstraitement formulée>
```

3. **Suppression optionnelle post-exécution** (`delete-interaction`) si la conservation côté Google
   n'est pas souhaitée.

---

## 4. Identité partagée (`DB_IDENTITE`), double monture et OAuth 2.1

### 4.1 Topologie de la base D1 partagée `mcp-identite` (`DB_IDENTITE`)

Une seule base Cloudflare D1 nommée **`mcp-identite`** est liée sous le nom **`DB_IDENTITE`** aux
trois Workers authentifiés :

1. **`MCP-Acces` (`acces.poirierlavoie.ca`)** — lecture/écriture : demandes d'admission,
   vérification courriel, épreuve et scellement initial du coffre CanLII, approbation manuelle
   (`/exploitant`), console libre-service (`/moi`), serveur d'autorisation OAuth 2.1 (`/oauth/*`),
   lecture des quotas et indicateurs d'anomalies.
2. **`MCP-Legislation` (`legislation.poirierlavoie.ca`)** — lecture de `titulaire`/`jeton` et
   `compteur_jour` ; écriture asynchrone (`ctx.waitUntil`) de `jeton.vu_le`, `compteur_jour` et
   `evenement_technique`. Sa base métier `DB` (`legislation`) demeure strictement dédiée au corpus.
3. **`MCP-Jurisprudence` (`jurisprudence.poirierlavoie.ca`)** — lecture de `titulaire`/`jeton`,
   `coffre_clef` (`usage = 'canlii'`) et `compteur_jour` ; écriture asynchrone de `jeton.vu_le`,
   `compteur_jour`, `evenement_technique` et `coffre_clef.etat` (si CanLII révoque une clé en
   cours d'usage). Sa base métier `DB` (`canlii`) demeure dédiée au répertoire et au cache partagé.

Le schéma SQL canonique est engendré par `construireSchemaIdentiteD1(["legislation", "jurisprudence"])`
dans `src/identite/gouverne.ts` et validé hors ligne par `verifierSchemaSansContenuIdentifiant` (`G13`, `G25`)
et `verifierCouvertureRetentionSchema` (`G18`).

### 4.2 Forme et portée des jetons (`frapperJeton` — correctif A2 + `portee`)

- **Entropie et alphabet :** `32` octets tirés de `crypto.getRandomValues` encodés en `base64url`
  sans remplissage (`43` caractères exacts, `estJetonFrappe`), affichés **une seule fois** à
  l'émission ; seuls `empreinte` (`SHA-256` hexadécimal) et `queue` (`6` derniers caractères,
  `queueJeton`) sont stockés dans `DB_IDENTITE.jeton`.
- **Portée (`jeton.portee` et `porteesCanoniques`) :**
  - `'les_deux'` *(défaut)* : accepté par `MCP-Legislation` et `MCP-Jurisprudence` — permet au
    praticien local de configurer un seul secret s'il le souhaite.
  - `'legislation'` ou `'jurisprudence'` (et, de manière générale pour $1 \le N \le 8$ services,
    tout sous-ensemble propre trié produit par `porteesCanoniques` / `normaliserPorteeOAuth`) :
    jeton cloisonné, sélectionnable dans `/moi` ou par le paramètre `scope` OAuth 2.1, en
    concordance stricte avec `CHECK (portee IN (...))`.

### 4.3 Parcours d'admission sur `acces.poirierlavoie.ca/demande` (sas `demande_acces` anti-squattage et `MODE_ADMISSION`)

Aucune auto-ouverture immédiate. Le mode d'ouverture est gouverné par `MODE_ADMISSION`
(`resoudreModeAdmission`, fermé par défaut sur `'ferme'` si absent, `'invitation'` pour le
déploiement initial par cohorte via `invitation_acces`, puis `'ouvert'`). L'admission comporte
**trois verrous séquentiels** conçus pour interdire tout déni d'inscription (*squattage*) d'un
numéro public du Barreau avant confirmation de la maîtrise du courriel :

1. **Sas préalable `demande_acces` et vérification automatisée du courriel :** `POST /demande`
   n'écrit **jamais** dans `titulaire` (où `numero_membre` et `courriel` sont `UNIQUE`). La demande
   non confirmée est déposée dans la table sas `demande_acces` (sans contrainte `UNIQUE` sur
   `numero_membre` ni `courriel`, TTL `DUREE_DEMANDE_ACCES_MINUTES = 30` min, purgée par
   `purgerDemandesAccesD1`), avec réponse neutre uniforme sans oracle d'énumération. Un jeton de
   confirmation à usage unique (haché SHA-256 dans `demande_acces.empreinte_jeton`) est expédié
   depuis `noreply@acces.poirierlavoie.ca` (Cloudflare Email Sending, liaison `send_email`).
2. **Épreuve CanLII en direct et promotion atomique vers `titulaire` (`etat = 'en_attente'`) :**
   lors de la confirmation du courriel (ou dès la soumission si scellée sous `demande_acces.id`),
   `MCP-Acces` éprouve en direct `GET caseBrowse/fr/` auprès de l'API CanLII avec la clé fournie.
   Si CanLII répond `401`/`403`, la demande n'entre **pas** en file d'approbation. Si l'appel
   réussit et que le courriel est confirmé, `MCP-Acces` promeut atomiquement la demande dans
   `titulaire` (`id = demande.id`, `etat = 'en_attente'`, `courriel_verifie_le` renseigné) et
   scelle la clé via `scellerCoffre` (`usage = "canlii"`) dans `coffre_clef` (`etat = 'valide'`,
   avec `empreinte_clef` HMAC indexée par `cc_par_empreinte` sans contrainte `UNIQUE`).
3. **Vérification humaine manuelle au *Bottin des avocats* (`/exploitant`) :** l'exploitant vérifie
   manuellement l'inscription active et l'exercice en règle au Tableau de l'Ordre (avec badge
   informatif non bloquant si `coffre_clef.empreinte_clef` révèle le partage d'une clé de cabinet
   entre collègues), consigne sa trace de diligence dans `titulaire.note_admission`, et approuve
   (`etat = 'actif'`) ou refuse (`etat = 'refuse'`). À l'approbation, `MCP-Acces` envoie un
   courriel invitant le confrère à ouvrir `/moi` (par lien magique `session_portail`) pour frapper
   son premier jeton (affiché une seule fois) ou connecter directement ses clients en OAuth 2.1.

### 4.4 Architecture double monture (`/mcp` et `/mcp/oauth`) et ordre de traitement

Chaque connecteur (`MCP-Legislation` et `MCP-Jurisprudence`) sert deux points d'entrée adossés au
même registre d'outils et à la même gouverne :

1. **`/mcp` (monture directe à jeton opaque — refus `404` à corps vide) :**
   - Accepte `Authorization: Bearer <jeton>`, `?key=<jeton>` et `/mcp/<jeton>` (plus `X-Clef-CanLII`
     sur `MCP-Jurisprudence`).
   - Sert Claude Code, Claude Desktop, Antigravity, Gemini CLI, `claude.ai` (`?key=`), l'API
     Gemini Deep Research (`mcp_server`) et la veille CI (`MCP_TOKEN_VEILLE`).
   - **Important :** les routes exactes `/mcp/server-card` et `/mcp/oauth` doivent être interceptées
     **avant** le motif `/mcp/<jeton>` pour ne jamais être interprétées comme un segment de secret.
2. **`/mcp/oauth` (monture OAuth 2.1 — refus `401` + RFC 9728) :**
   - N'accepte que `Authorization: Bearer <jeton>` (`queryKey` et segment de chemin désactivés ;
     tout sous-chemin `/mcp/oauth/<x>` est rejeté par `estCheminMontageAdmissible`).
   - Tout appel non authentifié ou porteur d'un jeton invalide/expiré/révoqué reçoit
     `refuser("401", origin, { resourceMetadata: "https://<hote>/.well-known/oauth-protected-resource/mcp/oauth", scope: "..." })`.
   - Chaque connecteur sert publiquement **uniquement** `GET /.well-known/oauth-protected-resource/mcp/oauth`
     (conformément à l'insertion de chemin RFC 9728 §3.1 et à l'URL `resource_metadata` émise dans
     `WWW-Authenticate`), en laissant la racine `GET /.well-known/oauth-protected-resource` en `404`
     afin qu'aucun client à jeton statique sur `/mcp` ne bascule accidentellement en découverte
     OAuth lors d'une faute de frappe sur `?key=`.
   - `MCP-Acces` sert `GET /.well-known/oauth-authorization-server` (`repondreServeurAutorisation`),
     `GET/POST /oauth/authorize` (authentifiant le titulaire `actif` par sa session `/moi`
     `type_lien = 'session_moi'`, exigeant PKCE `S256`, normalisant `scope` via
     `normaliserPorteeOAuth` et validant `client_id` soit contre `client_oauth`, soit par CIMD via
     `estClientIdMetadonneesValide` + `fetch(clientId, { redirect: "error" })` +
     `validerMetadonneesClientCimd`, ainsi que `redirect_uri` par égalité stricte via
     `estUriRedirectionAutorisee`) et `POST /oauth/token` (vérifiant `verifierDefiPkceS256`,
     consommant atomiquement `code_oauth` et émettant un jeton `frapperJeton()` inscrit dans
     `DB_IDENTITE.jeton`).

**Ordre impératif de traitement d'une requête MCP (§4.3 actualisé) :**

1. **Coupe-circuit global (`MCP_ENABLED !== "true"`) :** `404` sur `/mcp*`, `/.well-known/oauth-protected-resource*` et `/health`. **Jamais** sur `/` ni sur les pages publiques de `MCP-Acces`.
2. **Origine navigateur (`origineRefusee`) :** `403` sans CORS avant toute authentification.
3. **Pré-vol CORS (`OPTIONS`) :** `204` (`preflight`, incluant `X-Clef-CanLII` sur `juris`), **jamais limité en débit** (`G6`).
4. **Garde de débit pré-authentification (`verifierDebitPreAuth`) :** vérifie la quarantaine locale des IP fautives et le plafond brut de rafale par IP (`600/min`), tout en laissant passer vers l'étape 5 toute requête porteuse d'une empreinte SHA-256 récemment validée sur l'isolat (`quarantaine.marquerEmpreinteValide`, tant pour les jetons `frapperJeton` de 43 car. que pour les secrets partagés transitoires/CI de 64 car. hex) afin qu'aucune tempête d'échecs collatéraux sur une IP infonuagique partagée (`claude.ai`, `gemini.google.com`, runners CI) n'interrompe la session active d'un confrère (`S15`). Sur refus : `404` sur `/mcp`, `429` sur `/mcp/oauth`.
5. **Identité (`ouvrirPrincipal`) :** résolution D1 sans court-circuit (`resoudreJeton`) + secrets partagés/CI éventuels (`trouverPorteurApparie` sur `/mcp`), alimentant tous deux `surEmpreinteValide: (h) => quarantaine.marquerEmpreinteValide(h)` uniquement lorsque le chemin est structurellement admissible (`estCheminMontageAdmissible`). En cas d'échec : appel de `enregistrerEchecAuth` avec `candidatsJetons` (évinçant immédiatement tout jeton révoqué/compromis du laissez-passer pré-D1 et imputant les `20/min` d'échecs par IP ainsi que les `300/min` globaux `"echecs"`), puis `404` vide sur `/mcp` ou `401` RFC 9728 sur `/mcp/oauth`.
6. **Méthode HTTP (`POST` requis) — APRÈS l'identité sur `/mcp` (`G23`) :** `405` (`methodeNonPermise`) uniquement pour un appelant authentifié (un `GET /mcp` anonyme reste en `404`).
7. **Débit par titulaire (`verifierDebitTitulaire`) :** clé = `titulaireId` (`300/min` `lois`, `180/min` `juris` pour `actif`/`surveille` ; `20/min` pour `limite`) -> `429` + `Retry-After`.
8. **Lecture des compteurs journaliers (`lireCompteursJourD1`) :** une lecture indexée sur `(titulaire_id, jour)`.
9. **Corps borné (`64 Kio`), négociation de version et validation d'en-têtes (`servirRequeteMcp`).**
10. **Décision de quota (`verifierQuotaJour`) sur le nom d'outil du CORPS** (jamais sur `Mcp-Name` seul) : dépassement -> HTTP `200` + `erreurQuotaEpuise` (`isError: true`).
11. **Garde BYOK CanLII (sur `MCP-Jurisprudence` uniquement, avant même toute lecture du cache D1 `cases`/`citator_*`) :** résolution via `ouvrirCoffre` (`surchargeEntete = porteurEntete(req, "X-Clef-CanLII")` -> `coffre_clef`). Si `ABSENTE` ou `REFUSEE` -> HTTP `200` (`isError: true`, `[CLEF_ABSENTE]` ou `[CLEF_REFUSEE]`).
12. **Exécution de l'outil**, puis écriture différée dans `ctx.waitUntil` de `compteur_jour` et `evenement_technique`.

---

## 5. Coffre de clés CanLII et politique du cache partagé

### 5.1 Chiffrement par enveloppe et empreinte HMAC à clé maître (`src/identite/coffre.ts`)

```text
DEK            = HKDF-SHA256(ikm = COFFRE_MAITRE_V{n}, salt = titulaireId, info = "canlii/v1")
chiffre        = AES-256-GCM(DEK, iv_12_octets, clair, aad = titulaireId || ":canlii:" || version)
K_empreinte    = HKDF-SHA256(ikm = COFFRE_MAITRE_V1, salt = "coffre-hmac/v1", info = "canlii/empreinte-v1")
empreinte_clef = HMAC-SHA256(K_empreinte, clair)
K_repere       = HKDF-SHA256(ikm = COFFRE_MAITRE_V1, salt = "coffre-hmac/v1", info = "canlii/repere-v1")
repere         = masque_fin(clair) || "#" || hex(HMAC-SHA256(K_repere, clair))[0..8]
```

- `COFFRE_MAITRE_V1` (>= 32 caractères aléatoires) est posé par `wrangler secret put` sur
  `MCP-Acces` et `MCP-Jurisprudence` uniquement (`MCP-Legislation` n'a pas ce secret et ne lit
  jamais `coffre_clef`).
- `empreinte_clef` (`empreinteCoffre`, indexée sans contrainte `UNIQUE` par `cc_par_empreinte` sur
  `(usage, empreinte_clef)`) est indépendante de `titulaire_id` afin que `/exploitant` affiche un
  badge informatif lorsque des collègues d'un même cabinet partagent une clé CanLII commune sans
  bloquer leur admission, tout en interdisant toute recherche exhaustive hors ligne si D1 était
  extraite sans `COFFRE_MAITRE`.
- `repereCoffre` dérive son étiquette `#8 hex` par `HMAC-SHA256` sous clé maître (jamais d'empreinte
  `SHA-256` non salée) et n'expose **aucun préfixe** (`0` car. sous 16 car., `2` derniers car. de
  16 à 23 car., `4` derniers car. à 24+ car.).
- `ouvrirCoffre` ne renvoie **jamais** `Promise<string>` : le texte clair n'existe que dans la
  fermeture construisant le client HTTP CanLII, et son `Uint8Array` temporaire est remis à zéro
  (`fill(0)`) dans un bloc `finally` (`G10`).
- `expurger()` purge systématiquement `?key=`, `api_key=`, `Bearer`, `/mcp/<jeton>` et toute clé
  connue des messages d'erreur avant journalisation (`G9`).

### 5.2 Cache global D1 `MCP-Jurisprudence` sous garde BYOK (`S17` amendée)

1. **Partage global entre titulaires actifs :** les tables `databases`, `cases`, `cases_fts` et
   `citator_*` de `MCP-Jurisprudence` sont communes à tous les avocats vérifiés actifs.
2. **Verrou BYOK préalable au cache :** aucun outil consultant les fiches ou le citateur CanLII ne
   peut lire le cache D1 si `ouvrirCoffre` retourne `ABSENTE`, `REFUSEE` ou `INVALIDE`. Un titulaire
   dont la clé CanLII a été retirée ou révoquée reçoit `[CLEF_ABSENTE]` / `[CLEF_REFUSEE]` même si
   la décision figure déjà en cache.
3. **Suppression de l'horodatage exact `fetched_at` au rendu :** la prose retournée au modèle ne
   doit jamais afficher l'heure ou la seconde de mise en cache (`fetched_at`), afin qu'aucun
   titulaire ne puisse inférer qu'un confrère adverse vient d'interroger un arrêt précis.
4. **Révocation dynamique :** si un appel sortant à CanLII avec la clé du coffre (hors surcharge
   `X-Clef-CanLII`) reçoit `401` ou `403` de CanLII, `MCP-Jurisprudence` marque
   `coffre_clef.etat = 'refusee'` dans `ctx.waitUntil` et renvoie `[CLEF_REFUSEE]` en invitant le
   titulaire à mettre à jour sa clé dans `https://acces.poirierlavoie.ca/moi`.

---

## 6. Gouverne à deux étages et résistance aux rafales Deep Research

### 6.1 Étage 1 — Limiteurs d'arête à `namespace_id` distincts (`G34`)

Deux dépôts ou deux étages ne doivent **jamais** partager un même `namespace_id` Cloudflare
(corrigeant le `"1001"` historique partagé entre `legislation` et `jurisprudence`).

| Worker | Liaison Wrangler | `namespace_id` | Clé | Plafond | Effet au franchissement |
|---|---|---|---|---|---|
| `MCP-Legislation` | `RL_PRE_AUTH_IP` | `"1011"` | `CF-Connecting-IP` | `600 / 60 s` | `404` (`/mcp`) ou `429` (`/mcp/oauth`) avant D1 |
| `MCP-Legislation` | `RL_ECHEC_IP` | `"1012"` | `CF-Connecting-IP` *(échecs seuls)* | `20 / 60 s` | Quarantaine mémoire 60 s de l'IP fautive |
| `MCP-Legislation` | `RL_ECHECS_GLOBAL` | `"1013"` | `"echecs"` *(échecs seuls)* | `300 / 60 s` | Disjoncteur d'incident distribué |
| `MCP-Legislation` | `RL_TITULAIRE` | `"1014"` | `titulaire_id` | `300 / 60 s` | `429` + `Retry-After: 60` |
| `MCP-Legislation` | `RL_TITULAIRE_LIMITE` | `"1015"` | `titulaire_id` | `20 / 60 s` | `429` + `Retry-After: 300` |
| `MCP-Jurisprudence` | `RL_PRE_AUTH_IP` | `"1021"` | `CF-Connecting-IP` | `600 / 60 s` | `404` (`/mcp`) ou `429` (`/mcp/oauth`) avant D1 |
| `MCP-Jurisprudence` | `RL_ECHEC_IP` | `"1022"` | `CF-Connecting-IP` *(échecs seuls)* | `20 / 60 s` | Quarantaine mémoire 60 s de l'IP fautive |
| `MCP-Jurisprudence` | `RL_ECHECS_GLOBAL` | `"1023"` | `"echecs"` *(échecs seuls)* | `300 / 60 s` | Disjoncteur d'incident distribué |
| `MCP-Jurisprudence` | `RL_TITULAIRE` | `"1024"` | `titulaire_id` | `180 / 60 s` | `429` + `Retry-After: 60` (`CANLII_MIN_INTERVAL_MS=600` maintenu sur les manqués de cache) |
| `MCP-Jurisprudence` | `RL_TITULAIRE_LIMITE` | `"1025"` | `titulaire_id` | `20 / 60 s` | `429` + `Retry-After: 300` |
| `MCP-Acces` | `RL_DEMANDE_IP` | `"1031"` | `CF-Connecting-IP` | `10 / 60 s` | `429` sur `POST /demande` et liens magiques |
| `MCP-Acces` | `RL_OAUTH_IP` | `"1032"` | `CF-Connecting-IP` | `60 / 60 s` | `429` sur `/oauth/authorize` et `/oauth/token` |

### 6.2 Étage 2 — Quotas journaliers D1 par classe d'outil (`QUOTAS_ACTIF_PAR_DEFAUT`)

| Classe | Outils rattachés | Plafond `actif` / `surveille` | Plafond `limite` |
|---|---|---|---|
| `local` | Tous les outils `lois` lexicaux/structurels (`find_relevant`, `get_article`, `get_articles`, `get_toc`, etc.), outils `juris` hors réseau (`parse_citation`, `list_tribunals`) et lectures servies à 100 % depuis le cache D1 | **1 500 / jour UTC** | **150 / jour UTC** |
| `sortant` | Tout appel d'outil `juris` déclenchant au moins une requête sortante vers l'API CanLII (manqué de cache) | **200 / jour UTC** | **20 / jour UTC** |
| `semantique` | `lois.search_text` lorsque le mode vectoriel hybride (`Workers AI`) est effectivement exécuté (`hybride_permis = 1` et `HYBRID_SEARCH = "true"`) | **150 / jour UTC** | **15 / jour UTC** |

### 6.3 Indicateurs d'anomalies dans `/exploitant` (sans automate nocturne au lancement)

La machine d'états automatique nocturne (`SEUILS_GOUVERNE`) est **reportée**. Au lancement, la vue
`/exploitant` de `MCP-Acces` affiche des indicateurs agrégés en lecture seule calculés sur
`compteur_jour` et `evenement_technique` :
- titulaires approchant ou atteignant `QUOTA_EPUISE` à répétition ;
- ratio élevé `introuvables / appels` ou `erreurs / appels` ;
- multiplicité anormale de `client` (`clientInfo`) distincts sur un même jeton en une même journée.

Toute transition vers `limite`, `suspendu` ou `revoque` relève d'une décision humaine explicite de
l'exploitant consignée en ajout seul dans `registre_gouverne` (`G12`).

---

## 7. Confidentialité, télémétrie sans contenu et observabilité

1. **Aucune table de contenu :** `forme_requete` est abandonnée ; les anciennes tables `search_log`
   de `MCP-Legislation` et `MCP-Jurisprudence` cessent immédiatement de recevoir toute écriture en
   Phase 3 et sont archivées/purgées. `api_usage` est remplacée par `compteur_jour`.
2. **Plan technique unique sans contenu (`evenement_technique`) et purges Loi 25 (`purgerRetentionsD1`, `supprimerCompteTitulaireD1`) :**
   horodatage d'`evenement_technique` tronqué à la minute UTC (`AAAA-MM-JJTHH:MM`, contraint par `CHECK (minute GLOB ...)`), code d'erreur
   contraint par l'union littérale fermée `CodeErreurTechnique`, `client` réduit à `nom/version`
   nettoyé, rétention stricte de **90 jours** sur `evenement_technique` (`purgerEvenementsTechniquesD1`,
   index `et_par_minute`) **et** sur `compteur_jour` (`purgerCompteursJourD1`, index `cj_par_jour`, format `AAAA-MM-JJ` contraint par `CHECK`),
   complétée par les purges indexées des lignes expirées/consommées de `demande_acces` (`30` min),
   `invitation_acces` (invitations expirées sans titulaire rattaché), `session_portail` (`30` min / `12` h) et `code_oauth` (`300` s, horodatages `AAAA-MM-JJTHH:MM:SS.sssZ` contraints par `CHECK GLOB`), ainsi que par le retrait immédiat de clé (`retirerEntreeCoffreD1`) et la suppression intégrale en cascade d'un compte (`supprimerCompteTitulaireD1`), toutes
   recensées dans `POLITIQUES_RETENTION_IDENTITE` et vérifiées par `verifierCouvertureRetentionSchema`
   (`G16`, `G18`, `S20`).
3. **Observabilité Cloudflare désactivée sur les Workers MCP :** `wrangler.jsonc` déclare
   explicitement `"observability": { "enabled": false, "logs": { "enabled": false, "invocation_logs": false } }`
   sur `MCP-Legislation` et `MCP-Jurisprudence` afin qu'aucune URL porteuse de `?key=` ni aucune
   métadonnée d'invocation ne soit retenue dans les journaux Cloudflare.
4. **Recherche hybride désarmable (`hybride_permis`) :** activée par défaut (`1`), divulguée dans
   `/conformite` (mentionnant le traitement d'empreinte vectorielle par Cloudflare Workers AI) et
   désactivable en un clic dans `/moi`. Lorsque `hybride_permis = 0`, `MCP-Legislation` force la
   recherche lexicale FTS5 locale sans aucun appel à `env.AI` et le signale dans la réponse.

---

## 8. Identifiants législatifs et jurisprudentiels (référence Phase 5 ultérieure)

- **Législation (FRBR Akoma Ntoso sous domaine propre) :** `/id/qc/loi/{loi}/{lang}@{version}/art_{numero}`
  (décimaux translittérés `art_2926-1` ; alias AKN en ISO 639-2 `fra`/`eng` et abréviations neutres
  `bk_`, `tit_`, `chp_`, `art_`). Routes publiques non authentifiées, séparées de `/mcp`.
- **Jurisprudence :** identifiants CanLII repris tels quels (`databaseId`, `caseId`, citation neutre,
  URL CanLII), sans frapper d'identifiant sur la donnée de CanLII.

---

## 9. Portail dédié `MCP-Acces` (`https://acces.poirierlavoie.ca`)

Worker Cloudflare autonome (nouveau dépôt `MCP-Acces`), consommant `@poirierlavoie/mcp-socle#v0.8.0`,
lié à `DB_IDENTITE` (`mcp-identite`), au secret `COFFRE_MAITRE_V1`, au secret `CONSOLE_TOKEN` et à
la liaison Cloudflare Email Sending (`send_email`, expéditeur `noreply@acces.poirierlavoie.ca`).

| Route | Public | Fonction |
|---|---|---|
| `GET /` | Public | Page d'accueil expliquant l'admissibilité (Barreau du Québec), le prérequis BYOK CanLII, l'architecture de confidentialité et les liens vers `/demande` et les 5 documents publics |
| `GET/POST /demande` | Public (limité IP `10/min`) | Formulaire d'admission (§4.3), vérification courriel automatisée et épreuve en direct + scellement de la clé API CanLII |
| `GET/POST /moi` | Titulaire (lien magique `session_portail`, cookie `HttpOnly; Secure; SameSite=Lax`) | Émission/révocation de jetons (`les_deux`, `legislation`, `jurisprudence`), extraits de configuration prêts à coller (`.mcp.json`, `mcp_config.json`, `claude.ai`, Gemini App/Enterprise, API Deep Research), rotation/retrait/épreuve de la clé CanLII, bascule `hybride_permis`, consultation de sa consommation du jour, export Loi 25 et suppression du compte |
| `GET/POST /exploitant` | Exploitant (`Authorization: Bearer` sur `CONSOLE_TOKEN` via `memeSecret`) | File d'admission avec saisie de `note_admission` (vérification manuelle au *Bottin des avocats*), gestion des états, `registre_gouverne` et indicateurs d'anomalies sans contenu |
| `GET /.well-known/oauth-authorization-server`<br>`GET/POST /oauth/authorize`<br>`POST /oauth/token`<br>`POST /oauth/revoke` | Clients OAuth 2.1 | Serveur d'autorisation OAuth 2.1 avec PKCE `S256` obligatoire, support CIMD anti-SSRF et clients pré-inscrits (`claude.ai`, `gemini.google.com`, Vertex AI Gemini Enterprise, boucle locale CLI) |

Politique CSP stricte sur toutes les pages HTML : zéro police, script, image ou feuille de style
chargés depuis un domaine tiers.

---

## 10. Documents publics de gouvernance et licence (`acces.poirierlavoie.ca`)

| Document | Route sur `acces.poirierlavoie.ca` | Source et contenu obligatoire |
|---|---|---|
| Conditions d'utilisation | `/cgu` | Rédigé et versionné : **Autorisation de pratique professionnelle du droit** (permettant les mandats clients rémunérés des membres en règle du Barreau du Québec tout en interdisant toute revente LegalTech/SaaS), fourniture « tel quel », absence totale de SLA, préavis de fermeture, divulgation explicite que l'exploitant est un avocat plaideur en exercice, responsabilité exclusive de vérification des sources primaires et voie écrite de rétablissement (réponse sous 5 jours ouvrables) |
| Politique de confidentialité | `/confidentialite` | Rédigé et versionné (Loi 25) : responsable de la protection des RP, finalités limitées à l'admission et à la sécurité, absence de collecte du contenu des recherches, droits d'accès/portabilité/suppression dans `/moi` |
| Attestation solennelle | `/attestation` | Rédigé et versionné : déclaration d'inscription active en règle au Tableau de l'Ordre du Barreau du Québec et de détention légitime d'une clé API CanLII personnelle |
| Fiche de conformité | `/conformite` | **Dérivée du code (`S20`, `G18`)** via `POLITIQUES_RETENTION_IDENTITE` : sous-traitants (Cloudflare D1/Workers, Workers AI désarmable via `hybride_permis`, API CanLII en BYOK), inventaire exhaustif des 11 tables de `DB_IDENTITE` et durées de rétention exactes (`90` jours sur `evenement_technique` et `compteur_jour`, `30` min sur `demande_acces` et liens magiques, `12` h sur `session_moi`, `300` s sur `code_oauth`), chiffrement par enveloppe et empreinte HMAC du coffre, désactivation d'`observability` et preuve de ce que l'exploitant ne peut **pas** lire |
| Registre de gouverne | `/gouverne` | **Dérivée du code (`S20`)** : quotas journaliers exacts (`1 500` / `200` / `150` ; `150` / `20` / `15`), plafonds de débit d'arête, états de compte et procédure contradictoire de rétablissement |

---

## 11. Ordre de migration sans coupure

**Règle d'or :** *ajouter d'abord, servir les deux, vérifier en conditions réelles, retirer ensuite.*

1. **Publier `@poirierlavoie/mcp-socle#v0.8.0` (Phase 1 — fait).** Aucun Worker en production n'est encore modifié.
2. **Déployer `mcp-identite` (`DB_IDENTITE`) et `MCP-Acces` (`acces.poirierlavoie.ca`) (Phase 2).** Créer votre propre compte `titulaire` d'exploitant, déposer votre clé CanLII dans `coffre_clef`, frapper votre jeton individuel `les_deux` et tester le flux OAuth 2.1 de bout en bout hors production.
3. **Mettre à niveau `MCP-Legislation` et `MCP-Jurisprudence` en coexistence (Phase 3a).** Lier `DB_IDENTITE`, ouvrir `/mcp/oauth` et `/.well-known/oauth-protected-resource*`, accepter sur `/mcp` les jetons D1 **en parallèle** des secrets actuels (`MCP_TOKEN`, `MCP_TOKEN_VEILLE`, `MCP_SHARED_SECRET`), désactiver `observability` / `invocation_logs`, cesser toute écriture dans `search_log`, activer les nouveaux limiteurs à `namespace_id` distincts et régler le WAF de zone.
4. **Basculer vos propres clients sur votre jeton de `titulaire` (et OAuth 2.1), puis retirer les secrets personnels hérités (Phase 3b).** Vérifier que `CLEF_ABSENTE` est bien retournée à un titulaire d'essai sans clé alors même que le cache D1 contient des arrêts (`G8`), puis supprimer `CANLII_API_KEY`, `MCP_TOKEN` et `MCP_SHARED_SECRET` (en ne conservant que `MCP_TOKEN_VEILLE` si la veille CI l'utilise, ou un jeton de titulaire dédié `legislation`).
5. **Aligner `droit-civil-quebecois` et `MCP-Outils`, puis ouvrir graduellement (Phase 4).** Mettre à jour les `README.md`, `SECURITY.md`, `LICENSE` et guides Deep Research, exécuter `verifier_tout.py --mode live`, puis ouvrir la file d'admission `/demande`.

---

## 12. Portes de validation automatisées (hors ligne, sous `workerd`)

| Porte | Contrôle | Phase |
|---|---|---|
| G1 | `tsc --noEmit`, `biome check .`, `vitest run` (`workerd`) et `npm run audit` (`0` vulnérabilité d'exécution + parité stricte `osv-scanner.toml`) verts | 1–4 |
| G2 | Parité `CLAUDE.md === GEMINI.md` (< 24 Kio), `README.md`, `/mcp/server-card` et pages publiques | 1–4 |
| G3–G4 | Session complète et ordre déterministe de `tools/list` sous `2026-07-28`, `2025-11-25`, `2025-06-18` | 1 (livré) |
| G6 | Pré-vol CORS jamais limité en débit ; origine navigateur inconnue rejetée en `403` sans CORS avant auth | 1 (livré) |
| G7 | Jeton inconnu, expiré, révoqué, hors portée, ou titulaire `en_attente`/`suspendu`/`revoque`/`refuse` : **même** réponse (`404` vide sur `/mcp`, `401` sur `/mcp/oauth`), sans requête D1 secondaire | 1 (livré) |
| G8 | Sans clé dans `coffre_clef` (ou clé `refusee`) et sans en-tête `X-Clef-CanLII`, `ouvrirCoffre` rend `ABSENTE` / `REFUSEE` sans aucune retombée, bloquant aussi le cache D1 | 1 & 3 |
| G9 | `expurger()` purge `?key=`, `api_key=`, `Bearer`, `/mcp/<jeton>` et les secrets connus ; aucun `request.url` dans `console.*` | 1 & 3 |
| G10 | Aucune fonction exportée dont le nom évoque une clé/secret ne retourne `string` / `Promise<string>` ; `ouvrirCoffre` garde le clair en fermeture et efface son tampon mémoire | 1 (livré) |
| G12 | Aucun `UPDATE` ni `DELETE` sur `registre_gouverne` | 2 & 3 |
| G13 | `verifierSchemaSansContenuIdentifiant` échoue si `search_log` ou `forme_requete` existe ou si une table opérationnelle joint identité et colonne `TEXT` non contrainte par `CHECK IN` | 1 (livré) |
| G16 | `purgerRetentionsD1` (`purgerEvenementsTechniquesD1`, `purgerCompteursJourD1`, `purgerDemandesAccesD1`, `purgerInvitationsAccesD1`, `purgerSessionsPortailD1`, `purgerCodesOAuthD1`) purge exactement les entrées échues en utilisant ses index D1 (`EXPLAIN QUERY PLAN` sans `SCAN`) | 1 (livré) |
| G18 | `verifierCouvertureRetentionSchema` garantit que `POLITIQUES_RETENTION_IDENTITE` couvre toutes les tables de `DB_IDENTITE` sans table oubliée ni entrée orpheline | 1 & 2 |
| G19 | Aucune occurrence de `x-mcp-header` dans les registres d'outils | 1 & 3 |
| G21 | Fermé par défaut : secrets absents, table `jeton` vide, dépôt absent ou erreur D1 -> refus systématique | 1 (livré) |
| G22–G24 | `MCP_ENABLED` fermé par défaut sur `/mcp*` mais pages publiques `200` ; `GET /mcp` anonyme -> `404` ; absence de `MCP-Protocol-Version` gérée selon `SERT_AVANT_2025_06_18` | 1 & 3 |
| G25 | `verifierSchemaSansContenuIdentifiant` échoue si une table portant du texte libre déclare un horodatage plus fin que le jour | 1 (livré) |
| G32 | Mille jetons distincts invalides depuis une même IP sont bloqués avant D1, **tandis que** des rafales authentifiées Deep Research sur une IP infonuagique partagée ne déclenchent jamais la quarantaine d'échecs IP | 1 (livré) |
| G33 | `frapperJeton()` rend 43 caractères `base64url` via `crypto.getRandomValues` ; aucun `Math.random` dans `src/` ; seuls `porteur.ts` et `coffre.ts` appellent `getRandomValues` | 1 (livré) |
| G34 | Tous les `namespace_id` de `ratelimits` sont distincts intra-Worker et inter-Workers (`1011..1032`) | 2 & 3 |
| G35 | OAuth 2.1 : `verifierDefiPkceS256` rejette `plain` et tout `code_verifier` hors `43..128` car. RFC 7636 | 1 (livré) |
| G36 | OAuth 2.1 : `estUriRedirectionAutorisee` et `estClientIdMetadonneesValide` rejettent HTTP hors boucle locale, fragments `#`, traversées `..` et tout littéral IPv4/IPv6 ou hôte local (anti-SSRF) | 1 (livré) |
| G37 | `observability.enabled === false` et `invocation_logs === false` épinglés par test sur `wrangler.jsonc` de `MCP-Legislation` et `MCP-Jurisprudence` | 3 |
| G38 | Aucun horodatage exact `fetched_at` n'apparaît dans la prose rendue par `MCP-Jurisprudence` | 3 |

---

## 13. Plan de livraison multi-dépôts (Phases 1 à 4)

| Phase | Dépôt(s) | Contenu livrable |
|---|---|---|
| **Phase 1** *(livrée)* | `MCP-Socle` (`v0.8.0`) | Mise à jour de `SPEC-SOCLE-COMMUN.md`, `titulaire.ts`, `coffre.ts` (`empreinteCoffre` & `repereCoffre` HMAC), `oauth.ts` (`porteesCanoniques`), `gouverne.ts` (sas `demande_acces`, `invitation_acces`, purges indexées Loi 25, `POLITIQUES_RETENTION_IDENTITE`), extensions `porteur.ts` / `refus.ts` / `http.ts`, migration `@cloudflare/vitest-plugin`, autorisation de pratique professionnelle dans `LICENSE`, parité `CLAUDE.md` = `GEMINI.md`, tests de garde `workerd` (`G7`–`G10`, `G13`, `G16`, `G18`, `G21`, `G25`, `G32`, `G33`, `G35`, `G36`) |
| **Phase 2** | `MCP-Acces` *(nouveau)* + D1 `mcp-identite` | Worker `acces.poirierlavoie.ca`, migrations D1 `mcp-identite`, Cloudflare Email Sending (`noreply@acces.poirierlavoie.ca`), `/demande` (vérification courriel + épreuve CanLII en direct + scellement coffre), `/moi`, `/exploitant`, serveur OAuth 2.1 (`/oauth/*`, RFC 8414, CIMD) et les 5 documents publics (`/cgu`, `/confidentialite`, `/attestation`, `/conformite`, `/gouverne`) |
| **Phase 3** | `MCP-Legislation` & `MCP-Jurisprudence` | Passage à `@poirierlavoie/mcp-socle#v0.8.0`, liaison `DB_IDENTITE`, double monture `/mcp` (`404` uniforme) + `/mcp/oauth` (`401` RFC 9728), BYOK CanLII strict + cache partagé sans `fetched_at` (`G38`), bascule `hybride_permis`, retrait/archivage de `search_log`, désactivation d'`observability` (`G37`), limiteurs Deep Research (`1011..1025`, `G34`), `openWorldHint: false` sur outils hors ligne, mise à jour de `GET /`, `/mcp/server-card`, `README.md`, `SECURITY.md` et `LICENSE` |
| **Phase 4** | `droit-civil-quebecois` & `MCP-Outils` | Mise à jour de `README.md`, `SECURITY.md`, `LICENSE` (autorisation de pratique professionnelle), `CLAUDE.md` / `GEMINI.md`, instructions de connexion multi-plateformes et Deep Research (préambule `SAFETY-KERNEL`), `verifier.py`, `verifier_tout.py --mode live` et ouverture graduée |
