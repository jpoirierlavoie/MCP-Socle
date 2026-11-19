# MCP-Socle — Socle commun des connecteurs MCP

Code d'infrastructure partagé par les connecteurs MCP authentifiés et le portail d'accès de Poirier Lavoie avocat :

- [`MCP-Legislation`](https://github.com/jpoirierlavoie/MCP-Legislation) — Législation du Québec et du Canada (`lois`, 10 outils)
- [`MCP-Jurisprudence`](https://github.com/jpoirierlavoie/MCP-Jurisprudence) — Jurisprudence canadienne, collection CanLII (`juris`, 10 outils)
- `MCP-Acces` (`acces.poirierlavoie.ca`) — Portail d'admission des membres du Barreau du Québec, gestion des jetons/coffres et serveur d'autorisation OAuth 2.1

Le socle porte le **protocole** (JSON-RPC 2.0, transport Streamable HTTP sans état, négociation de versions, en-têtes `2026-07-28`, fiche SEP-2127 `/mcp/server-card`, validateur JSON Schema fermé par défaut et répartiteur unifié) et l'**identité / gouverne** (extraction et comparaison SHA-256 à temps constant des porteurs, résolution multilocataire sur D1 `titulaire`/`jeton` avec portées, coffre chiffré par enveloppe `HKDF-SHA256` + `AES-256-GCM`, découverte OAuth 2.1 RFC 9728 / RFC 8414 + PKCE `S256` + validation CIMD anti-SSRF, limitation de débit à deux étages adaptée aux rafales Deep Research et télémétrie technique sans contenu). Il ne porte aucune connaissance du droit : celle-ci reste dans les connecteurs.

## Comment il est consommé

En **dépendance de développement**, par étiquette git immuable, et empaqueté par `esbuild` / Wrangler au déploiement :

```jsonc
"devDependencies": {
  "@poirierlavoie/mcp-socle": "github:jpoirierlavoie/MCP-Socle#v0.8.3"
}
```

Aucune dépendance d'exécution (`dependencies` vide) : les connecteurs et le portail conservent ainsi zéro dépendance à l'exécution, et le code partagé reste versionné et immuable par étiquette.

## Commandes

```sh
npm ci
npm run type-check
npm run lint
npm test
npm run audit
```

Les tests s'exécutent hors ligne dans `workerd` (`@cloudflare/vitest-plugin`) avec une base Cloudflare D1 locale en mémoire afin d'éprouver `crypto.subtle.timingSafeEqual`, `HKDF-SHA256`, `AES-256-GCM`, `HMAC-SHA256` et les requêtes/plans d'exécution SQL D1 en conditions réelles.

## Documents

| Fichier | Contenu |
|---|---|
| [`CLAUDE.md`](CLAUDE.md) | consignes de travail, architecture à trois couches et invariants de ce dépôt |
| [`GEMINI.md`](GEMINI.md) | guide de contexte identique octet pour octet à `CLAUDE.md` (< 24 Kio) |
| [`SECURITY.md`](SECURITY.md) | politique de divulgation coordonnée (sécurité, confidentialité et secret professionnel) et propriétés de sécurité |
| [`LICENSE`](LICENSE) | licence Creative Commons `CC-BY-NC-SA-4.0` + autorisation complémentaire de pratique professionnelle du droit |
| [`SPEC-SOCLE-COMMUN.md`](SPEC-SOCLE-COMMUN.md) | architecture directrice : ouverture multilocataire, portail `MCP-Acces`, double monture `/mcp` + `/mcp/oauth` et compatibilité Deep Research Claude & Gemini |
| [`src/identite/LISEZ-MOI.md`](src/identite/LISEZ-MOI.md) | inventaire de `identite/` (`porteur.ts`, `refus.ts`, `titulaire.ts`, `coffre.ts`, `oauth.ts`, `gouverne.ts`) |
| [`src/protocole/LISEZ-MOI.md`](src/protocole/LISEZ-MOI.md) | inventaire de `protocole/` (`rpc.ts`, `valide.ts`, `registre.ts`, `versions.ts`, `entetes.ts`, `meta.ts`, `decouverte.ts`, `http.ts`, `serveur.ts`) |
| [`docs/archive/`](docs/archive/) | documents historiques d'ouverture et de planification (`NOTE-OUVERTURE-PUBLIQUE.md`, `FEUILLE-DE-ROUTE.md`, `PROCEDURES-MANUELLES.md`) |

## État (`v0.8.3` — Boucles locales élargies et validation RFC 7591 DCR sans état)

- **Protocole (`src/protocole/`) :** enveloppe JSON-RPC 2.0, validateur JSON Schema **fermé par défaut** (`TypeConnu`, sûreté prototype), registre et exécuteur d'outils (`appelerOutil`), négociation de versions (`negocierInitialize`), validation UTF-8 fatale des en-têtes `2026-07-28`, fiche SEP-2127 (`construireCarteServeur`, `repondreCarteServeur`), origines CORS (`claude.ai`, `claude.com`, `gemini.google.com`, `aistudio.google.com`), `preflight` extensible, utilitaires (`drapeau`, `reponseSante` et `jsonResponse` avec `Cache-Control: no-store`), lecture bornée `64 Kio` et répartiteur HTTP sans état `servirRequeteMcp`.
- **Identité, coffre, OAuth 2.1 et gouverne (`src/identite/`) :**
  - Extraction et appariement constant-time des porteurs (`Bearer`, `?key=` optionnel, `/mcp/<jeton>`, `lirePorteurEntete` distinguant `absent` d'`invalide`, `porteurEntete`, plafond `MAX_LONGUEUR_PORTEUR = 512`) et fabrique CSPRNG `frapperJeton` (`43` car. `base64url`, `queueJeton`).
  - Double posture de refus : `404` sans corps ni oracle pour la monture directe `/mcp`, et `401` + `WWW-Authenticate: Bearer resource_metadata="..."` (RFC 9728) pour la monture `/mcp/oauth`, tous émis avec `Cache-Control: no-store`.
  - Résolution multilocataire D1 (`resoudreJeton`, `ouvrirPrincipal`, `creerDepotJetonsD1`) avec portée unifiée par défaut (`les_deux`) ou par service et coexistence transitoire avec les secrets d'instance.
  - Coffre chiffré par enveloppe (`scellerCoffre`, `ouvrirCoffre` en fermeture stricte sans exposition du texte clair, `empreinteCoffre` et `repereCoffre` HMAC à clé maître, `expurger`).
  - Découverte et sécurité OAuth 2.1 (`construireRessourceProtegee` RFC 9728, `construireServeurAutorisation` RFC 8414, PKCE `S256` obligatoire `verifierDefiPkceS256`, `porteesCanoniques`, validation des `redirect_uri` dont Antigravity / `/oauth-callback`, validation d'inscription dynamique RFC 7591 `validerMetadonneesInscriptionDcr` et validation CIMD anti-SSRF) pour Claude Code/Desktop, Claude Research, Antigravity, Gemini CLI, Gemini App et Gemini Enterprise.
  - Gouverne à deux étages compatible avec les rafales Deep Research (`verifierDebitPreAuth`, `enregistrerEchecAuth`, `verifierDebitTitulaire`, quotas journaliers `verifierQuotaJour`), sas d'admission anti-squattage (`demande_acces`, `invitation_acces`, `resoudreModeAdmission`), purges indexées et suppression de compte en cascade Loi 25 (`purgerRetentionsD1`, `supprimerCompteTitulaireD1`, `retirerEntreeCoffreD1`, `POLITIQUES_RETENTION_IDENTITE`, `verifierCouvertureRetentionSchema`) et télémétrie technique sans contenu (`formaterEvenementTechnique`, rétention 90 jours, schéma canonique `construireSchemaIdentiteD1` et garde `verifierSchemaSansContenuIdentifiant`).
- **Phases aval (dépôts consommateurs) :** déploiement du portail `MCP-Acces` et de la base `DB_IDENTITE` (Phase 2), bascule multilocataire et double monture `/mcp` + `/mcp/oauth` dans `MCP-Legislation` et `MCP-Jurisprudence` (Phase 3), puis alignement documentaire et E2E en direct dans `droit-civil-quebecois` et `MCP-Outils` (Phase 4).
