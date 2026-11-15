# Socle commun des connecteurs juridiques

Code partagé par les deux connecteurs MCP de Poirier Lavoie avocat :

- [`MCP-Legislation`](https://github.com/jpoirierlavoie/MCP-Legislation) — Législation du Québec et du Canada
- [`MCP-Jurisprudence`](https://github.com/jpoirierlavoie/MCP-Jurisprudence) — Jurisprudence canadienne (collection CanLII)

Le socle porte le **protocole** (JSON-RPC 2.0, transport Streamable HTTP sans état, négociation
de versions, en-têtes `2026-07-28`, fiche SEP-2127 `/mcp/server-card`, validateur JSON Schema et
répartiteur unifié) et l'**identité** (extraction et comparaison SHA-256 à temps constant des
porteurs, réponses de refus sans oracle). Il ne porte aucune connaissance du droit : celle-ci reste
dans les connecteurs.

## Comment il est consommé

En **dépendance de développement**, par étiquette git, et empaqueté par `esbuild` / Wrangler au
déploiement :

```jsonc
"devDependencies": {
  "@poirierlavoie/socle-juridique": "github:jpoirierlavoie/MCP-Socle-Juridique#v0.6.2"
}
```

Aucune dépendance d'exécution (`dependencies` vide) : les deux connecteurs conservent ainsi zéro
dépendance à l'exécution, et le code partagé reste versionné et immuable par étiquette.

## Commandes

```sh
npm ci
npm run type-check
npm run lint
npm test
npm audit
```

Les tests s'exécutent dans `workerd` (`@cloudflare/vitest-pool-workers`) pour éprouver
`crypto.subtle.timingSafeEqual` en conditions réelles.

## Documents

| Fichier | Contenu |
|---|---|
| [`CLAUDE.md`](CLAUDE.md) | consignes de travail et invariants de ce dépôt |
| [`GEMINI.md`](GEMINI.md) | guide de contexte concis pour agents (< 24 Kio) |
| [`SECURITY.md`](SECURITY.md) | politique de divulgation coordonnée (sécurité, confidentialité et secret professionnel) et propriétés de sécurité |
| [`LICENSE`](LICENSE) | licence Creative Commons `CC-BY-NC-SA-4.0` |
| [`SPEC-SOCLE-COMMUN.md`](SPEC-SOCLE-COMMUN.md) | contrats et architecture cible (dont l'ouverture multilocataire en phase 2) |
| [`src/identite/LISEZ-MOI.md`](src/identite/LISEZ-MOI.md) | inventaire de `identite/` (`porteur.ts`, `refus.ts`) |
| [`src/protocole/LISEZ-MOI.md`](src/protocole/LISEZ-MOI.md) | inventaire de `protocole/` (`rpc.ts`, `valide.ts`, `registre.ts`, `versions.ts`, `entetes.ts`, `meta.ts`, `decouverte.ts`, `http.ts`, `serveur.ts`) |
| [`docs/archive/`](docs/archive/) | documents historiques d'ouverture et de planification (`NOTE-OUVERTURE-PUBLIQUE.md`, `FEUILLE-DE-ROUTE.md`, `PROCEDURES-MANUELLES.md`) |

## État (`v0.6.2`)

- **Livré (`src/identite/` et `src/protocole/`) :** extraction et appariement constant-time des
  porteurs (`MAX_LONGUEUR_PORTEUR = 512`), refus HTTP (`404`/`401`/`403`/`429`/`405`), enveloppe
  JSON-RPC 2.0, validateur JSON Schema **fermé par défaut** (`TypeConnu`, sûreté prototype),
  registre & exécuteur d'outils (`appelerOutil`), négociation (`negocierInitialize`), validation
  UTF-8 fatale des en-têtes `2026-07-28`, fiche SEP-2127 (`construireCarteServeur`,
  `repondreCarteServeur`), origines CORS (`claude.ai`, `claude.com`, `gemini.google.com`,
  `aistudio.google.com`), utilitaires (`drapeau`, `reponseSante`), lecture bornée `64 Kio` et
  répartiteur HTTP unifié `servirRequeteMcp`.
- **Reporté à la phase 2 :** ouverture publique multilocataire (`Principal`, `Titulaire`,
  `DepotJetons`, D1 `titulaire`/`jeton`, consoles et OAuth / RFC 9728 décrits dans
  [`SPEC-SOCLE-COMMUN.md`](SPEC-SOCLE-COMMUN.md)).
