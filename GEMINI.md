# MCP-Socle-Juridique — consignes pour agents

Bibliothèque TypeScript partagée par [MCP-Legislation](https://github.com/jpoirierlavoie/MCP-Legislation)
et [MCP-Jurisprudence](https://github.com/jpoirierlavoie/MCP-Jurisprudence), consommée par étiquette git
(`github:jpoirierlavoie/MCP-Socle-Juridique#v0.6.0`) dans leurs `devDependencies` puis empaquetée par
`esbuild` / Wrangler au déploiement.

## Règle de frontière (absolue)

**Le socle ne connaît pas le droit.** Aucun terme ni type du domaine juridique (`article`, `loi`,
`décision`, `greffe`, `palais`, `tribunal`, `canlii`, `mjq`, `cqlr`, `rlrq`) ne doit entrer dans `src/`.
Les descripteurs d'outils, `INSTRUCTIONS`, `SERVER_INFO`, `COERCITIONS` et la logique métier restent
dans les connecteurs consommateurs.

## Architecture (`src/`)

| Répertoire | Modules | Responsabilité |
|---|---|---|
| `src/identite/` | `porteur.ts`, `refus.ts` | Extraction et comparaison SHA-256 à temps constant des porteurs (`MAX_LONGUEUR_PORTEUR = 512`), fabrique `frapperJeton`, réponses de refus (`404`/`401`/`403`/`429`/`405`). |
| `src/protocole/` | `rpc.ts`, `valide.ts`, `registre.ts`, `versions.ts`, `entetes.ts`, `meta.ts`, `decouverte.ts`, `http.ts`, `serveur.ts` | JSON-RPC 2.0, validateur JSON Schema fermé par défaut (`TypeConnu`), registre & `appelerOutil`, négociation & `negocierInitialize`, en-têtes `2026-07-28`, `_meta` & `habillerResultat`, `server/discover` + fiche SEP-2127 (`/mcp/server-card`), intergiciels HTTP/CORS/`drapeau`/`reponseSante`, répartiteur sans état `servirRequeteMcp` (`MAX_OCTETS_CORPS_MCP = 65_536`). |
| `src/index.ts` | — | Point d'entrée unique réexportant les surfaces publiques. |

## Invariants

1. **Zéro dépendance d'exécution** : `package.json` n'a aucune section `dependencies`.
2. **Fermé par défaut** : authentification (`apparie`), validation de schémas (`typeOk` -> `false`), et lecture d'en-têtes (`TextDecoder` UTF-8 fatal). Seule la limitation de débit (`debitAcceptable`) échoue ouvert en cas de panne de liaison.
3. **`queryKey` optionnel** dans `Porte` (`porteur.ts`) : ouvrir `?key=` reste un choix explicite de chaque connecteur.
4. **Tests sous `workerd` uniquement** : `@cloudflare/vitest-pool-workers` (Miniflare) pour éprouver `crypto.subtle.timingSafeEqual`. `test/fumee.test.ts` épingle ce moteur.
5. **Fins de ligne LF** (`.gitattributes`), y compris sous Windows.
6. **Sûreté prototype & entrées bornées** : utiliser `Object.hasOwn` sur toute table indexée par des noms fournis par le client ; lire les corps HTTP via `lireCorpsBorne`.
7. **Secrets** : ne jamais lire ni afficher `cf.token`, `*.token`, `.dev.vars`, `mcp.url` ou `.env*`.

## Commandes (Windows : utiliser `npm.cmd` / `npx.cmd`)

```sh
npm ci
npx tsc --noEmit
npx biome check .
npx vitest run
npm audit
```

## Propagation vers les connecteurs

Tout changement d'interface publique implique une nouvelle étiquette semver (`v0.6.0`, sans jamais
réécrire une étiquette publiée) et la mise à jour explicite dans `MCP-Legislation` et `MCP-Jurisprudence`.
L'ouverture publique multilocataire (D1 `titulaire`/`jeton`, OAuth / RFC 9728) spécifiée dans
`SPEC-SOCLE-COMMUN.md` est reportée à une phase ultérieure.
