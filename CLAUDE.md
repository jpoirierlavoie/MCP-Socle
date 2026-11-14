# MCP-Socle-Juridique — consignes de travail

Socle commun des trois dépôts. Les contrats sont dans [`SPEC-SOCLE-COMMUN.md`](SPEC-SOCLE-COMMUN.md) ;
les notes historiques d'arbitrage et de planification sont archivées sous [`docs/archive/`](docs/archive/).
Ce fichier dit comment travailler ici et quels invariants tiennent.

## ⛔ La règle de frontière, avant toute chose

**Le socle ne connaît pas le droit.** S'il faut y écrire un identifiant ou un concept du domaine
(« article », « loi », « décision », « greffe », « palais », « tribunal », « canlii », « mjq »,
« cqlr », « rlrq »), c'est qu'on s'est trompé de dépôt.

Ne montent jamais ici : l'analyseur de citations, les tables du Québec, le pipeline EPUB,
les descripteurs d'outils, `INSTRUCTIONS`, `SERVER_INFO`, `COERCITIONS`, les gabarits de rendu du
domaine, **la sortie structurée et les mises en garde**.

Montent ici : **l'identité et le transport MCP qui la porte** — rien d'autre. Deux répertoires,
`identite/` et `protocole/`. Voir leurs `LISEZ-MOI.md`.

## Propagation

Le socle a **deux consommateurs**, et aucune commande locale de ce dépôt ne détecte seul leur
dérive. Toute modification d'une surface publique oblige à vérifier et énoncer :

1. `MCP-Legislation` — touché ? pourquoi ?
2. `MCP-Jurisprudence` — touché ? pourquoi ?
3. La version : une évolution ou rupture de contrat fait progresser l'étiquette (`v0.6.0`), jamais
   un `git push --force` ni une réécriture d'étiquette publiée.

Le socle est consommé par **étiquette git** (`github:jpoirierlavoie/MCP-Socle-Juridique#v0.6.0`),
en `devDependencies`, et empaqueté par `esbuild` / Wrangler au déploiement. **Jamais une dépendance
d'exécution** (S2, D2).

## Invariants

1. **Zéro dépendance d'exécution.** `dependencies` doit rester absent de `package.json`.
2. **`queryKey` est optionnel dans `identite/porteur.ts`.** Absent ⇒ pas de porteur `?key=`.
   Chaque connecteur choisit explicitement s'il ouvre `?key=` (`jurisprudence` et `legislation` le
   servent tous deux dans leur `PORTE`), sans jamais en hériter par défaut.
3. **Fermé par défaut, sans exception.**
   - Authentification (`apparie`) : aucune configuration ni erreur ne doit ouvrir un point d'entrée.
   - Validation JSON Schema (`protocole/valide.ts`) : `JsonSchema.type` est restreint à `TypeConnu`
     et `typeOk` rend `false` par défaut depuis `v0.6.0` (décision écrite remplaçant l'ancien test
     documentant la tolérance ouverte dans `test/valide.test.ts`, conformément à l'invariant 6).
   - En-têtes et sentinelles (`entetes.ts`, `serveur.ts`) : décodage UTF-8 avec `{ fatal: true, ignoreBOM: false }`.
   - Sûreté prototype : `Object.hasOwn` sur toute table indexée par des noms client (`valide.ts`,
     `entetes.ts`, `rpc.ts`, `registre.ts`).
   - Bornage d'entrée : `MAX_LONGUEUR_PORTEUR = 512` (`porteur.ts`) et `MAX_OCTETS_CORPS_MCP = 65_536`
     (`serveur.ts`).
   - Seule la limitation de débit (`debitAcceptable`) échoue ouvert en cas de panne de liaison.
4. **Les tests tournent dans `workerd`, pas dans Node.** `crypto.subtle.timingSafeEqual`
   n'existe pas dans la WebCrypto de Node. `test/fumee.test.ts` épingle Miniflare/`workerd`.
5. **Fins de ligne LF** (`.gitattributes`, y compris `LICENSE`) pour rester aligné avec Biome et Linux CI.
6. **Un test de garde qui échoue se répare en rétablissant la garantie**, jamais en abaissant le
   test. Tout changement de garantie passe par décision explicite et remplacement du test.
7. **Windows / PowerShell :** employer `npm.cmd` et `npx.cmd` ; éviter les heredocs bash.

## Commandes

```sh
npm ci
npm run type-check    # npx tsc --noEmit
npm run lint          # npx biome check .
npm test              # npx vitest run (workerd)
npm audit             # 0 vulnérabilité attendue (devDependencies + overrides)
```

## Chaîne d'approvisionnement et CI (`.github/workflows/`)

- `ci.yml` (`tsc`, `biome`, `vitest`, `npm audit`), `codeql.yml` (`javascript-typescript`,
  `security-extended,security-and-quality`), `osv-scanner.yml` (`osv-scanner.toml` sans exemption +
  verdict SARIF fermé par défaut), `trivy.yml` (`vuln,misconfig,secret`) et `scorecard.yml`, tous
  épinglés au SHA complet avec `step-security/harden-runner`.
- `dependabot.yml` hebdomadaire sur `npm` et `github-actions`.

## État (`v0.6.0`)

- `src/identite/` : `porteur.ts`, `refus.ts`.
- `src/protocole/` : `rpc.ts`, `valide.ts`, `registre.ts`, `versions.ts`, `entetes.ts`, `meta.ts`,
  `decouverte.ts`, `http.ts`, `serveur.ts`.
- `npm audit` : **0 vulnérabilité** grâce aux versions à jour et aux `overrides` (`sharp`, `undici`, `zod`).
- **Ce qui est écrit sans appelant dans la phase actuelle :** `frapperJeton`, `LONGUEUR_JETON` et
  `empreinte` (`porteur.ts`), conservés comme primitives prêtes pour la phase 2.
- **Ce que le socle n'authentifie pas encore (phase 2 reportée) :** aucun usager individuel ni
  D1 `titulaire`/`jeton` (`Principal`, `Titulaire`, `DepotJetons`, OAuth / RFC 9728).
- **Secrets locaux :** ne jamais lire, afficher ni versionner `cf.token`, `*.token`, `.dev.vars`,
  `mcp.url` ou `.env*`.
