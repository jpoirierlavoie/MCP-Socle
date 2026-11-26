# MCP-Socle — Socle commun des connecteurs MCP

Code d'infrastructure partagé par les connecteurs MCP authentifiés et le portail d'accès de Poirier Lavoie avocat :

- [`MCP-Legislation`](https://github.com/jpoirierlavoie/MCP-Legislation) — Législation du Québec et du Canada (`lois`, 10 outils)
- [`MCP-Jurisprudence`](https://github.com/jpoirierlavoie/MCP-Jurisprudence) — Jurisprudence canadienne, collection CanLII (`juris`, 12 outils)
- `MCP-Acces` (`acces.poirierlavoie.ca`) — Portail d'admission des membres du Barreau du Québec, gestion des jetons/coffres et serveur d'autorisation OAuth 2.1

Le socle porte le **protocole** (JSON-RPC 2.0, transport Streamable HTTP sans état, négociation de versions, en-têtes `2026-07-28`, fiche SEP-2127 `/mcp/server-card`, validateur JSON Schema fermé par défaut et répartiteur unifié) et l'**identité / gouverne** (extraction et comparaison SHA-256 à temps constant des porteurs, résolution multilocataire sur D1 `titulaire`/`jeton` avec portées, coffre chiffré par enveloppe `HKDF-SHA256` + `AES-256-GCM`, découverte OAuth 2.1 RFC 9728 / RFC 8414 + PKCE `S256` + validation CIMD anti-SSRF, limitation de débit à deux étages adaptée aux rafales Deep Research et télémétrie technique sans contenu). Il ne porte aucune connaissance du droit : celle-ci reste dans les connecteurs.

## Comment il est consommé

En **dépendance de développement**, par étiquette git immuable, et empaqueté par `esbuild` / Wrangler au déploiement :

```jsonc
"devDependencies": {
  "@poirierlavoie/mcp-socle": "github:jpoirierlavoie/MCP-Socle#v0.8.5"
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
| [`LICENSE`](LICENSE) | licence open source `Apache-2.0` |
| [`NOTICE`](NOTICE) | mention de création assistée par IA, portée de la licence et non-revendication |
| [`SPEC-SOCLE-COMMUN.md`](SPEC-SOCLE-COMMUN.md) | architecture directrice : ouverture multilocataire, portail `MCP-Acces`, double monture `/mcp` + `/mcp/oauth` et compatibilité Deep Research Claude & Gemini |
| [`src/identite/LISEZ-MOI.md`](src/identite/LISEZ-MOI.md) | inventaire de `identite/` (`porteur.ts`, `refus.ts`, `titulaire.ts`, `coffre.ts`, `oauth.ts`, `gouverne.ts`) |
| [`src/protocole/LISEZ-MOI.md`](src/protocole/LISEZ-MOI.md) | inventaire de `protocole/` (`rpc.ts`, `valide.ts`, `registre.ts`, `versions.ts`, `entetes.ts`, `meta.ts`, `decouverte.ts`, `http.ts`, `serveur.ts`) |
| [`docs/archive/`](docs/archive/) | documents historiques d'ouverture et de planification (`NOTE-OUVERTURE-PUBLIQUE.md`, `FEUILLE-DE-ROUTE.md`, `PROCEDURES-MANUELLES.md`) |

## État (`v0.8.5` — Origines OpenAI/ChatGPT, SEP-3149 CIMD, RFC 9207 `iss`, licence Apache-2.0 et alignement documentaire)

- **Protocole ([`src/protocole/LISEZ-MOI.md`](src/protocole/LISEZ-MOI.md)) :** enveloppe JSON-RPC 2.0, validateur JSON Schema fermé par défaut, registre et exécution des outils, négociation de versions et validation UTF-8 des en-têtes `2026-07-28`, fiche de découverte `/mcp/server-card`, origines CORS (Claude, Gemini et ChatGPT/OpenAI), lecture bornée `64 Kio` et répartiteur HTTP sans état.
- **Identité, coffre, OAuth 2.1 et gouverne ([`src/identite/LISEZ-MOI.md`](src/identite/LISEZ-MOI.md)) :**
  - Extraction et comparaison SHA-256 à temps constant des jetons (`Bearer`, `?key=` optionnel, `/mcp/<jeton>`), avec refus uniforme `404` sur `/mcp` et `401` (`WWW-Authenticate` RFC 9728) sur `/mcp/oauth` (`Cache-Control: no-store`).
  - Résolution multilocataire sur base D1 (`titulaire` / `jeton`) avec portées par service et coffre chiffré (`HKDF-SHA256` + `AES-256-GCM`) pour les clés CanLII personnelles.
  - Découverte et sécurité OAuth 2.1 (RFC 9728, RFC 8414, RFC 9207 `iss`, PKCE `S256` obligatoire, inscription dynamique RFC 7591 et validation CIMD SEP-3149 anti-SSRF) pour Claude, Antigravity, Gemini et ChatGPT/OpenAI.
  - Limitation de débit à deux étages compatible avec les rafales Deep Research, sas d'admission et d'invitation, purges/suppression de compte Loi 25 et télémétrie technique sans contenu conservée 90 jours.
- **Dépôts consommateurs :** `MCP-Acces` (portail d'admission, coffre et serveur OAuth 2.1 sur `DB_IDENTITE`), `MCP-Legislation` (`lois`, double montage `/mcp` + `/mcp/oauth`), `MCP-Jurisprudence` (`juris`, double montage et coffre CanLII) et [`droit-civil-quebecois`](https://github.com/jpoirierlavoie/droit-civil-quebecois) (greffon cadre multiplateforme).
