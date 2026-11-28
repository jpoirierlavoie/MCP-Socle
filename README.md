# MCP-Socle — Socle commun des connecteurs MCP

Code d'infrastructure partagé par les connecteurs MCP authentifiés et le portail d'accès de Poirier Lavoie avocat :

- [`MCP-Legislation`](https://github.com/jpoirierlavoie/MCP-Legislation) — Législation du Québec et du Canada (`lois`, 10 outils)
- [`MCP-Jurisprudence`](https://github.com/jpoirierlavoie/MCP-Jurisprudence) — Jurisprudence canadienne, collection CanLII (`juris`, 12 outils)
- [`MCP-Outils`](https://github.com/jpoirierlavoie/MCP-Outils) — Calculateurs et repères juridiques déterministes (`outils`, 15 outils)
- `MCP-Acces` (`acces.poirierlavoie.ca`) — Portail d'admission des membres du Barreau du Québec, gestion des jetons/coffres et serveur d'autorisation OAuth 2.1

Le socle porte le **protocole** (JSON-RPC 2.0, transport Streamable HTTP sans état, négociation de versions, en-têtes `2026-07-28`, fiche SEP-2127 `/mcp/server-card`, validateur JSON Schema fermé par défaut et répartiteur unifié) et l'**identité / gouverne** (extraction et comparaison SHA-256 à temps constant des porteurs, résolution multilocataire sur D1 `titulaire`/`jeton` avec portées unifiées `tous` et rétrocompatibilité `les_deux`, coffre chiffré par enveloppe `HKDF-SHA256` + `AES-256-GCM`, découverte OAuth 2.1 RFC 9728 / RFC 8414 + PKCE `S256` + validation CIMD anti-SSRF, limitation de débit à deux étages adaptée aux rafales Deep Research et télémétrie technique sans contenu). Il ne porte aucune connaissance du droit : celle-ci reste dans les connecteurs.

## Comment il est consommé

En **dépendance de développement**, par étiquette git immuable, et empaqueté par `esbuild` / Wrangler au déploiement :

```jsonc
"devDependencies": {
  "@poirierlavoie/mcp-socle": "github:jpoirierlavoie/MCP-Socle#v0.8.9"
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

## État (`v0.8.9` — Portée universelle `tous` rétrocompatible `les_deux`, quotas `local` `3 000`/`300` et support des 3 connecteurs authentifiés)

- **Protocole (`src/protocole/`) :** enveloppe JSON-RPC 2.0, validateur JSON Schema fermé par défaut, registre et exécution des outils, négociation de versions et validation UTF-8 des en-têtes `2026-07-28`, fiche de découverte `/mcp/server-card` et `/.well-known/mcp/server-card.json`, origines CORS (Claude et Gemini), lecture bornée `64 Kio` et répartiteur HTTP sans état.
- **Identité, coffre, OAuth 2.1 et gouverne (`src/identite/`) :**
  - Extraction et comparaison SHA-256 à temps constant des jetons (`Bearer`, `?key=` optionnel, `/mcp/<jeton>`, avec repli portable hors `workerd`), avec refus uniforme `404` sur `/mcp` et `401` (`WWW-Authenticate` RFC 9728) sur `/mcp/oauth` (`Cache-Control: no-store`).
  - Résolution multilocataire sur base D1 (`titulaire` / `jeton`) avec portée unifiée `tous` (rétrocompatible `les_deux`) et coffre chiffré (`HKDF-SHA256` + `AES-256-GCM`) pour les clés CanLII personnelles.
  - Découverte et sécurité OAuth 2.1 (RFC 9728, RFC 8414, RFC 9207 `iss`, PKCE `S256` obligatoire, inscription dynamique RFC 7591 et validation CIMD SEP-3149 anti-SSRF) pour Claude, Antigravity et Gemini.
  - Limitation de débit à deux étages compatible avec les rafales Deep Research, quotas UTC (`3 000` `local` / `200` `sortant` / `150` `semantique`), sas d'admission et d'invitation, purges/suppression de compte Loi 25 et télémétrie technique sans contenu conservée 90 jours.
- **Audit partagé (`./verifier-audit`) :** `scripts/verifier-audit.mjs` exporte `executerAudit` et valide `npm audit` (exécution et développement) contre `osv-scanner.toml`.
- **Dépôts consommateurs :** `MCP-Acces` (portail d'admission, coffre et serveur OAuth 2.1 sur `DB_IDENTITE`), `MCP-Legislation` (`lois`, double montage `/mcp` + `/mcp/oauth`), `MCP-Jurisprudence` (`juris`, double montage et coffre CanLII), `MCP-Outils` (`outils`, double montage `/mcp` + `/mcp/oauth`, sans clé CanLII) et [`droit-civil-quebecois`](https://github.com/jpoirierlavoie/droit-civil-quebecois) (greffon cadre multiplateforme).
