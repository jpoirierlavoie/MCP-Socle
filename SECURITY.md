# Security Policy

Ce dépôt contient `@poirierlavoie/socle-juridique`, la bibliothèque partagée par les connecteurs MCP
Cloudflare Workers en lecture seule [MCP-Jurisprudence](https://github.com/jpoirierlavoie/MCP-Jurisprudence)
et [MCP-Legislation](https://github.com/jpoirierlavoie/MCP-Legislation). Elle ne contient aucun secret
ni aucune dépendance d'exécution (`dependencies` vide).

## Signalement d'une vulnérabilité

Si vous découvrez une faille de sécurité, **n'ouvrez pas d'issue publique sur GitHub**. Écrivez
directement au mainteneur :

**Contact :** Jason Poirier Lavoie — `jason@poirierlavoie.ca`

Merci d'inclure :
- une description de la vulnérabilité et de l'impact potentiel ;
- les étapes ou un scénario minimal de reproduction ;
- toute piste d'atténuation connue, le cas échéant.

Un accusé de réception est transmis sous 72 heures, avec divulgation coordonnée avant publication.

## Portée

Dans la portée :
- Tout module sous `src/identite/`, `src/protocole/` et `src/index.ts`.
- Les garanties de protocole et de sûreté publiées aux connecteurs consommateurs.

Hors portée :
- Ingénierie sociale, attaques physiques ou volumétriques sur l'infrastructure tierce.
- Failles de dépendances transitives de développement qui n'affectent pas le bundle déployé
  (toutes les dépendances de `package.json` sont limitées à `devDependencies`).

## Propriétés de sécurité intégrées (`v0.6.0`)

- **Authentification fermée par défaut et comparaison à temps constant :** `apparie` compare des
  condensés SHA-256 via `crypto.subtle.timingSafeEqual` (aucune liste vide acceptée, aucun secret
  journalisé). Longueur des jetons porteurs plafonnée à `MAX_LONGUEUR_PORTEUR` (512 caractères).
- **Défense contre le ré-attachement DNS et oracle CORS :** `origineRefusee` bloque en `403` sans
  en-têtes CORS toute origine de navigateur non reconnue.
- **Bornage du corps HTTP et UTF-8 strict :** `lireCorpsBorne` coupe la lecture en continu à
  `MAX_OCTETS_CORPS_MCP` (`65 536` octets) et décode en UTF-8 fatal (`fatal: true`).
- **Validation stricte des en-têtes MCP `2026-07-28` :** `decoderSentinelle` échoue fermé en UTF-8
  fatal ; `validerEntetes` rejette tout `_meta` non-objet ou `_meta["io.modelcontextprotocol/protocolVersion"]`
  non textuel ou discordant.
- **Validateur et registre à l'épreuve de la pollution de prototype :** `valide.ts` (`TypeConnu`,
  `default: return false`), `entetes.ts` et `appelerOutil` utilisent `Object.hasOwn`.
- **Chaîne d'approvisionnement :** Actions GitHub épinglées au SHA complet avec `step-security/harden-runner`,
  CodeQL, OSV-Scanner (verdict SARIF fermé par défaut), Trivy (`vuln,misconfig,secret`) et OpenSSF Scorecard.
