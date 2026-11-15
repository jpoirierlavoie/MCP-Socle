# Security, Privacy & Professional Secrecy Policy / Politique de sécurité, confidentialité et secret professionnel

> **Français :** Ce dépôt contient `@poirierlavoie/socle-juridique`, la bibliothèque partagée par les connecteurs MCP Cloudflare Workers en lecture seule [`MCP-Legislation`](https://github.com/jpoirierlavoie/MCP-Legislation) et [`MCP-Jurisprudence`](https://github.com/jpoirierlavoie/MCP-Jurisprudence). Elle ne contient aucun secret ni aucune dépendance d'exécution (`dependencies` vide).
> Pour signaler une **vulnérabilité de sécurité** OU un **enjeu de vie privée, de confidentialité ou de secret professionnel / privilège** lié au socle ou à un connecteur qui l'emploie, **n'ouvrez jamais d'issue publique sur GitHub** — écrivez directement à :
> **Jason Poirier Lavoie, avocat (Québec)** — `jason@poirierlavoie.ca` (accusé de réception sous **72 heures**, divulgation coordonnée).
> **Ne joignez jamais** de documents clients confidentiels, de communications privilégiées ni de jetons/secrets actifs à un premier message ; utilisez des scénarios synthétiques.
>
> **English:** To report a **security vulnerability** OR a **privacy, confidentiality, or solicitor-client privilege issue** affecting `@poirierlavoie/socle-juridique` or downstream connectors, **do not open a public GitHub issue** — email the maintainer directly:
> **Jason Poirier Lavoie, Lawyer (Québec)** — `jason@poirierlavoie.ca` (acknowledgement within **72 hours**, coordinated disclosure).
> **Never send** privileged client records, unredacted identifying facts, or live bearer tokens/secrets in an initial disclosure; use synthetic test cases.

---

## Signalement (sécurité, confidentialité et privilège)

Merci d'inclure :
- une description de la vulnérabilité ou de l'exposition potentielle de données / métadonnées (sécurité cryptographique, transport HTTP, en-tête ou journalisation) ;
- les étapes ou un scénario minimal de reproduction (données fictives uniquement) ;
- l'impact potentiel identifié sur le socle ou les connecteurs consommateurs (`MCP-Legislation`, `MCP-Jurisprudence`) ;
- toute piste d'atténuation connue, le cas échéant.

Un accusé de réception est transmis sous **72 heures**, avec divulgation coordonnée avant toute publication.

---

## Portée

Dans la portée :
- Tout module sous `src/identite/`, `src/protocole/` et `src/index.ts`.
- Les garanties de protocole, de confidentialité d'authentification et de sûreté publiées aux connecteurs consommateurs.

Hors portée :
- Ingénierie sociale, attaques physiques ou volumétriques sur l'infrastructure tierce.
- Failles de dépendances transitives de développement qui n'affectent pas le bundle déployé (toutes les dépendances de `package.json` sont limitées à `devDependencies`).

---

## Propriétés de sécurité et de confidentialité intégrées (`v0.6.2`)

- **Authentification fermée par défaut et comparaison à temps constant :** `apparie` compare des condensés SHA-256 via `crypto.subtle.timingSafeEqual` (aucune liste vide acceptée, aucun secret journalisé, aucun court-circuit révélant quel secret ou porteur a concordé). Longueur des jetons porteurs plafonnée à `MAX_LONGUEUR_PORTEUR` (512 caractères).
- **Hygiène des journaux et porteurs d'authentification :** Le socle n'enregistre jamais `request.url` ni les jetons présentés en erreur (`decodeURIComponent` échoue silencieusement en refus fermé). Le porteur `?key=` reste optionnel dans `Porte` ; les connecteurs privilégient `Authorization: Bearer` partout où le client le supporte afin d'éviter l'inscription du jeton dans les journaux d'arête URL.
- **Défense contre le ré-attachement DNS et oracle CORS :** `origineRefusee` bloque en `403` sans en-têtes CORS toute origine de navigateur non reconnue (n'admettant par défaut que `claude.ai`, `claude.com`, `gemini.google.com`, `aistudio.google.com` et `ALLOWED_ORIGINS`).
- **Bornage du corps HTTP et UTF-8 strict :** `lireCorpsBorne` coupe la lecture en continu à `MAX_OCTETS_CORPS_MCP` (`65 536` octets) et décode en UTF-8 fatal (`{ fatal: true, ignoreBOM: false }`).
- **Validation stricte des en-têtes MCP `2026-07-28` :** `decoderSentinelle` échoue fermé en UTF-8 fatal ; `validerEntetes` rejette tout `_meta` non-objet ou `_meta["io.modelcontextprotocol/protocolVersion"]` non textuel ou discordant.
- **Validateur et registre à l'épreuve de la pollution de prototype :** `valide.ts` (`TypeConnu`, `default: return false`), `entetes.ts` et `appelerOutil` utilisent `Object.hasOwn`.
- **Zéro concept juridique et zéro stockage :** Le socle ne manipule ni données clients, ni textes législatifs, ni dossiers ; il ne conserve aucun état ni aucune base de données.
- **Chaîne d'approvisionnement :** Actions GitHub épinglées au SHA complet avec `step-security/harden-runner`, CodeQL, OSV-Scanner (verdict SARIF fermé par défaut), Trivy (`vuln,misconfig,secret`) et OpenSSF Scorecard.
