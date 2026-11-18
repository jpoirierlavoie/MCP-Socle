# Security, Privacy & Professional Secrecy Policy / Politique de sécurité, confidentialité et secret professionnel

> **Français :** Ce dépôt contient `@poirierlavoie/mcp-socle` (`#v0.8.0`), la bibliothèque d'infrastructure partagée par les connecteurs MCP Cloudflare Workers en lecture seule [`MCP-Legislation`](https://github.com/jpoirierlavoie/MCP-Legislation), [`MCP-Jurisprudence`](https://github.com/jpoirierlavoie/MCP-Jurisprudence) et le portail d'accès `MCP-Acces` (`acces.poirierlavoie.ca`). Elle ne contient aucun secret ni aucune dépendance d'exécution (`dependencies` vide).
> Pour signaler une **vulnérabilité de sécurité** OU un **enjeu de vie privée, de confidentialité ou de secret professionnel / privilège** lié au socle ou à un service qui l'emploie, **n'ouvrez jamais d'issue publique sur GitHub** — écrivez directement à :
> **Jason Poirier Lavoie, avocat (Québec)** — `jason@poirierlavoie.ca` (accusé de réception sous **72 heures**, divulgation coordonnée).
> **Ne joignez jamais** de documents clients confidentiels, de communications privilégiées ni de jetons/secrets actifs à un premier message ; utilisez des scénarios synthétiques.
>
> **English:** To report a **security vulnerability** OR a **privacy, confidentiality, or solicitor-client privilege issue** affecting `@poirierlavoie/mcp-socle` or downstream services, **do not open a public GitHub issue** — email the maintainer directly:
> **Jason Poirier Lavoie, Lawyer (Québec)** — `jason@poirierlavoie.ca` (acknowledgement within **72 hours**, coordinated disclosure).
> **Never send** privileged client records, unredacted identifying facts, or live bearer tokens/secrets in an initial disclosure; use synthetic test cases.

---

## Signalement (sécurité, confidentialité et privilège)

Merci d'inclure :
- une description de la vulnérabilité ou de l'exposition potentielle de données / métadonnées (sécurité cryptographique, enveloppe du coffre, OAuth 2.1 / PKCE, transport HTTP, en-tête ou télémétrie) ;
- les étapes ou un scénario minimal de reproduction (données fictives uniquement) ;
- l'impact potentiel identifié sur le socle ou les Workers consommateurs (`MCP-Legislation`, `MCP-Jurisprudence`, `MCP-Acces`) ;
- toute piste d'atténuation connue, le cas échéant.

Un accusé de réception est transmis sous **72 heures**, avec divulgation coordonnée avant toute publication.

---

## Portée

Dans la portée :
- Tout module sous `src/identite/`, `src/protocole/` et `src/index.ts`.
- Les garanties de protocole, de confidentialité d'authentification, de chiffrement par enveloppe, d'OAuth 2.1 / PKCE et de télémétrie sans contenu publiées aux services consommateurs.

Hors portée :
- Ingénierie sociale, attaques physiques ou volumétriques sur l'infrastructure tierce.
- Failles de dépendances transitives de développement qui n'affectent pas le bundle déployé (toutes les dépendances de `package.json` sont limitées à `devDependencies`).

---

## Propriétés de sécurité et de confidentialité intégrées (`v0.8.0`)

- **Authentification fermée par défaut et absence d'oracle :** `apparie` compare des condensés SHA-256 via `crypto.subtle.timingSafeEqual` ; `resoudreJeton` résout les jetons 256 bits (`frapperJeton`, 43 car. `base64url`) par empreinte SHA-256 indexée en exécutant un condensé factice à défaut de candidat et en évaluant révocation, expiration, état (`actif`, `surveille`, `limite`) et portée (`les_deux` ou par connecteur) sur une seule lecture sans oracle. Longueur des porteurs plafonnée à `MAX_LONGUEUR_PORTEUR` (512 caractères).
- **Double monture et sécurité OAuth 2.1 / PKCE `S256` :** `refuser("404")` sert un `404` à corps vide sur `/mcp` (clients à jeton direct), tandis que `refuser("401", origin, options)` émet un en-tête `WWW-Authenticate: Bearer` nettoyé contre toute injection CRLF/guillemets sur `/mcp/oauth` (RFC 9728). `verifierDefiPkceS256` impose exclusivement `S256` à temps constant ; `estUriRedirectionAutorisee` et `estClientIdMetadonneesValide` bloquent les fragments, traversées de chemin, schémas dangereux et cibles SSRF (littéraux IPv4/IPv6 et hôtes locaux).
- **Coffre chiffré par enveloppe à fermeture stricte :** `scellerCoffre` et `ouvrirCoffre` dérivent une clé non extractible via `HKDF-SHA256` et chiffrent en `AES-256-GCM` avec donnée additionnelle authentifiée (`titulaireId:usage:version`). `empreinteCoffre` (`empreinte_clef`) et `repereCoffre` dérivent leurs condensés par `HMAC-SHA256` sous clé maître (aucun condensé non salé ni préfixe en clair exposé hors ligne). Le texte clair n'est jamais retourné par une fonction exportée : il est livré à la seule fermeture `fabrique`, puis son tampon mémoire est remis à zéro (`fill(0)`). `expurger` purge les secrets des chaînes journalisables.
- **Limitation de débit compatible Deep Research et sas anti-squattage :** `verifierDebitPreAuth` et `enregistrerEchecAuth` séparent la quarantaine des IP en échec d'authentification du trafic authentifié (avec laissez-passer pré-D1 des empreintes SHA-256 récemment validées — tant pour les jetons 43 car. `base64url` que pour les secrets partagés transitoires/CI de 64 car. hex — afin qu'aucune tempête d'échecs collatéraux sur une IP infonuagique partagée d'Anthropic ou de Google n'interrompe un titulaire actif), tandis que `verifierDebitTitulaire` limite après authentification par `titulaireId`. Le sas `demande_acces` empêche tout squattage de `numero_membre` ou `courriel` avant confirmation du courriel.
- **Zéro journalisation de contenu de requête et purges Loi 25 :** `formaterEvenementTechnique` n'accepte que des énumérations fermées et un horodatage tronqué à la minute UTC (`AAAA-MM-JJTHH:MM`, imposé par `CHECK GLOB`), avec purges indexées à 90 jours sur `evenement_technique` et `compteur_jour` ainsi que sur les entrées expirées/consommées de `demande_acces`, `invitation_acces`, `session_portail` et `code_oauth`, retrait immédiat de coffre (`retirerEntreeCoffreD1`) et suppression intégrale de compte en cascade (`supprimerCompteTitulaireD1`, `purgerRetentionsD1`, `POLITIQUES_RETENTION_IDENTITE`, `verifierCouvertureRetentionSchema`). `verifierSchemaSansContenuIdentifiant` interdit formellement `search_log`, `forme_requete`, toute jointure identité + colonne non numérique sans énumération fermée et tout horodatage sous-journalier sur du texte libre.
- **Défense contre le ré-attachement DNS, bornage HTTP et sûreté prototype :** `origineRefusee` bloque en `403` sans CORS toute origine navigateur inconnue ; `lireCorpsBorne` plafonne à `65 536` octets en UTF-8 fatal ; `Object.hasOwn` protège les indexations dynamiques.
- **Chaîne d'approvisionnement :** Actions GitHub épinglées au SHA complet avec `step-security/harden-runner`, CodeQL, OSV-Scanner (verdict SARIF fermé par défaut), Trivy (`vuln,misconfig,secret`) et OpenSSF Scorecard.
