# `identite/`

| Fichier | État | Contenu |
|---|---|---|
| `porteur.ts` | Implémenté (`v0.6.0`) | Extraction et appariement du jeton (`Bearer`, `?key=` optionnel, segment de chemin), comparaison SHA-256 à temps constant (`crypto.subtle.timingSafeEqual`), plafond `MAX_LONGUEUR_PORTEUR` (512 caractères), fabrique CSPRNG `frapperJeton`. **`queryKey` est optionnel** afin que chaque dépôt ouvre `?key=` explicitement. |
| `refus.ts` | Implémenté (`v0.6.0`) | `404` sans oracle (`refuser("404")`), bascule `401` + `WWW-Authenticate: Bearer`, `origineInterdite` (`403` sans CORS), `tropDeRequetes` (`429` + `Retry-After`), `methodeNonPermise` (`405` + `Allow`). |
| `titulaire.ts` | Phase 2 (non implémenté) | Futur socle multilocataire (`Principal`, `Titulaire`, `DepotJetons` sur D1) — reporté hors `v0.6.0`. |

**Fermé par défaut, sans exception.** Aucune configuration ne doit ouvrir un point d'entrée : ni
l'absence de secret, ni une table vide, ni une erreur de lecture.
