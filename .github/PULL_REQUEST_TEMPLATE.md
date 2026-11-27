## Résumé / Summary

## Vérifications locales / Local Verification

- [ ] `npm run type-check` (`tsc --noEmit`)
- [ ] `npm run lint` (`biome check .`)
- [ ] `npm test` (`vitest run`)
- [ ] `npm run audit` (`node scripts/verifier-audit.mjs`)

## Évaluation d'impact obligatoire (4 axes — `CLAUDE.md` / `GEMINI.md`)

1. **Code / schémas / tests du dépôt :**
2. **`README.md`, `SECURITY.md`, `LICENSE` et manifestes :**
3. **Page publique HTML (`GET /`) et `/mcp/server-card` (ce dépôt ou serveurs aval) :**
4. **Impacts inter-dépôts (`droit-civil-quebecois`, `MCP-Socle`, `MCP-Acces`, `MCP-Legislation`, `MCP-Jurisprudence`, `MCP-Outils`) :**

## Confidentialité et sécurité

- [ ] Aucun secret (`MCP_*`, `Bearer`, SHA/clé API), aucun chemin local personnel et aucune donnée client confidentielle ou privilégiée dans les commits ni dans cette PR.
