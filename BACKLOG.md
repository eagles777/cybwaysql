# BACKLOG.md

## Done — v0.1

- [x] Oracle tokeniser and structural analyser (hints, q-quotes, links, `$`/`#` identifiers)
- [x] 20 guards + 2 approval gates, each with evidence and a remedy
- [x] Policy as reviewable JSON; two shipped policies
- [x] Synthetic schema with sensitivity labels and declared statistics
- [x] Row-estimate arithmetic that explains itself
- [x] Mock provider with realistic fault injection; live provider behind three locks
- [x] 32-case golden set; false-block and missed-block rates; the fault curve
- [x] Approval gate with a fingerprint over question + SQL + policy
- [x] Hash-chained run directories, manifest, `verify`
- [x] CLI, 84 tests, CI that runs the benchmark as a gate
- [x] Committed evidence with chains intact

## Next

- [ ] Tagged v0.1.0 release (needs owner)
- [ ] A browser demo: paste a query, see the guards fire, no install
- [ ] SARIF output so findings appear in the GitHub code-scanning tab
- [ ] View resolution: expand a view to its base tables so column guards see through it
- [ ] A second dialect (PostgreSQL) behind the same guard interface
- [ ] Bind-variable extraction: rewrite a literal predicate into a bound one and show the diff

## Later

- [ ] `EXPLAIN PLAN` ingestion as an optional, clearly-separated cost source, so the
      estimate can be replaced by a real plan where one is available
- [ ] Row-level security awareness: which predicates a policy would inject
- [ ] PyPI publish (needs owner account)

## Never

- An override flag on a BLOCK.
- A code path that executes generated SQL.
