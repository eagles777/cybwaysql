# MAINTENANCE.md

How a future session keeps Cybwaysql healthy.

## Layout

```
src/cybwaysql/
  oraclesql.py   tokeniser + structural analyser for Oracle SQL. The piece everything
                 else depends on. Hand-written because the dialect specifics that matter
                 (hints, q-quoted literals, database links, $ and # in identifiers) are
                 what generic parsers get wrong.
  schema.py      the synthetic schema, its declared statistics, and its sensitivity
                 labels; Oracle DDL rendering; a SQLite instance for the harness
  policy.py      Policy dataclass, JSON load/save, the two shipped policies,
                 the dangerous-package list
  guards.py      GUARD-001..020 + GATE-001..002, estimate_rows(), review()
  providers.py   MockProvider (deterministic, deliberately imperfect), BudgetCeiling,
                 LiveProvider (three locks, no transport)
  golden.py      the 32-case golden set: ANSWERABLE / GUARDED / HOSTILE
  evalbench.py   scoring, false-block and missed-block rates, the fault curve
  gate.py        the approval gate and the fingerprint
  engine.py      ask(), run_batch(), run_bench(), run directories, integrity_of()
  auditlog.py    hash-chained JSONL + SHA-256 manifest  [adapted from Cybwaydb]
  cli.py         the only place that reads argv and decides an exit code
docs/evidence/   committed runs with their chains intact
```

## Dependencies

Runtime: **stdlib only**, deliberately. A governance tool whose core is a dependency
nobody has read is not much of a governance tool. Dev: `pytest==8.2.2`, pinned.

## Routine checks, all of which CI runs

- `pytest` passes.
- `cybwaysql bench --min-accuracy 1.0` — the reference set stays perfect.
- `cybwaysql bench --generated --fault-rate 0.35` — the pipeline end to end.
- A clean query passes and a PII query is refused, both asserted in CI.
- `cybwaysql verify` on a freshly written run.

## Adding a guard

1. Write the function in `guards.py` with the `@guard` decorator, a unique `GUARD-0xx`,
   and a docstring that states the condition. Return `[]` when it does not apply.
2. Give the finding a `remedy`: how to ask for the same thing in a way that passes.
   A guard that only refuses teaches nobody anything.
3. Add both polarities to `tests/test_guards.py` — it fires when it should, and it is
   quiet when it should not.
4. Add a golden case that exercises it, and set `expect_guards`.
5. Re-run `cybwaysql bench`. If the false-block rate moved, the guard is too eager;
   that number is the one that decides whether anyone keeps using the tool.
6. Regenerate `docs/evidence/` and update the counts in README.

## Adding a schema object

Give every column a sensitivity label and every table a declared `num_rows`. The cost
guard is arithmetic on those numbers, so a table with no statistics blocks rather than
passes. Say in the column's `note` why a label was chosen.

## Invariants (from CLAUDE.md — do not break)

- Static analysis then a gate, never execution. No database driver enters this project.
- Anything unparseable is blocked. Unsure means blocked.
- A BLOCK cannot be approved. No override flag may ever be added.
- The word "safe" never appears in a verdict; a test enforces it.
- Cost estimates are labelled as arithmetic on declared statistics, never as a plan.
- Mock by default, $0. Live is opt-in + env key + budget charged before the call.
- Synthetic data only; no credential-shaped literal in any file, including tests.
