# PROGRESS.md

## Session 1 — 2026-09-09 — v0.1 built end to end

Scope decided with the owner: the seam between his database career and his AI
positioning is an LLM writing SQL against a real database. Oracle-flavoured, named
`cybwaysql`, third in the Cybway family.

Built:
- `oraclesql.py` — tokeniser and structural analyser. Hand-written, stdlib only, because
  the dialect specifics that matter are what generic parsers get wrong: `/*+ hints */`
  distinguished from comments, `q'[...]'` quoting, `@dblink`, `$` and `#` in identifiers,
  `''` escaping, and multi-statement detection.
- `schema.py` — synthetic case-management schema, 8 tables, sensitivity labels on every
  column, declared row counts up to 96 million, Oracle DDL rendering, SQLite instance.
- `policy.py` — policy as a reviewable JSON document; `read-only-analyst` and
  `strict-public`; the dangerous-package list with a reason per package.
- `guards.py` — GUARD-001..020 and GATE-001..002; `estimate_rows()` that explains its
  own arithmetic; `review()` where the worst finding wins.
- `providers.py` — deterministic mock with realistic fault injection; `BudgetCeiling`
  charged before the call; `LiveProvider` behind opt-in + env key + budget, no transport.
- `golden.py` — 32 cases: 12 answerable, 10 guarded, 10 hostile.
- `evalbench.py` — verdict accuracy, false-block rate, missed-block rate, precision and
  recall over the block decision, and the fault curve.
- `gate.py` — approval fingerprinted over question + SQL + policy; a BLOCK cannot be
  approved by anyone; no override exists.
- `engine.py`, `cli.py`, hash-chained run directories, `verify`.

Measured this session:
- `pytest` → 84 passed, offline, $0.
- Reference set: verdict accuracy 100%, false blocks 0%, missed blocks 0%, precision
  1.000, recall 1.000.
- End to end through the mock at fault rate 0.35: accuracy 75%, false blocks 62%,
  missed blocks 0%.
- Fault curve 0.00 → 1.00: missed-block rate stays at 0.000 at every point. The harness
  fails closed. That is the headline result.
- All three committed evidence runs verify: chain intact, manifest matches.

Four defects the harness found in itself while being built, each now a test:
1. A comma in `GROUP BY a, b` was read as another table in the FROM list.
2. `COUNT(*)` was read as `SELECT *`, blocking every aggregate.
3. `alias.column` was read as a package call, so every qualified column looked like one.
4. A table joined on a key was reported as a full scan, so every lookup table in a
   correct query looked like an accident.

One policy miscalibration, also caught by the benchmark: the approval threshold started
at 250,000 rows, which fired on nearly every query. A gate that fires on everything is a
queue, not a gate, and people learn to click through it. Raised to 2,000,000.

Open, and needing the owner:
- The GitHub repo does not exist yet. It is created PRIVATE or not at all.
- Tag, release, Pages, PyPI: all owner decisions, none taken.
