# Resume language for Cybwaysql

Written to be pasted into the resume and defended in an interview. Every number
here is reproducible: `cybwaysql bench --curve` prints it, and the run directories
under `docs/evidence/` carry it with their hash chains intact.

Not for the repo's README — this file exists so the claims and the code stay in
step. If a number changes, change it here too.

---

## 1. The entry, for the Independent AI Engineering Practice section

**Text-to-SQL Assurance Harness (Oracle) — open source**
Built an assurance layer that sits between an LLM and a production database: the model
proposes a query, the harness decides statically whether it may execute. Twenty guards
enforce read-only access, table and column allowlists, sensitivity-labelled column
blocking, cost ceilings from declared statistics, bind-variable use, and prompt-injection
detection, against a policy held as reviewable JSON rather than code. A human approval
gate carries a SHA-256 fingerprint over the question, the SQL and the policy together, so
editing any one of them voids the approval, and a blocked query cannot be approved by
anyone — there is no override path in the codebase. Published accuracy against a committed
32-case golden set: 100% verdict accuracy, 0% false blocks, 0% missed blocks. Under a
fault sweep that degrades generation quality from 0% to 100%, the missed-block rate stays
at 0.000 — the harness fails closed. Stdlib-only runtime, no database driver, no network,
$0 to run.

## 2. Bullet points, pick four to six

- Designed and shipped a text-to-SQL assurance harness that statically validates every
  LLM-generated Oracle query before execution — read-only enforcement, table and column
  allowlisting, sensitive-column blocking, cost ceilings, and bind-variable checking —
  with no code path that executes generated SQL.
- Wrote a dialect-aware Oracle SQL analyser from scratch (stdlib only): optimizer hints
  distinguished from comments, alternative `q'[...]'` quoting, database links, `$` and `#`
  in identifiers, and stacked-statement detection, so the guards reason about structure
  rather than pattern-matching text.
- Modelled data sensitivity at column level (PUBLIC / INTERNAL / RESTRICTED / PII) and
  enforced it at query-review time, blocking identifier columns outright and routing
  restricted columns through a named human decision per NIST SP 800-53 AC-3.
- Implemented a human-in-the-loop approval gate whose fingerprint covers the question, the
  SQL and the policy together; a blocked query cannot be approved by any user, and there is
  no override flag anywhere in the codebase.
- Applied DBA cost discipline to generated SQL: row estimates derived from declared table
  statistics, cartesian-product detection by join-condition counting, full-scan detection
  on tables above a policy threshold, and refusal of optimizer hints a model has no basis
  to supply.
- Detected literal concatenation instead of bind variables as both an injection surface
  (OWASP, CWE-89) and an Oracle shared-pool cursor problem, blocking outright when the
  literal was lifted from the user's own question.
- Published measured accuracy on a committed golden set of 32 cases — answerable,
  policy-refused, and hostile — reporting false-block and missed-block rates separately
  because they are different failures, and demonstrating fail-closed behaviour under
  progressive model degradation.
- Logged every review and decision to a hash-chained, manifested run directory, so a run
  can be shown to be the run that happened; verified in CI on every push.

## 3. Skills-section additions

Add to **AI Governance & Assurance**:
> Text-to-SQL Guardrails · Query-Level Policy Enforcement · Column-Level Data
> Sensitivity Classification · Static SQL Analysis · Fail-Closed Design

Add to **Data & Cloud** (it belongs there as much as in AI):
> LLM-to-Database Access Control · Query Cost Governance · Bind-Variable Enforcement

## 4. Terms recruiters and ATS filters actually search

Carried by the entry above without keyword-stuffing: text-to-SQL, natural language to SQL,
LLM guardrails, AI guardrails, prompt injection, SQL injection, CWE-89, OWASP Top 10 for
LLM Applications, data access control, least privilege, PII, data classification, column-level
security, NIST SP 800-53, NIST SP 800-122, human-in-the-loop, approval gate, separation of
duties, audit trail, tamper-evident logging, model evaluation, golden dataset, precision and
recall, fail-closed, policy as code, Oracle, PL/SQL, query optimization, execution plan,
bind variables, static analysis, CI gate.

## 5. The two-minute interview answer

*"Tell me about Cybwaysql."*

Text-to-SQL is the most useful thing an LLM can do with a database and the most dangerous,
because the model is good enough that people stop reading the query. The failures are
quiet: a `SELECT *` that returns a column of identifiers, a missing join that turns two
tables into a cartesian product on a ninety-six-million-row table, a value from the user's
question concatenated into the predicate instead of bound. None of those are things you
prompt your way out of. They need a control between generation and execution.

So I built one. The model proposes; twenty guards decide. Read-only enforcement, allowlists,
column sensitivity, cost ceilings from table statistics, bind variables, injection patterns.
The policy is JSON so it gets reviewed in a pull request by people who don't read Python.
Nothing in the project executes SQL — there's no driver in it.

Two design decisions I'd defend. First, a blocked query cannot be approved by anyone; if a
block is wrong, the policy is wrong, and a policy changes in a reviewed commit. Second, I
report false blocks and missed blocks separately, because a suite that blocks everything
scores perfectly on safety and is useless — the false-block rate is what decides whether
anyone keeps using it.

The result I'd point at: as I degrade the model from perfect to broken, the missed-block
rate stays at zero and the false-block rate climbs. It fails closed. That's the property
you actually want, and it's the one you only find out about by measuring.

## 6. What NOT to claim

- Not "certified", "compliant", or "secure". The tool's own word is: no guard fired against
  the policy supplied.
- Not "prevents SQL injection". It blocks specific published shapes and enforces binds.
- Not an Oracle parser or optimizer. It is a tokeniser and a structural pass, and the cost
  figure is arithmetic on declared statistics, never an execution plan.
- The accuracy figures are against a 32-case set the author wrote. Say the size out loud
  in an interview; it is a strength that the set is small enough to have been read.
- Do not attach any employer, agency or system name to this work. It is synthetic
  throughout and was built independently.
