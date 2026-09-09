# CLAUDE.md — Project Instructions for Cybwaysql

Cybwaysql is an open-source assurance harness for LLM-generated Oracle SQL — a personal AI-engineering portfolio project by V. Vikram, and the third in the Cybway family after Cybwaydb and Cybwaycard. A model proposes a query from a question in English; Cybwaysql decides, statically and before anything runs, whether that query may execute at all. It is NOT connected to any employer and contains zero employer or organizational data. Everything in the repo is synthetic.

The family arc, stated so it stays coherent: **Cybwaydb** is AI reading a database's security configuration. **Cybwaycard** is auditing the code around a model. **Cybwaysql** is AI writing SQL that touches data — the point where the risk is highest and the governance has to be strictest.

Act as a senior engineer and build partner: direct, practical, push back on weak ideas, no praise-padding. Build the code; the owner supervises and approves. Show passing tests before moving on. Track progress in PROGRESS.md so it compounds across sessions.

## STANDING SESSION REMINDER

At the START of every session, check whether the GitHub repo (eagles777/cybwaysql) is PUBLIC or PRIVATE and report the status before doing anything else. It stays PRIVATE until the owner reviews it and explicitly says to go public. Never change visibility, never tag a release, never enable Pages, never publish to PyPI without asking first.

## HARD RULES (never violate)

* **Static analysis, then a gate. Never execution.** Cybwaysql parses generated SQL and decides. It never connects to a real database, never executes a generated statement against anything but the synthetic read-only sample, and has no code path that runs DDL or DML at all. "Dry run" means parse and estimate, not execute.
* **DEFENSIVE only.** The red-team suite exercises OUR OWN guards with published injection patterns, the way promptfoo or DeepEval does. Nothing here teaches anyone to attack a database. If a feature drifts toward "how to exfiltrate X", reframe it as "detect and block X".
* **Synthetic data only.** The sample schema, the row data, the golden question set and every fixture are invented. No real table name, column name, connect string, credential, or organizational identifier ever enters the repo. Assemble any credential-shaped test value at runtime so no such literal exists in source.
* **Mock first, $0 by default.** Everything runs with a deterministic mock provider: no API key, no network, no cost. A live provider is opt-in only, gated behind an explicit flag plus an environment key plus a code-enforced budget ceiling charged BEFORE each call. CI never makes a paid call.
* **The model never grades itself.** Generation and verification are separate objects. The guard engine and the checker derive their verdict from the SQL text and the schema, never from the model's own explanation of what it wrote.
* **Honest output.** A PASS means "no guard fired against the policy you supplied", never "this query is safe". Cost and row estimates are estimates from declared statistics and are labelled as such — they are not an Oracle optimizer plan and must never be presented as one. Anything the analyser cannot parse is reported UNPARSEABLE and blocked, never waved through.
* **Copyright.** Oracle is a trademark of Oracle Corporation; this project is not affiliated with or endorsed by them. Oracle SQL syntax and data-dictionary view names are facts and are referenced by name; no Oracle documentation text is reproduced. OWASP Top 10 for LLM Applications and OWASP API/SQL-injection category names are referenced with attribution. NIST SP 800-53 and the NIST AI RMF are US Government works cited by identifier. CIS Benchmarks are excluded. Our code is Apache-2.0, V. Vikram is the copyright holder. Maintain LEGAL.md and NOTICE.
* **Privacy (STRICT).** No personal or employer information anywhere in the repo: no location, no citizenship, no employer or agency name, no job history, no contact details. Attribution is limited to the author's name as copyright holder. Ask before committing any personal detail.
* **Maintainability.** Stdlib-only runtime, pinned dev dependency, deterministic output so two runs of the same input diff cleanly, MAINTENANCE.md and BACKLOG.md kept current.
