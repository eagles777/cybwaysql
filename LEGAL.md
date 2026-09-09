# LEGAL.md — Source Material & Licensing

## Our code

Apache-2.0. Copyright © V. Vikram. See `LICENSE` and `NOTICE`.

The hash-chained audit log and run manifest are adapted from the author's projects
Cybwaydb and Cybwaycard (Apache-2.0, same copyright holder).

## Third-party and reference material

| Source | Status | How we use it |
|---|---|---|
| Oracle SQL syntax, supplied package names (`DBMS_*`, `UTL_*`), data-dictionary view names | Facts and identifiers, not expression | Named in the analyser and the guards so a finding can say which construct it found. No Oracle documentation text is reproduced. |
| OWASP Top 10 for LLM Applications | Referenced by name, with attribution to the OWASP Foundation | Category identifiers on findings (LLM01, LLM02, LLM05, LLM06, LLM10). Category names only. |
| OWASP injection category names, CWE-89 | Referenced by identifier | Named on the bind-variable and stacked-statement guards. |
| NIST SP 800-53 rev5 (AC-3) | US Government work, public domain | Control identifier on the allowlist and approval guards. |
| NIST SP 800-122 | US Government work, public domain | Cited on the sensitive-column guard. |
| NIST AI RMF 1.0 (NIST AI 100-1) | US Government work, public domain | Referenced in the design; self-assessed, not a conformance claim. |
| CIS Benchmarks | **Copyrighted — EXCLUDED** | Not used anywhere in this repository. |

## Trademarks

Oracle is a trademark of Oracle Corporation. This project is not affiliated with,
endorsed by, or sponsored by Oracle, OWASP, NIST, or any employer of the author.

## Data

Every schema object, row, question, query, policy and fixture in this repository is
synthetic and invented for testing. No real database, credential, personal, or
organizational data appears anywhere. Sample values carry a marker (`SAMPLE`, `FAKE`,
`example.com`, `555-01xx`) so they are recognisable as invented.

## What this project is not

It is not legal advice, not a compliance certification, and not a security product.
A verdict of ALLOW means no guard fired against the policy supplied. It is not a
statement that a query is safe, and the tool never uses that word.
