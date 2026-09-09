"""The pipeline, end to end, and the run directory it writes.

    question -> provider -> analyser -> guards -> gate -> run directory

Everything is written down: the question, the SQL that came back, every guard
that fired and why, the estimate and the arithmetic behind it, and the decision.
The log is hash-chained and the directory is manifested, so a run can be shown
to be the run that happened rather than the run someone would like to have
happened. That is the same control Cybwaydb applies to a scan, applied here to
the thing a model wrote.

Deterministic: given the same question, provider seed and policy, two runs
produce byte-identical output.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import golden, schema
from .auditlog import AuditLog, verify_manifest, write_manifest
from .evalbench import run_benchmark, summary_lines
from .gate import ApprovalGate, fingerprint
from .guards import ALLOW, APPROVE, BLOCK, WARN, guard_ids, review
from .policy import Policy, READ_ONLY_ANALYST
from .providers import MockProvider

FROZEN_STAMP = "2026-01-01T00:00:00+00:00"


def _stamp(frozen: bool) -> str:
    return FROZEN_STAMP if frozen else datetime.now(timezone.utc).isoformat(timespec="seconds")


def ask(question: str, pol: Policy | None = None, provider=None,
        sql: str | None = None) -> dict:
    """One question through the whole pipeline. Returns the review as a dict.

    `sql` short-circuits generation, which is how a person reviews a query they
    already have.
    """
    pol = pol or READ_ONLY_ANALYST
    provider = provider or MockProvider(fault_rate=0.0)
    generated = sql if sql is not None else provider.generate(question)
    r = review(question, generated, pol)
    out = r.to_dict()
    out["provider"] = "supplied" if sql is not None else getattr(provider, "name", "?")
    out["fingerprint"] = fingerprint(question, generated, pol.name)
    return out


def run_batch(questions: list, out_dir: str | Path, pol: Policy | None = None,
              provider=None, frozen: bool = False, approver: str = "") -> dict:
    """Review a list of questions and write the run directory."""
    pol = pol or READ_ONLY_ANALYST
    provider = provider or MockProvider(fault_rate=0.0)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = _stamp(frozen)

    log = AuditLog(out / "audit.log.jsonl")
    log.append("run_started", {
        "policy": pol.name, "provider": getattr(provider, "name", "?"),
        "questions": len(questions), "guards": len(guard_ids()),
        "schema_tables": len(schema.TABLES), "mode": "static review, no execution",
        "cost_usd": 0,
    }, timestamp=stamp)

    gate = ApprovalGate(log)
    reviews = []
    for q in questions:
        r = review(q, provider.generate(q), pol)
        reviews.append(r)
        log.append("query_reviewed", {
            "question": q, "verdict": r.verdict,
            "fingerprint": fingerprint(q, r.sql, pol.name),
            "guards_fired": [f.guard_id for f in r.findings],
            "estimated_rows": r.estimate.get("rows"),
        }, timestamp=stamp)
        if approver and r.verdict in (ALLOW, WARN, APPROVE):
            gate.approve(r, approver, "batch approval recorded at review time", timestamp=stamp)

    summary = summarise(reviews, pol, provider, gate)
    (out / "reviews.json").write_text(
        json.dumps({"policy": pol.name, "reviews": [r.to_dict() for r in reviews]}, indent=2),
        encoding="utf-8")
    (out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (out / "summary.txt").write_text(render_text(reviews, summary), encoding="utf-8")
    (out / "decisions.json").write_text(
        json.dumps([d.to_dict() for d in gate.decisions.values()], indent=2), encoding="utf-8")
    (out / "policy.json").write_text(json.dumps(pol.to_dict(), indent=2), encoding="utf-8")

    log.append("run_completed", summary, timestamp=stamp)
    write_manifest(out, {"summary": summary, "generated_at": stamp})
    return summary


def summarise(reviews: list, pol: Policy, provider, gate: ApprovalGate) -> dict:
    counts: dict = {}
    for r in reviews:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    fired: dict = {}
    for r in reviews:
        for f in r.findings:
            fired[f.guard_id] = fired.get(f.guard_id, 0) + 1
    blocked = counts.get(BLOCK, 0)
    return {
        "questions": len(reviews),
        "verdicts": counts,
        "blocked": blocked,
        "needs_a_person": counts.get(APPROVE, 0),
        "ran_without_comment": counts.get(ALLOW, 0),
        "guards_fired": dict(sorted(fired.items())),
        "policy": pol.name,
        "provider": getattr(provider, "name", "?"),
        "gate": gate.summary(),
        "mode": "static review only, nothing was executed",
        "cost_usd": 0,
    }


def render_text(reviews: list, summary: dict) -> str:
    """The run as sentences, wrapped to 78 columns for reading or mailing."""
    import textwrap

    def wrap(text, indent="      "):
        return textwrap.wrap(text, 78, initial_indent=indent, subsequent_indent=indent,
                             break_long_words=False) or []

    L = [f"Cybwaysql - {summary['questions']} question(s) reviewed under policy "
         f"{summary['policy']}", "=" * 74,
         f"{summary['blocked']} blocked, {summary['needs_a_person']} need a person, "
         f"{summary['ran_without_comment']} passed without comment. "
         f"Nothing was executed.", ""]
    for r in reviews:
        L.append(f"[{r.verdict}] {r.question}")
        L += wrap(" ".join(r.sql.split()), "      SQL: ")
        for f in r.findings:
            L.append(f"      {f.verdict:7} {f.guard_id}  {f.title}")
            L += wrap(f.detail, "              ")
            if f.remedy:
                L += wrap(f"Try: {f.remedy}", "              ")
        if r.estimate.get("rows") is not None:
            L += wrap(f"Estimate: {r.estimate['rows']:,} rows examined. "
                      f"{r.estimate['basis']}.", "      ")
        L.append("")
    L.append("An estimate here is arithmetic on declared statistics, not an Oracle")
    L.append("execution plan. A verdict of ALLOW means no guard fired against the policy")
    L.append("supplied, which is not the same as saying the query is safe.")
    return "\n".join(L) + "\n"


def integrity_of(run_dir: str | Path) -> dict:
    run_dir = Path(run_dir)
    chain_ok, chain_msg = AuditLog(run_dir / "audit.log.jsonl").verify_chain()
    man_ok, problems = verify_manifest(run_dir)
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    return {"chain_ok": chain_ok, "chain_msg": chain_msg, "manifest_ok": man_ok,
            "manifest_problems": problems,
            "manifest_sha256": manifest.get("manifest_sha256", "")}


def run_bench(out_dir: str | Path | None = None, pol: Policy | None = None,
              provider=None, use_reference: bool = True, frozen: bool = True) -> dict:
    """The benchmark, optionally written to a run directory with its own chain."""
    result = run_benchmark(pol, provider=provider, use_reference=use_reference)
    if out_dir is None:
        return result
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = _stamp(frozen)
    log = AuditLog(out / "audit.log.jsonl")
    log.append("benchmark_started", {"cases": result["cases"], "policy": result["policy"],
                                     "mode": result["mode"]}, timestamp=stamp)
    for case in result["per_case"]:
        log.append("case_scored", {k: case[k] for k in
                                   ("case_id", "kind", "expected", "actual", "correct")},
                   timestamp=stamp)
    headline = {k: result[k] for k in
                ("cases", "guard_accuracy", "false_block_rate", "missed_block_rate",
                 "precision", "recall", "f1", "policy", "mode")}
    (out / "benchmark.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (out / "benchmark.txt").write_text("\n".join(summary_lines(result)) + "\n", encoding="utf-8")
    log.append("benchmark_completed", headline, timestamp=stamp)
    write_manifest(out, {"summary": headline, "generated_at": stamp})
    return result
