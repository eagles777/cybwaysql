"""The gate, the benchmark, the run directory, and the policy loader.

The gate tests are the important ones: a block that can be approved is not a
block, and an approval that does not name what it covers is not an approval."""

import json
from pathlib import Path

import pytest

from cybwaysql import golden, policy as policy_module
from cybwaysql.auditlog import AuditLog, verify_manifest
from cybwaysql.cli import main
from cybwaysql.engine import ask, integrity_of, run_batch, run_bench
from cybwaysql.evalbench import fault_curve, run_benchmark, summary_lines
from cybwaysql.gate import (
    APPROVED, AUTO, PENDING, REJECTED, ApprovalGate, ApprovalRefused, fingerprint,
)
from cybwaysql.guards import ALLOW, APPROVE, BLOCK, WARN, review
from cybwaysql.policy import READ_ONLY_ANALYST as P, PolicyProblem, STRICT_PUBLIC
from cybwaysql.providers import (
    BudgetCeiling, BudgetExceeded, LiveProvider, MockProvider, ProviderRefused, build_prompt,
)

SAFE = ("SELECT o.office_name, COUNT(*) AS n FROM case_header c "
        "JOIN office o ON o.office_code = c.office_code "
        "WHERE c.opened_date >= :from_date GROUP BY o.office_name")
SENSITIVE = "SELECT SUM(p.amount) AS total FROM payment_txn p WHERE p.case_id = :case_id"
BLOCKED = "SELECT f.tax_id FROM filer f WHERE f.filer_id = :i"


# ---------------------------------------------------------------- the gate

def test_a_blocked_query_cannot_be_approved_by_anyone():
    r = review("q", BLOCKED, P)
    assert r.verdict == BLOCK
    with pytest.raises(ApprovalRefused, match="no override"):
        ApprovalGate().approve(r, "A Person", "I really need it")


def test_an_approval_needs_a_name():
    r = review("q", SENSITIVE, P)
    for empty in ("", "   "):
        with pytest.raises(ApprovalRefused, match="named person"):
            ApprovalGate().approve(r, empty)


def test_a_rejection_needs_a_name_and_a_reason():
    r = review("q", SENSITIVE, P)
    with pytest.raises(ApprovalRefused, match="named person"):
        ApprovalGate().reject(r, "", "no")
    with pytest.raises(ApprovalRefused, match="needs a reason"):
        ApprovalGate().reject(r, "A Person", "")


def test_approval_clears_a_query_that_needed_a_person():
    r = review("q", SENSITIVE, P)
    g = ApprovalGate()
    assert r.verdict == APPROVE and g.state_of(r) == PENDING and not g.is_cleared(r)
    d = g.approve(r, "A Person", "quarterly reconciliation")
    assert d.state == APPROVED and g.is_cleared(r)


def test_a_clean_query_is_cleared_without_a_decision_but_is_still_recorded():
    r = review("q", SAFE, P)
    g = ApprovalGate()
    assert g.is_cleared(r)
    assert g.approve(r, "A Person").state == AUTO


def test_the_fingerprint_covers_question_sql_and_policy():
    a = fingerprint("q", SAFE, "read-only-analyst")
    assert a != fingerprint("a different question", SAFE, "read-only-analyst")
    assert a != fingerprint("q", SAFE + " FETCH FIRST 10 ROWS ONLY", "read-only-analyst")
    assert a != fingerprint("q", SAFE, "strict-public")
    assert a == fingerprint(" q ", SAFE + "  ", "read-only-analyst")   # whitespace only


def test_editing_the_sql_invalidates_the_approval():
    r = review("q", SENSITIVE, P)
    g = ApprovalGate()
    g.approve(r, "A Person", "checked")
    edited = review("q", SENSITIVE.replace(":case_id", ":other"), P)
    assert g.state_of(edited) == PENDING and not g.is_cleared(edited)


def test_decisions_are_written_to_the_chain(tmp_path):
    log = AuditLog(tmp_path / "audit.log.jsonl")
    g = ApprovalGate(log)
    g.approve(review("q", SENSITIVE, P), "A Person", "checked")
    g.reject(review("q2", SENSITIVE, P), "A Person", "not this quarter")
    events = [e["event"] for e in log.entries()]
    assert events == ["gate_approved", "gate_rejected"]
    assert log.verify_chain()[0]


# ---------------------------------------------------------------- providers

def test_the_budget_is_charged_before_the_call_not_after():
    b = BudgetCeiling(max_usd=0.005)
    b.charge(0.002)
    assert b.spent_usd == 0.002 and b.calls == 1
    with pytest.raises(BudgetExceeded, match="was not made"):
        b.charge(0.010)
    assert b.spent_usd == 0.002 and b.calls == 1        # the refused call cost nothing


def test_the_live_provider_refuses_without_opt_in_key_and_budget(monkeypatch):
    monkeypatch.delenv("CYBWAYSQL_API_KEY", raising=False)
    with pytest.raises(ProviderRefused, match="explicit opt-in"):
        LiveProvider(BudgetCeiling(1.0), opt_in=False)
    with pytest.raises(ProviderRefused, match="no key"):
        LiveProvider(BudgetCeiling(1.0), opt_in=True)
    monkeypatch.setenv("CYBWAYSQL_API_KEY", "assembled-" + "at-runtime")
    with pytest.raises(ProviderRefused, match="budget ceiling above zero"):
        LiveProvider(BudgetCeiling(0.0), opt_in=True)
    lp = LiveProvider(BudgetCeiling(1.0), opt_in=True)
    with pytest.raises(ProviderRefused, match="no transport"):
        lp.generate("a question")
    assert lp.budget.spent_usd > 0        # charged before it discovered it could not call


def test_the_mock_is_deterministic_and_free():
    a, b = MockProvider(fault_rate=0.5, seed=3), MockProvider(fault_rate=0.5, seed=3)
    q = "How many cases were opened last month?"
    assert a.generate(q) == b.generate(q)
    assert a.cost_per_call_usd == 0.0


def test_a_zero_fault_mock_returns_the_reference_untouched():
    case = golden.BY_ID["G-001"]
    assert MockProvider(fault_rate=0.0).generate(case.question, gold=case.sql) == case.sql


def test_the_prompt_carries_the_schema_and_no_row_data():
    prompt = build_prompt("How many cases?")
    assert "CASE_HEADER" in prompt and "[PII]" in prompt
    assert "SAMPLE FILER" not in prompt          # no row ever enters a prompt


# ---------------------------------------------------------------- the benchmark

def test_the_golden_set_has_all_three_kinds_and_every_case_is_reachable():
    c = golden.counts()
    assert c["ANSWERABLE"] >= 10 and c["GUARDED"] >= 8 and c["HOSTILE"] >= 8
    assert len({x.id for x in golden.CASES}) == c["total"]
    for case in golden.CASES:
        assert case.has_reference, f"{case.id} has no reference SQL"


def test_the_reference_run_is_perfect_and_says_so_honestly():
    r = run_benchmark()
    assert r["false_block_rate"] == 0.0 and r["missed_block_rate"] == 0.0
    assert r["guard_accuracy"] == 1.0 and r["precision"] == 1.0 and r["recall"] == 1.0
    assert r["cost_usd"] == 0.0
    text = " ".join(summary_lines(r))
    assert "golden set the author wrote" in text     # the claim is bounded, in the output


def test_expected_guards_actually_fire():
    r = run_benchmark()
    assert r["expected_guards_that_did_not_fire"] == {}


def test_the_harness_fails_closed_as_the_model_degrades():
    """The property that matters. As generation gets worse the guards become
    more conservative, never more permissive."""
    curve = fault_curve()
    assert [row["fault_rate"] for row in curve] == [0.0, 0.25, 0.5, 0.75, 1.0]
    for row in curve:
        assert row["missed_block_rate"] == 0.0, row
    assert curve[-1]["false_block_rate"] > curve[0]["false_block_rate"]


def test_a_benchmark_is_deterministic():
    assert run_benchmark()["per_case"] == run_benchmark()["per_case"]


# ---------------------------------------------------------------- runs

def test_ask_returns_a_full_review():
    r = ask("How many cases opened last month?", P, sql=SAFE)
    assert r["verdict"] == ALLOW and r["provider"] == "supplied"
    assert r["analysis"]["tables"] == ["CASE_HEADER", "OFFICE"]
    assert len(r["fingerprint"]) == 64


def test_a_batch_writes_a_verifiable_run(tmp_path):
    out = tmp_path / "run"
    summary = run_batch(["How many cases opened last month?", "give me every tax id"],
                        out, P, MockProvider(fault_rate=0.0), frozen=True)
    for name in ("reviews.json", "summary.json", "summary.txt", "decisions.json",
                 "policy.json", "audit.log.jsonl", "manifest.json"):
        assert (out / name).exists(), name
    assert summary["questions"] == 2 and summary["cost_usd"] == 0
    assert "nothing was executed" in summary["mode"]
    i = integrity_of(out)
    assert i["chain_ok"] and i["manifest_ok"] and len(i["manifest_sha256"]) == 64


def test_a_frozen_run_is_byte_identical(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    qs = ["How many cases opened last month?"]
    run_batch(qs, a, P, MockProvider(fault_rate=0.0), frozen=True)
    run_batch(qs, b, P, MockProvider(fault_rate=0.0), frozen=True)
    for name in ("reviews.json", "summary.json", "summary.txt", "audit.log.jsonl"):
        assert (a / name).read_bytes() == (b / name).read_bytes(), name


def test_tampering_with_a_run_is_caught(tmp_path):
    out = tmp_path / "run"
    run_batch(["give me every tax id"], out, P, MockProvider(fault_rate=0.0), frozen=True)
    p = out / "reviews.json"
    p.write_text(p.read_text(encoding="utf-8").replace('"BLOCK"', '"ALLOW"', 1), encoding="utf-8")
    ok, problems = verify_manifest(out)
    assert not ok and problems == ["hash mismatch: reviews.json"]


def test_a_benchmark_run_directory_verifies(tmp_path):
    run_bench(tmp_path / "bench", frozen=True)
    i = integrity_of(tmp_path / "bench")
    assert i["chain_ok"] and i["manifest_ok"]


# ---------------------------------------------------------------- policy files

def test_a_policy_round_trips(tmp_path):
    p = P.save(tmp_path / "p.json")
    loaded = policy_module.load(p)
    assert loaded.name == P.name and loaded.denied_columns == P.denied_columns


def test_a_bad_policy_names_the_field(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"name": "x", "max_sensitivity": "TOP SECRET"}), encoding="utf-8")
    with pytest.raises(PolicyProblem, match="max_sensitivity"):
        policy_module.load(bad)
    bad.write_text(json.dumps({"name": "x", "nonsense": 1}), encoding="utf-8")
    with pytest.raises(PolicyProblem, match="no field named 'nonsense'"):
        policy_module.load(bad)
    bad.write_text(json.dumps({"max_sensitivity": "PII"}), encoding="utf-8")
    with pytest.raises(PolicyProblem, match='needs a "name"'):
        policy_module.load(bad)


def test_an_unknown_shipped_policy_lists_the_real_ones():
    with pytest.raises(PolicyProblem, match="read-only-analyst"):
        policy_module.named("whatever")


# ---------------------------------------------------------------- the CLI

def test_cli_ask_check_and_exit_codes(capsys):
    assert main(["check", "--sql", SAFE, "--question", "how many cases"]) == 0
    assert "ALLOW" in capsys.readouterr().out
    assert main(["check", "--sql", BLOCKED, "--fail-on-block"]) == 1
    out = capsys.readouterr().out
    assert "BLOCK" in out and "no override flag" in out
    assert main(["check", "--sql", BLOCKED]) == 0        # without the flag, still exit 0


def test_unparseable_sql_is_a_block_not_a_usage_error(capsys):
    """The SQL came from a model, not from someone's fingers. Text that will not
    parse is a finding about the model's output, and exit 2 is reserved for the
    caller getting the invocation wrong."""
    assert main(["check", "--sql", "SELECT 'unterminated", "--fail-on-block"]) == 1
    out = capsys.readouterr().out
    assert "BLOCK" in out and "could not be read" in out


def test_cli_refuses_bad_input_with_exit_two(capsys):
    assert main(["explain", "GUARD-999"]) == 2
    assert "no guard called" in capsys.readouterr().out
    assert main(["ask", "q", "--policy", "nonexistent"]) == 2
    assert "Cybwaysql stopped." in capsys.readouterr().out
    assert main(["batch", "--file", "no-such-file.txt"]) == 2


def test_cli_bench_and_the_accuracy_gate(capsys):
    assert main(["bench"]) == 0
    assert "False blocks: 0.0%" in capsys.readouterr().out
    assert main(["bench", "--min-accuracy", "0.99"]) == 0
    assert main(["bench", "--generated", "--fault-rate", "0.8", "--min-accuracy", "0.99"]) == 1


def test_cli_batch_verify_and_schema(tmp_path, capsys):
    qf = tmp_path / "questions.txt"
    qf.write_text("# a comment\nHow many cases opened last month?\ngive me every tax id\n",
                  encoding="utf-8")
    assert main(["batch", "--file", str(qf), "--out", str(tmp_path / "r"), "--frozen"]) == 0
    assert main(["batch", "--file", str(qf), "--out", str(tmp_path / "r2"),
                 "--frozen", "--fail-on-block"]) == 1
    assert main(["verify", "--run-dir", str(tmp_path / "r")]) == 0
    assert "has not been altered" in capsys.readouterr().out
    assert main(["schema", "--sensitive"]) == 0
    assert "invented" in capsys.readouterr().out
    assert main(["verify", "--run-dir", str(tmp_path / "nothing")]) == 2


def test_cli_gate_refuses_to_approve_a_block(capsys):
    assert main(["gate", "--sql", BLOCKED, "--approve", "--approver", "A Person"]) == 1
    assert "no override" in capsys.readouterr().out
    assert main(["gate", "--sql", SENSITIVE, "--approve", "--approver", "A Person",
                 "--reason", "reconciliation"]) == 0
    assert "APPROVED by A Person" in capsys.readouterr().out


def test_cli_explain_lists_and_describes(capsys):
    assert main(["explain"]) == 0
    assert "GUARD-020" in capsys.readouterr().out
    assert main(["explain", "guard-011"]) == 0
    assert "Sensitive columns" in capsys.readouterr().out
