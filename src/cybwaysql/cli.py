"""The command line. The only place that reads argv and decides an exit code.

Exit codes, because a pipeline reads them:
  0  the review completed and nothing blocked
  1  the caller asked to fail on this answer (a block, a missed guard, a bad chain)
  2  the input was wrong, and the message says which field
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, golden, guards, policy as policy_module, schema
from .engine import ask, integrity_of, run_batch, run_bench
from .evalbench import fault_curve, summary_lines
from .gate import ApprovalGate, ApprovalRefused, explain_gate
from .guards import ALLOW, APPROVE, BLOCK, WARN, review
from .oraclesql import SqlUnparseable, analyse
from .policy import PolicyProblem
from .providers import BudgetCeiling, BudgetExceeded, MockProvider, describe_providers

STOP = "Cybwaysql stopped."


def _policy(args):
    if getattr(args, "policy_file", None):
        return policy_module.load(args.policy_file)
    return policy_module.named(getattr(args, "policy", "read-only-analyst"))


def _print_review(r: dict, show_sql: bool = True) -> None:
    print(f"[{r['verdict']}] {r['question']}")
    if show_sql:
        print(f"  SQL: {' '.join(r['sql'].split())}")
    for f in r["findings"]:
        print(f"  {f['verdict']:7} {f['guard_id']}  {f['title']}")
        print(f"          {f['detail']}")
        for e in f["evidence"][:3]:
            print(f"          - {e}")
        if f["remedy"]:
            print(f"          try: {f['remedy']}")
    est = r.get("estimate") or {}
    if est.get("rows") is not None:
        print(f"  Estimate: {est['rows']:,} rows examined. {est['basis']}.")
        print("  That is arithmetic on declared statistics, not an execution plan.")


def main(argv: list | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="cybwaysql",
        description="Decide whether an LLM-generated Oracle query may run. "
                    "Static review only: nothing here executes SQL.")
    p.add_argument("--version", action="version", version=f"cybwaysql {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def add_policy(sp):
        sp.add_argument("--policy", default="read-only-analyst",
                        help="a shipped policy: " + ", ".join(policy_module.POLICIES))
        sp.add_argument("--policy-file", default=None, help="a policy JSON file")

    a = sub.add_parser("ask", help="Review one question, generating the SQL")
    a.add_argument("question")
    a.add_argument("--sql", default=None, help="review this SQL instead of generating it")
    a.add_argument("--fault-rate", type=float, default=0.0,
                   help="how often the mock model makes a mistake (0 to 1)")
    a.add_argument("--json", action="store_true")
    a.add_argument("--fail-on-block", action="store_true")
    add_policy(a)

    c = sub.add_parser("check", help="Review SQL you already have")
    c.add_argument("--sql", required=True)
    c.add_argument("--question", default="", help="the question it came from, if any")
    c.add_argument("--json", action="store_true")
    c.add_argument("--fail-on-block", action="store_true")
    add_policy(c)

    b = sub.add_parser("batch", help="Review a file of questions and write a run directory")
    b.add_argument("--file", required=True, help="one question per line")
    b.add_argument("--out", default="runs/latest")
    b.add_argument("--fault-rate", type=float, default=0.0)
    b.add_argument("--approver", default="", help="record an approval under this name")
    b.add_argument("--frozen", action="store_true", help="freeze timestamps for reproducibility")
    b.add_argument("--fail-on-block", action="store_true")
    add_policy(b)

    bench = sub.add_parser("bench", help="Score the golden set and publish the numbers")
    bench.add_argument("--out", default=None, help="write a run directory too")
    bench.add_argument("--generated", action="store_true",
                       help="score the pipeline end to end instead of the reference SQL")
    bench.add_argument("--fault-rate", type=float, default=0.35)
    bench.add_argument("--curve", action="store_true",
                       help="show how the harness behaves as the model degrades")
    bench.add_argument("--json", action="store_true")
    bench.add_argument("--min-accuracy", type=float, default=None,
                       help="exit 1 if verdict accuracy falls below this")
    add_policy(bench)

    g = sub.add_parser("gate", help="Approve or reject a query that needs a person")
    g.add_argument("--sql", required=True)
    g.add_argument("--question", default="")
    g.add_argument("--approve", action="store_true")
    g.add_argument("--reject", action="store_true")
    g.add_argument("--approver", default="")
    g.add_argument("--reason", default="")
    add_policy(g)

    e = sub.add_parser("explain", help="What a guard checks, and why")
    e.add_argument("guard_id", nargs="?", default="")

    s = sub.add_parser("schema", help="The synthetic schema")
    s.add_argument("--ddl", action="store_true", help="as Oracle DDL")
    s.add_argument("--sensitive", action="store_true", help="only the labelled columns")

    pol = sub.add_parser("policy", help="Show or export a policy")
    pol.add_argument("--out", default=None, help="write it to a JSON file")
    add_policy(pol)

    v = sub.add_parser("verify", help="Check a run's hash chain and manifest")
    v.add_argument("--run-dir", default="runs/latest")

    sub.add_parser("providers", help="What generates the SQL, and what it costs")

    args = p.parse_args(argv)

    try:
        return _dispatch(args)
    except (PolicyProblem, SqlUnparseable) as ex:
        print(f"{STOP} {ex}")
        return 2
    except FileNotFoundError as ex:
        print(f"{STOP} {ex.filename or ex} was not found.")
        return 2
    except json.JSONDecodeError as ex:
        print(f"{STOP} a JSON file could not be read: {ex.msg} at line {ex.lineno}.")
        return 2
    except ApprovalRefused as ex:
        print(f"{STOP} {ex}")
        return 1
    except BudgetExceeded as ex:
        print(f"{STOP} {ex}")
        return 1


def _dispatch(args) -> int:
    cmd = args.command

    if cmd in ("ask", "check"):
        pol = _policy(args)
        if cmd == "ask":
            provider = MockProvider(fault_rate=args.fault_rate)
            r = ask(args.question, pol, provider, sql=args.sql)
        else:
            r = review(args.question, args.sql, pol).to_dict()
            r["provider"] = "supplied"
        if args.json:
            print(json.dumps(r, indent=2))
        else:
            _print_review(r)
            if r["verdict"] == BLOCK:
                print("\n  This query does not run. There is no override flag.")
            elif r["verdict"] == APPROVE:
                print("\n  This query waits for a named person. See: cybwaysql gate --help")
        return 1 if (args.fail_on_block and r["verdict"] == BLOCK) else 0

    if cmd == "batch":
        pol = _policy(args)
        path = Path(args.file)
        if not path.exists():
            raise FileNotFoundError(str(path))
        questions = [q.strip() for q in path.read_text(encoding="utf-8").splitlines()
                     if q.strip() and not q.strip().startswith("#")]
        if not questions:
            print(f"{STOP} {path} has no questions in it.")
            return 2
        summary = run_batch(questions, args.out, pol,
                            MockProvider(fault_rate=args.fault_rate),
                            frozen=args.frozen, approver=args.approver)
        print(Path(args.out, "summary.txt").read_text(encoding="utf-8"))
        print(f"Run written to {args.out}")
        return 1 if (args.fail_on_block and summary["blocked"]) else 0

    if cmd == "bench":
        pol = _policy(args)
        provider = MockProvider(fault_rate=args.fault_rate, seed=7) if args.generated else None
        result = run_bench(args.out, pol, provider=provider, use_reference=not args.generated)
        if args.json:
            print(json.dumps({k: v for k, v in result.items() if k != "per_case"}, indent=2))
        else:
            for line in summary_lines(result):
                print(line)
            for c in result["per_case"]:
                if not c["correct"]:
                    print(f"  mismatch {c['case_id']}: expected {c['expected']}, "
                          f"got {c['actual']} ({c['failure']})")
        if args.curve:
            print("\nHow it behaves as the model degrades:")
            print(f"{'fault':>6} {'accuracy':>9} {'false blocks':>13} {'missed blocks':>14}")
            for row in fault_curve(pol):
                print(f"{row['fault_rate']:>6.2f} {row['guard_accuracy']:>9.3f} "
                      f"{row['false_block_rate']:>13.3f} {row['missed_block_rate']:>14.3f}")
            print("Missed blocks staying at zero as the model gets worse is the property "
                  "that matters: the harness fails closed.")
        if args.out:
            print(f"\nRun written to {args.out}")
        if args.min_accuracy is not None and result["guard_accuracy"] < args.min_accuracy:
            print(f"\nAccuracy {result['guard_accuracy']:.3f} is below the required "
                  f"{args.min_accuracy:.3f}.")
            return 1
        return 0

    if cmd == "gate":
        pol = _policy(args)
        r = review(args.question, args.sql, pol)
        gate = ApprovalGate()
        print(f"[{r.verdict}] {args.question or '(no question recorded)'}")
        for f in r.findings:
            print(f"  {f.verdict:7} {f.guard_id}  {f.detail}")
        if args.reject:
            d = gate.reject(r, args.approver, args.reason)
            print(f"\nRejected by {d.approver}: {d.reason}")
            print(f"Fingerprint {d.fingerprint[:16]}… covers the question, the SQL and the policy.")
            return 0
        if args.approve:
            d = gate.approve(r, args.approver, args.reason)
            print(f"\n{d.state} by {d.approver}"
                  + (f": {d.reason}" if d.reason else ""))
            print(f"Fingerprint {d.fingerprint[:16]}… covers the question, the SQL and the policy.")
            print("Edit any of the three and this approval no longer applies.")
            return 0
        print("\n" + explain_gate())
        print(f"\nThis query is: {'blocked, and cannot be approved' if r.verdict == BLOCK else r.verdict}")
        return 0

    if cmd == "explain":
        if not args.guard_id:
            print(f"{len(guards.GUARDS)} guards:\n")
            for fn in guards.GUARDS:
                print(f"  {fn.guard_id}  {fn.title}")
            print("\nAlso two gates, GATE-001 and GATE-002, which ask for a person rather "
                  "than refusing.")
            return 0
        wanted = args.guard_id.upper()
        for fn in guards.GUARDS:
            if fn.guard_id == wanted:
                print(f"{fn.guard_id}  {fn.title}")
                print(f"\n{(fn.__doc__ or '').strip() or 'See the source for the condition.'}")
                if fn.refs:
                    print(f"\nReferenced categories: {', '.join(fn.refs)}")
                return 0
        print(f"{STOP} no guard called {args.guard_id!r}. Run: cybwaysql explain")
        return 2

    if cmd == "schema":
        if args.ddl:
            print(schema.oracle_ddl())
        elif args.sensitive:
            print("Columns a policy can restrict, by label:\n")
            for t in schema.TABLES.values():
                labelled = [c for c in t.columns if c.sensitivity != schema.PUBLIC]
                if not labelled:
                    continue
                print(f"{t.name}  ({t.num_rows:,} rows)")
                for c in labelled:
                    note = f" - {c.note}" if c.note else ""
                    print(f"    {c.sensitivity:<10} {c.name}{note}")
                print()
        else:
            print(schema.schema_for_prompt())
        print("\nEvery table, column and row in this schema is invented.")
        return 0

    if cmd == "policy":
        pol = _policy(args)
        if args.out:
            pol.save(args.out)
            print(f"Policy {pol.name!r} written to {args.out}. Edit it and pass it with "
                  f"--policy-file.")
            return 0
        print(json.dumps(pol.to_dict(), indent=2))
        return 0

    if cmd == "verify":
        run_dir = Path(args.run_dir)
        if not (run_dir / "manifest.json").exists():
            print(f"{STOP} {run_dir} has no manifest.json. Run a batch or a bench first.")
            return 2
        i = integrity_of(run_dir)
        print(f"RUN {run_dir}")
        print(f"  Audit chain: {i['chain_msg']}")
        print(f"  Manifest:    {'matches every file' if i['manifest_ok'] else i['manifest_problems']}")
        print(f"  Manifest sha256: {i['manifest_sha256']}")
        ok = i["chain_ok"] and i["manifest_ok"]
        print("This run has not been altered since it was written." if ok
              else "This run has been altered since it was written.")
        return 0 if ok else 1

    if cmd == "providers":
        for k, v in describe_providers().items():
            print(f"  {k:<8} {v}")
        print("\nNo network client ships with this build. The live path exists so the "
              "harness is honest about what a live run would involve.")
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
