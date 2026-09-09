"""The approval gate: the point where a person, not a program, decides.

Three things this module refuses to do, and each one is deliberate.

It will not approve a BLOCK. A blocked query is not a query awaiting a
signature; it is a query the policy does not permit. There is no override flag,
no force option, and no environment variable that changes that. If a block is
wrong, the policy is wrong, and a policy is changed in a reviewed commit.

It will not accept an empty approver. An approval that names nobody is a log
line, not accountability.

It will not execute anything. Approval marks a decision. What a caller does
with an approved query afterwards is outside this project, which has no
database driver in it at all.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from .guards import ALLOW, APPROVE, BLOCK, WARN, Review

PENDING, APPROVED, REJECTED, AUTO = "PENDING", "APPROVED", "REJECTED", "AUTO"


class ApprovalRefused(RuntimeError):
    """The gate would not record this decision, and says why."""


def fingerprint(question: str, sql: str, policy_name: str) -> str:
    """Identifies exactly what was approved.

    An approval that does not name the text it applies to is worthless: the
    query can be edited afterwards and the approval still points at it. This
    hash is over the question, the SQL and the policy together.
    """
    canonical = f"{(question or '').strip()}\x00{(sql or '').strip()}\x00{policy_name}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class Decision:
    fingerprint: str
    state: str
    approver: str = ""
    reason: str = ""
    timestamp: str = ""
    verdict: str = ""
    question: str = ""
    sql: str = ""
    policy: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class ApprovalGate:
    """Holds decisions for this run and writes each one to the audit log."""

    def __init__(self, log=None):
        self.log = log
        self.decisions: dict = {}

    # ---- reading ----

    def state_of(self, review: Review) -> str:
        fp = fingerprint(review.question, review.sql, review.policy)
        d = self.decisions.get(fp)
        return d.state if d else PENDING

    def is_cleared(self, review: Review) -> bool:
        """May this query proceed? BLOCK is never cleared, by anyone."""
        if review.verdict == BLOCK:
            return False
        if review.verdict in (ALLOW, WARN):
            return True
        return self.state_of(review) == APPROVED

    # ---- writing ----

    def _record(self, review: Review, state: str, approver: str, reason: str,
                timestamp: str | None = None) -> Decision:
        d = Decision(
            fingerprint=fingerprint(review.question, review.sql, review.policy),
            state=state, approver=approver.strip(), reason=reason.strip(),
            timestamp=timestamp or datetime.now(timezone.utc).isoformat(timespec="seconds"),
            verdict=review.verdict, question=review.question, sql=review.sql,
            policy=review.policy)
        self.decisions[d.fingerprint] = d
        if self.log is not None:
            self.log.append(f"gate_{state.lower()}", d.to_dict(), timestamp=d.timestamp)
        return d

    def approve(self, review: Review, approver: str, reason: str = "",
                timestamp: str | None = None) -> Decision:
        if review.verdict == BLOCK:
            blocking = [f.guard_id for f in review.findings if f.verdict == BLOCK]
            raise ApprovalRefused(
                f"this query is blocked by {', '.join(blocking)} and cannot be approved. "
                f"There is no override. If the block is wrong, change the policy in a "
                f"reviewed commit and run the query again.")
        if not approver or not approver.strip():
            raise ApprovalRefused(
                "an approval needs a named person. An unnamed approval is a log line, "
                "not accountability.")
        if review.verdict in (ALLOW, WARN):
            return self._record(review, AUTO, approver, reason or
                                "no guard required a decision; recorded for the trail",
                                timestamp)
        return self._record(review, APPROVED, approver, reason, timestamp)

    def reject(self, review: Review, approver: str, reason: str,
               timestamp: str | None = None) -> Decision:
        if not approver or not approver.strip():
            raise ApprovalRefused("a rejection needs a named person too.")
        if not reason or not reason.strip():
            raise ApprovalRefused(
                "a rejection needs a reason. The next person to ask this question should "
                "learn something from the record.")
        return self._record(review, REJECTED, approver, reason, timestamp)

    # ---- reporting ----

    def pending(self) -> list:
        return [d for d in self.decisions.values() if d.state == PENDING]

    def summary(self) -> dict:
        counts: dict = {}
        for d in self.decisions.values():
            counts[d.state] = counts.get(d.state, 0) + 1
        return {"decisions": len(self.decisions), "by_state": counts,
                "approvers": sorted({d.approver for d in self.decisions.values() if d.approver})}


def explain_gate() -> str:
    return (
        "A query that no guard objected to runs, and the decision is still recorded. "
        "A query that needs a person waits for one, and the approval names them and the "
        "exact text they approved. A blocked query does not run at all, and no signature "
        "changes that. Nothing in this project executes SQL: approval is a decision, not "
        "an action.")
