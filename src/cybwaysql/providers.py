"""Where the SQL comes from, and what it is allowed to cost.

The default provider is a mock: deterministic, offline, free, and deliberately
imperfect. It is not a toy. A harness whose model never makes a mistake proves
nothing about the guards, so the mock reproduces the mistakes a real model
actually makes — a forgotten WHERE on a large table, a literal pasted in
instead of a bind, an extra identifier column nobody asked for, an occasional
cartesian join.

A live provider exists and is switched off. Reaching it takes an explicit
opt-in flag, an environment key, and a budget that is charged before the call
rather than counted after it. CI never has any of the three.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import re
from dataclasses import dataclass

from . import schema


class BudgetExceeded(RuntimeError):
    pass


class ProviderRefused(RuntimeError):
    """The live path was reached without the conditions that permit it."""


@dataclass
class BudgetCeiling:
    """Charged BEFORE a call. A ceiling counted afterwards is a report, not a control."""

    max_usd: float
    spent_usd: float = 0.0
    calls: int = 0

    def dry_run(self, estimated_cost_usd: float) -> dict:
        projected = self.spent_usd + estimated_cost_usd
        return {"estimated_cost_usd": estimated_cost_usd, "spent_usd": self.spent_usd,
                "projected_usd": projected, "ceiling_usd": self.max_usd,
                "would_exceed": projected > self.max_usd}

    def charge(self, estimated_cost_usd: float) -> None:
        if self.max_usd < 0:
            raise ValueError("a budget ceiling cannot be negative")
        if self.dry_run(estimated_cost_usd)["would_exceed"]:
            raise BudgetExceeded(
                f"a charge of ${estimated_cost_usd:.4f} would take spend to "
                f"${self.spent_usd + estimated_cost_usd:.4f}, past the ${self.max_usd:.2f} "
                f"ceiling. The call was not made.")
        self.spent_usd += estimated_cost_usd
        self.calls += 1


PROMPT_TEMPLATE = """You translate a question into one Oracle SELECT statement.

Rules:
- One SELECT. No DDL, no DML, no PL/SQL, no semicolons.
- Use :bind placeholders for every value. Never write a literal from the question.
- Name the columns you need. Never SELECT *.
- Do not select columns marked [PII] or [RESTRICTED].
- Join every table on a key.
- Add FETCH FIRST n ROWS ONLY unless the question asks for an aggregate.

{schema}

Question: {question}

Return only the SQL."""


def build_prompt(question: str) -> str:
    """What a model is shown. Only the schema and the question: no row data ever
    goes into a prompt, which is the whole point of a text-to-SQL boundary."""
    return PROMPT_TEMPLATE.format(schema=schema.schema_for_prompt(), question=question)


class MockProvider:
    """Deterministic, offline, and wrong in realistic ways.

    Seeded from the question text, so the same question always produces the same
    SQL and a benchmark is reproducible. `fault_rate` controls how often it
    makes each class of mistake; at 0.0 it writes the careful version every time.
    """

    name = "mock"
    cost_per_call_usd = 0.0

    def __init__(self, fault_rate: float = 0.35, seed: int = 0):
        self.fault_rate = fault_rate
        self.seed = seed

    def _rng(self, question: str) -> random.Random:
        digest = hashlib.sha256(f"{self.seed}:{question}".encode("utf-8")).hexdigest()
        return random.Random(int(digest[:16], 16))

    def generate(self, question: str, gold: str | None = None) -> str:
        """Produce SQL for a question.

        When a golden query is supplied the mock starts from it and injects
        faults, which is what makes the benchmark measure the guards rather than
        the mock's ability to write SQL from scratch.
        """
        rng = self._rng(question)
        sql = gold or _naive_sql(question)
        if self.fault_rate <= 0:
            return sql
        for fault in (_fault_drop_where, _fault_inline_literal, _fault_add_identifier,
                      _fault_select_star, _fault_drop_join, _fault_add_hint,
                      _fault_drop_limit):
            if rng.random() < self.fault_rate / 2:
                sql = fault(sql, question, rng)
        return sql


# ---------------------------------------------------------------- the faults

def _fault_drop_where(sql, question, rng):
    m = re.search(r"\bWHERE\b.*?(?=\bGROUP\b|\bORDER\b|\bFETCH\b|$)", sql, re.I | re.S)
    return sql[:m.start()] + sql[m.end():] if m else sql


def _fault_inline_literal(sql, question, rng):
    """Replace a bind with a value lifted from the question: the concatenation
    pattern, and the single most common real-world text-to-SQL flaw."""
    words = [w for w in re.findall(r"[A-Za-z0-9_]{3,}", question or "") if not w.isdigit()]
    if not words:
        return sql
    return re.sub(r":[A-Za-z0-9_]+", f"'{rng.choice(words)}'", sql, count=1)


def _fault_add_identifier(sql, question, rng):
    """Helpfully add a name or an identifier nobody asked for."""
    extra = rng.choice(["f.display_name", "f.tax_id", "f.email"])
    if "FILER" not in sql.upper() or extra.split(".")[1].upper() in sql.upper():
        return sql
    return re.sub(r"(?i)\bSELECT\b", f"SELECT {extra},", sql, count=1)


def _fault_select_star(sql, question, rng):
    m = re.search(r"(?is)\bSELECT\b(.*?)\bFROM\b", sql)
    if not m or "*" in m.group(1) or "COUNT" in m.group(1).upper():
        return sql
    return sql[:m.start(1)] + " * " + sql[m.end(1):]


def _fault_drop_join(sql, question, rng):
    return re.sub(r"(?i)\s+ON\s+[\w.]+\s*=\s*[\w.]+", "", sql, count=1)


def _fault_add_hint(sql, question, rng):
    return re.sub(r"(?i)\bSELECT\b", "SELECT /*+ PARALLEL(8) */", sql, count=1)


def _fault_drop_limit(sql, question, rng):
    return re.sub(r"(?i)\s*FETCH\s+FIRST\s+\d+\s+ROWS\s+ONLY", "", sql)


_KEYWORDS = [
    (("payment", "paid", "amount", "money"), "PAYMENT_TXN", "p"),
    (("document", "scan", "attachment"), "CASE_DOCUMENT", "d"),
    (("examiner", "staff", "assigned"), "EXAMINER", "e"),
    (("filer", "taxpayer", "person", "name"), "FILER", "f"),
    (("office", "region"), "OFFICE", "o"),
]


def _naive_sql(question: str) -> str:
    """A plausible query when no golden answer is supplied. Intentionally plain."""
    q = (question or "").lower()
    table, alias = "CASE_HEADER", "c"
    for words, t, al in _KEYWORDS:
        if any(w in q for w in words):
            table, alias = t, al
            break
    tbl = schema.table(table)
    cols = [c.name for c in tbl.columns if c.sensitivity == schema.PUBLIC][:3] or ["*"]
    select = ", ".join(f"{alias}.{c.lower()}" for c in cols)
    if any(w in q for w in ("how many", "count", "number of", "total")):
        select = "COUNT(*) AS n"
    date_col = next((c.name for c in tbl.columns if c.type == "DATE" and c.indexed), None)
    where = f"\n WHERE {alias}.{date_col.lower()} >= :from_date" if date_col else ""
    limit = "" if select.startswith("COUNT") else "\n FETCH FIRST 100 ROWS ONLY"
    return f"SELECT {select}\n  FROM {table.lower()} {alias}{where}{limit}"


# ---------------------------------------------------------------- live path

class LiveProvider:
    """A real model, behind three locks. Present so the harness is honest about
    what a live run would involve; not reachable by accident."""

    name = "live"

    def __init__(self, budget: BudgetCeiling, opt_in: bool = False,
                 env_var: str = "CYBWAYSQL_API_KEY", model: str = "",
                 transport=None, cost_per_call_usd: float = 0.002):
        if not opt_in:
            raise ProviderRefused(
                "the live provider requires an explicit opt-in. Nothing reaches a network "
                "in this project unless someone typed the flag that says so.")
        key = os.environ.get(env_var)
        if not key:
            raise ProviderRefused(
                f"no key in {env_var}. The key is read from the environment and is never "
                f"stored in this repo, in a config file, or in a log line.")
        if budget is None or budget.max_usd <= 0:
            raise ProviderRefused("a live provider requires a budget ceiling above zero.")
        self.budget = budget
        self.model = model or os.environ.get("CYBWAYSQL_MODEL", "")
        self._transport = transport          # injected, so tests stay offline
        self.cost_per_call_usd = cost_per_call_usd
        self._key_present = True             # the key itself is never held on the object

    def generate(self, question: str, gold: str | None = None) -> str:
        self.budget.charge(self.cost_per_call_usd)     # charged BEFORE the call
        if self._transport is None:
            raise ProviderRefused(
                "no transport is configured. This build ships no network client: wire one "
                "in deliberately, having read what it sends.")
        return _extract_sql(self._transport(build_prompt(question)))


def _extract_sql(text: str) -> str:
    """Take the SQL out of a model's answer, whatever wrapping it used."""
    if not text:
        return ""
    fenced = re.search(r"```(?:sql)?\s*(.+?)```", text, re.S | re.I)
    body = fenced.group(1) if fenced else text
    return body.strip().rstrip(";").strip()


def describe_providers() -> dict:
    return {
        "default": "mock",
        "mock": "deterministic, offline, $0, deliberately imperfect",
        "live": "opt-in flag + environment key + budget charged before the call; "
                "no transport ships with this build",
    }
