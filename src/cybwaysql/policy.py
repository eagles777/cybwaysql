"""The policy: what this caller is allowed to ask the database for.

A policy is data, not code, so it can be reviewed by someone who does not read
Python and diffed in a pull request like any other control. It is the thing a
guard measures a query against, and it is deliberately explicit: nothing is
permitted by omission.

Two policies ship. `READ_ONLY_ANALYST` is the one to copy: a person asking
questions of a reporting replica, allowed to see aggregate money but no
personal identifiers. `STRICT_PUBLIC` is the floor, for anything facing an
audience you do not control.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import schema
from .schema import INTERNAL, PII, PUBLIC, RESTRICTED, SENSITIVITY_ORDER

# Oracle packages that reach outside the database or run arbitrary text. A
# generated query has no business calling any of them; the list is here so the
# guard can name the one it found rather than saying "a dangerous function".
DANGEROUS_PACKAGES = {
    "DBMS_SQL": "builds and runs SQL at runtime, which defeats static review",
    "DBMS_XMLGEN": "can run a nested query supplied as a string",
    "DBMS_SCHEDULER": "creates jobs that run after the session ends",
    "DBMS_JOB": "creates jobs that run after the session ends",
    "DBMS_LOB": "reads and writes large objects, including from files",
    "DBMS_OUTPUT": "harmless in itself, but a sign the text is a PL/SQL block",
    "DBMS_CRYPTO": "not needed by a reporting query",
    "DBMS_AQ": "queues messages to other systems",
    "DBMS_PIPE": "sends data between sessions outside the audit trail",
    "DBMS_ADVISOR": "not needed by a reporting query",
    "UTL_FILE": "reads and writes files on the database server",
    "UTL_HTTP": "makes network calls from the database server",
    "UTL_TCP": "opens raw sockets from the database server",
    "UTL_SMTP": "sends mail from the database server",
    "UTL_INADDR": "resolves hostnames, a classic exfiltration channel",
    "UTL_URL": "used with UTL_HTTP to assemble a destination",
    "HTTPURITYPE": "fetches a URL from inside a query",
    "DBMS_LDAP": "makes directory calls from the database server",
}

# Functions that are fine in a reporting query.
SAFE_FUNCTION_PREFIXES = (
    "COUNT", "SUM", "AVG", "MIN", "MAX", "ROUND", "TRUNC", "NVL", "NVL2", "COALESCE",
    "DECODE", "CASE", "TO_CHAR", "TO_DATE", "TO_NUMBER", "SUBSTR", "INSTR", "LENGTH",
    "UPPER", "LOWER", "TRIM", "LTRIM", "RTRIM", "REPLACE", "LPAD", "RPAD", "ABS",
    "GREATEST", "LEAST", "EXTRACT", "MONTHS_BETWEEN", "ADD_MONTHS", "LAST_DAY",
    "ROW_NUMBER", "RANK", "DENSE_RANK", "LAG", "LEAD", "LISTAGG", "STDDEV", "VARIANCE",
    "CAST", "SIGN", "MOD", "FLOOR", "CEIL", "REGEXP_LIKE", "REGEXP_SUBSTR",
)


@dataclass
class Policy:
    """What may be asked, of what, and how much of it."""

    name: str
    description: str = ""

    # --- what kind of statement
    read_only: bool = True
    allow_plsql: bool = False
    allow_set_operators: bool = True

    # --- what objects
    allowed_tables: tuple = ()            # empty means every table in the schema
    denied_tables: tuple = ()
    allow_database_links: bool = False
    allow_unknown_objects: bool = False   # an object the schema has never heard of

    # --- what columns
    max_sensitivity: str = RESTRICTED     # the highest label allowed in a select list
    denied_columns: tuple = ()            # TABLE.COLUMN, always blocked
    allow_select_star: bool = False

    # --- how much work
    max_estimated_rows: int = 5_000_000
    require_row_limit_above_rows: int = 1_000_000
    require_where_above_rows: int = 1_000_000
    max_tables_joined: int = 6
    allow_cartesian: bool = False

    # --- how it is written
    require_bind_variables: bool = True   # values compared to columns must be bound
    allow_hints: bool = False
    max_subquery_depth: int = 4

    # --- what needs a person
    # Set below the block ceiling but well above ordinary reporting work. A gate
    # that fires on every query is not a gate, it is a queue, and people learn to
    # click through it.
    approval_required_above_rows: int = 2_000_000
    approval_required_for_sensitivity: str = RESTRICTED

    def allows_table(self, name: str) -> bool:
        n = (name or "").upper()
        if n in {t.upper() for t in self.denied_tables}:
            return False
        if self.allowed_tables:
            return n in {t.upper() for t in self.allowed_tables}
        return True

    def allows_sensitivity(self, level: str) -> bool:
        return SENSITIVITY_ORDER.get(level, 9) <= SENSITIVITY_ORDER[self.max_sensitivity]

    def denies_column(self, table_name: str, column_name: str) -> bool:
        key = f"{(table_name or '').upper()}.{(column_name or '').upper()}"
        return key in {c.upper() for c in self.denied_columns}

    def needs_approval_for(self, level: str) -> bool:
        return SENSITIVITY_ORDER.get(level, 0) >= SENSITIVITY_ORDER[self.approval_required_for_sensitivity]

    def to_dict(self) -> dict:
        return asdict(self)

    def save(self, path: str | Path) -> Path:
        p = Path(path)
        p.write_text(json.dumps(self.to_dict(), indent=2) + "\n", encoding="utf-8")
        return p


class PolicyProblem(ValueError):
    """The policy file could not be read. Names the field."""


def from_dict(data: dict) -> Policy:
    if not isinstance(data, dict):
        raise PolicyProblem("a policy should be a JSON object")
    known = {f for f in Policy.__dataclass_fields__}
    unknown = sorted(set(data) - known)
    if unknown:
        raise PolicyProblem(f"a policy has no field named {unknown[0]!r}. "
                            f"Known fields: {', '.join(sorted(known))}")
    if "name" not in data:
        raise PolicyProblem('a policy needs a "name"')
    for level_field in ("max_sensitivity", "approval_required_for_sensitivity"):
        level = data.get(level_field)
        if level is not None and level not in SENSITIVITY_ORDER:
            raise PolicyProblem(f"{level_field} {level!r} is not one of "
                                f"{', '.join(SENSITIVITY_ORDER)}")
    for tuple_field in ("allowed_tables", "denied_tables", "denied_columns"):
        if tuple_field in data:
            value = data[tuple_field]
            if not isinstance(value, (list, tuple)):
                raise PolicyProblem(f"{tuple_field} should be a list of names")
            data[tuple_field] = tuple(str(v).upper() for v in value)
    return Policy(**data)


def load(path: str | Path) -> Policy:
    p = Path(path)
    if not p.exists():
        raise PolicyProblem(f"no policy file at {p}")
    try:
        return from_dict(json.loads(p.read_text(encoding="utf-8")))
    except json.JSONDecodeError as e:
        raise PolicyProblem(f"{p} is not valid JSON: line {e.lineno}, {e.msg}") from e


# ---------------------------------------------------------------- shipped policies

READ_ONLY_ANALYST = Policy(
    name="read-only-analyst",
    description=("A person asking questions of a reporting replica. May read case and "
                 "payment data in aggregate, may not read personal identifiers, and may "
                 "not ask for more work than a replica can absorb."),
    read_only=True,
    denied_tables=(),
    max_sensitivity=RESTRICTED,
    denied_columns=tuple(schema.all_columns_at_or_above(PII)),
    allow_select_star=False,
    max_estimated_rows=5_000_000,
    require_row_limit_above_rows=1_000_000,
    require_where_above_rows=1_000_000,
    max_tables_joined=6,
    require_bind_variables=True,
    allow_hints=False,
    approval_required_above_rows=2_000_000,
    approval_required_for_sensitivity=RESTRICTED,
)

STRICT_PUBLIC = Policy(
    name="strict-public",
    description=("The floor, for anything facing an audience you do not control. "
                 "Public columns only, small result sets, no free-text columns."),
    read_only=True,
    allowed_tables=("CASE_HEADER", "OFFICE", "STATUS_REF"),
    max_sensitivity=PUBLIC,
    denied_columns=tuple(schema.all_columns_at_or_above(RESTRICTED)),
    allow_select_star=False,
    allow_set_operators=False,
    max_estimated_rows=100_000,
    require_row_limit_above_rows=10_000,
    require_where_above_rows=10_000,
    max_tables_joined=3,
    require_bind_variables=True,
    allow_hints=False,
    max_subquery_depth=2,
    approval_required_above_rows=10_000,
    approval_required_for_sensitivity=INTERNAL,
)

POLICIES = {p.name: p for p in (READ_ONLY_ANALYST, STRICT_PUBLIC)}


def named(name: str) -> Policy:
    p = POLICIES.get((name or "").strip().lower())
    if p is None:
        raise PolicyProblem(f"no shipped policy called {name!r}. "
                            f"Try one of: {', '.join(POLICIES)}")
    return p
