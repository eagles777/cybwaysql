"""A synthetic Oracle-style schema, its statistics, and its sensitivity labels.

Everything here is invented. The shape is deliberately ordinary — a case
management system with people, money and documents attached to it — because
that is the shape where a text-to-SQL mistake actually costs something.

Three things live on a column, and all three matter to a different guard:

  sensitivity   PUBLIC, INTERNAL, RESTRICTED or PII. A guard decides whether
                the column may appear in a select list at all.
  num_rows      declared table statistics. The cost guard uses them to estimate
                how much work a query is about to ask for. These are DECLARED
                numbers, not gathered ones: the estimate is arithmetic on them,
                and is never presented as an execution plan.
  indexed       whether a predicate on the column can avoid a full scan.

The schema is also materialised into SQLite so the evaluation harness can
actually run a golden query and compare result sets. SQLite is not Oracle, and
the module says so where it matters: the sample DDL is Oracle-flavoured for
reading, and a reduced form is what SQLite gets.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field

PUBLIC, INTERNAL, RESTRICTED, PII = "PUBLIC", "INTERNAL", "RESTRICTED", "PII"

SENSITIVITY_ORDER = {PUBLIC: 0, INTERNAL: 1, RESTRICTED: 2, PII: 3}


@dataclass(frozen=True)
class Column:
    name: str
    type: str
    sensitivity: str = INTERNAL
    indexed: bool = False
    nullable: bool = True
    note: str = ""


@dataclass(frozen=True)
class Table:
    name: str
    columns: tuple
    num_rows: int
    primary_key: str = ""
    note: str = ""

    def column(self, name: str):
        want = (name or "").upper()
        for c in self.columns:
            if c.name == want:
                return c
        return None

    @property
    def column_names(self) -> list:
        return [c.name for c in self.columns]

    def columns_at_or_above(self, level: str) -> list:
        floor = SENSITIVITY_ORDER[level]
        return [c.name for c in self.columns if SENSITIVITY_ORDER[c.sensitivity] >= floor]


# ---------------------------------------------------------------- the schema

TABLES = {t.name: t for t in [
    Table(
        name="CASE_HEADER", num_rows=4_200_000, primary_key="CASE_ID",
        note="One row per case. The table most questions start from.",
        columns=(
            Column("CASE_ID", "NUMBER(12)", PUBLIC, indexed=True, nullable=False),
            Column("CASE_NUMBER", "VARCHAR2(20)", INTERNAL, indexed=True, nullable=False),
            Column("FILER_ID", "NUMBER(12)", INTERNAL, indexed=True, nullable=False),
            Column("STATUS_CODE", "VARCHAR2(12)", PUBLIC, indexed=True),
            Column("OPENED_DATE", "DATE", PUBLIC, indexed=True),
            Column("CLOSED_DATE", "DATE", PUBLIC),
            Column("OFFICE_CODE", "VARCHAR2(8)", PUBLIC, indexed=True),
            Column("ASSESSED_AMOUNT", "NUMBER(14,2)", RESTRICTED,
                   note="A money figure attributable to one filer."),
            Column("EXAMINER_NOTES", "CLOB", RESTRICTED,
                   note="Free text. Anything at all can end up in here, which is why it is restricted."),
        )),
    Table(
        name="FILER", num_rows=1_800_000, primary_key="FILER_ID",
        note="The person or organisation a case is about.",
        columns=(
            Column("FILER_ID", "NUMBER(12)", PUBLIC, indexed=True, nullable=False),
            Column("FILER_TYPE", "VARCHAR2(1)", PUBLIC, indexed=True),
            Column("DISPLAY_NAME", "VARCHAR2(120)", PII, indexed=True),
            Column("TAX_ID", "VARCHAR2(11)", PII, indexed=True,
                   note="The single column most likely to end a career if it leaves the building."),
            Column("DATE_OF_BIRTH", "DATE", PII),
            Column("EMAIL", "VARCHAR2(120)", PII),
            Column("PHONE", "VARCHAR2(20)", PII),
            Column("ADDRESS_LINE1", "VARCHAR2(120)", PII),
            Column("ADDRESS_CITY", "VARCHAR2(60)", RESTRICTED),
            Column("ADDRESS_STATE", "VARCHAR2(2)", PUBLIC, indexed=True),
            Column("ADDRESS_ZIP", "VARCHAR2(10)", RESTRICTED, indexed=True),
            Column("REGISTERED_DATE", "DATE", PUBLIC),
        )),
    Table(
        name="PAYMENT_TXN", num_rows=96_000_000, primary_key="TXN_ID",
        note="The big one. A query that scans this without a predicate is the "
             "classic accident.",
        columns=(
            Column("TXN_ID", "NUMBER(16)", PUBLIC, indexed=True, nullable=False),
            Column("CASE_ID", "NUMBER(12)", INTERNAL, indexed=True),
            Column("FILER_ID", "NUMBER(12)", INTERNAL, indexed=True),
            Column("POSTED_DATE", "DATE", PUBLIC, indexed=True),
            Column("AMOUNT", "NUMBER(14,2)", RESTRICTED),
            Column("METHOD_CODE", "VARCHAR2(8)", PUBLIC, indexed=True),
            Column("ACCOUNT_LAST4", "VARCHAR2(4)", PII),
            Column("REVERSAL_FLAG", "CHAR(1)", PUBLIC),
        )),
    Table(
        name="CASE_DOCUMENT", num_rows=31_000_000, primary_key="DOC_ID",
        note="Documents attached to a case.",
        columns=(
            Column("DOC_ID", "NUMBER(14)", PUBLIC, indexed=True, nullable=False),
            Column("CASE_ID", "NUMBER(12)", INTERNAL, indexed=True),
            Column("DOC_TYPE", "VARCHAR2(16)", PUBLIC, indexed=True),
            Column("RECEIVED_DATE", "DATE", PUBLIC, indexed=True),
            Column("PAGE_COUNT", "NUMBER(6)", PUBLIC),
            Column("SCAN_TEXT", "CLOB", RESTRICTED,
                   note="OCR output. Treated as restricted because nobody has read all of it."),
        )),
    Table(
        name="OFFICE", num_rows=182, primary_key="OFFICE_CODE",
        note="A small reference table. Joining to it is cheap.",
        columns=(
            Column("OFFICE_CODE", "VARCHAR2(8)", PUBLIC, indexed=True, nullable=False),
            Column("OFFICE_NAME", "VARCHAR2(80)", PUBLIC),
            Column("REGION_CODE", "VARCHAR2(4)", PUBLIC, indexed=True),
        )),
    Table(
        name="EXAMINER", num_rows=9_400, primary_key="EXAMINER_ID",
        note="Staff. Their own details are PII too, which people forget.",
        columns=(
            Column("EXAMINER_ID", "NUMBER(8)", PUBLIC, indexed=True, nullable=False),
            Column("EXAMINER_NAME", "VARCHAR2(120)", PII),
            Column("OFFICE_CODE", "VARCHAR2(8)", PUBLIC, indexed=True),
            Column("HIRE_DATE", "DATE", RESTRICTED),
            Column("SALARY_BAND", "VARCHAR2(6)", RESTRICTED),
        )),
    Table(
        name="CASE_ASSIGNMENT", num_rows=6_100_000, primary_key="ASSIGNMENT_ID",
        note="Which examiner has which case.",
        columns=(
            Column("ASSIGNMENT_ID", "NUMBER(12)", PUBLIC, indexed=True, nullable=False),
            Column("CASE_ID", "NUMBER(12)", INTERNAL, indexed=True),
            Column("EXAMINER_ID", "NUMBER(8)", INTERNAL, indexed=True),
            Column("ASSIGNED_DATE", "DATE", PUBLIC, indexed=True),
            Column("RELEASED_DATE", "DATE", PUBLIC),
        )),
    Table(
        name="STATUS_REF", num_rows=24, primary_key="STATUS_CODE",
        note="Lookup table.",
        columns=(
            Column("STATUS_CODE", "VARCHAR2(12)", PUBLIC, indexed=True, nullable=False),
            Column("STATUS_LABEL", "VARCHAR2(40)", PUBLIC),
            Column("IS_TERMINAL", "CHAR(1)", PUBLIC),
        )),
]}

# Views a question might name. The analyser does not resolve a view to its base
# tables, so the policy has to know they exist and what they are made of.
VIEWS = {
    "V_OPEN_CASES": ("CASE_HEADER", "STATUS_REF"),
    "V_CASE_SUMMARY": ("CASE_HEADER", "FILER", "OFFICE"),
}


def table(name: str):
    return TABLES.get((name or "").upper())


def column(table_name: str, column_name: str):
    t = table(table_name)
    return t.column(column_name) if t else None


def sensitivity_of(table_name: str, column_name: str) -> str | None:
    c = column(table_name, column_name)
    return c.sensitivity if c else None


def all_columns_at_or_above(level: str) -> list:
    out = []
    for t in TABLES.values():
        for name in t.columns_at_or_above(level):
            out.append(f"{t.name}.{name}")
    return sorted(out)


def row_count(table_name: str) -> int | None:
    t = table(table_name)
    return t.num_rows if t else None


# ---------------------------------------------------------------- Oracle DDL

def oracle_ddl() -> str:
    """The schema as Oracle would declare it, for reading and for the prompt.

    This is what a model is shown. It carries the sensitivity label as a column
    comment, because telling the model which columns are off limits is cheaper
    than catching it afterwards — and the guards still catch it afterwards.
    """
    out = []
    for t in TABLES.values():
        out.append(f"-- {t.name}: {t.note}  (approx {t.num_rows:,} rows)")
        cols = []
        for c in t.columns:
            null = "" if c.nullable else " NOT NULL"
            cols.append(f"  {c.name:<16} {c.type:<14}{null}")
        out.append(f"CREATE TABLE {t.name} (\n" + ",\n".join(cols) + "\n);")
        if t.primary_key:
            out.append(f"ALTER TABLE {t.name} ADD CONSTRAINT PK_{t.name} "
                       f"PRIMARY KEY ({t.primary_key});")
        for c in t.columns:
            if c.sensitivity != PUBLIC:
                extra = f" {c.note}" if c.note else ""
                out.append(f"COMMENT ON COLUMN {t.name}.{c.name} IS "
                           f"'sensitivity={c.sensitivity}.{extra}';")
        out.append("")
    return "\n".join(out)


def schema_for_prompt(include_sensitivity: bool = True) -> str:
    """A compact schema description to put in front of a model."""
    lines = ["-- Oracle schema. Tables, columns and approximate row counts."]
    for t in TABLES.values():
        lines.append(f"{t.name} ({t.num_rows:,} rows) pk={t.primary_key}")
        for c in t.columns:
            label = f"  [{c.sensitivity}]" if include_sensitivity and c.sensitivity != PUBLIC else ""
            idx = " (indexed)" if c.indexed else ""
            lines.append(f"    {c.name} {c.type}{idx}{label}")
    lines.append("")
    lines.append("Joins: CASE_HEADER.FILER_ID = FILER.FILER_ID; "
                 "PAYMENT_TXN.CASE_ID = CASE_HEADER.CASE_ID; "
                 "CASE_DOCUMENT.CASE_ID = CASE_HEADER.CASE_ID; "
                 "CASE_ASSIGNMENT.CASE_ID = CASE_HEADER.CASE_ID; "
                 "CASE_ASSIGNMENT.EXAMINER_ID = EXAMINER.EXAMINER_ID; "
                 "CASE_HEADER.OFFICE_CODE = OFFICE.OFFICE_CODE; "
                 "CASE_HEADER.STATUS_CODE = STATUS_REF.STATUS_CODE")
    return "\n".join(lines)


# ---------------------------------------------------------------- sample rows

_SQLITE_TYPES = {"NUMBER": "NUMERIC", "VARCHAR2": "TEXT", "CHAR": "TEXT",
                 "DATE": "TEXT", "CLOB": "TEXT"}


def _sqlite_type(oracle_type: str) -> str:
    base = oracle_type.split("(")[0].upper()
    return _SQLITE_TYPES.get(base, "TEXT")


def build_sample_db(path: str = ":memory:") -> sqlite3.Connection:
    """A tiny, fully synthetic instance of the schema.

    Its only job is to let the evaluation harness execute a golden query and a
    candidate query and compare the rows. It is SQLite, not Oracle: it holds a
    few dozen invented rows and proves nothing about Oracle behaviour.
    """
    conn = sqlite3.connect(path)
    for t in TABLES.values():
        cols = ", ".join(f"{c.name} {_sqlite_type(c.type)}" for c in t.columns)
        conn.execute(f"CREATE TABLE {t.name} ({cols})")
    _seed(conn)
    conn.commit()
    return conn


def _seed(conn: sqlite3.Connection) -> None:
    offices = [("OFC-01", "SAMPLE North Office", "R1"),
               ("OFC-02", "SAMPLE South Office", "R1"),
               ("OFC-03", "SAMPLE Central Office", "R2")]
    conn.executemany("INSERT INTO OFFICE VALUES (?,?,?)", offices)

    statuses = [("OPEN", "Open", "N"), ("REVIEW", "Under review", "N"),
                ("CLOSED", "Closed", "Y"), ("APPEAL", "Under appeal", "N")]
    conn.executemany("INSERT INTO STATUS_REF VALUES (?,?,?)", statuses)

    filers = []
    for i in range(1, 13):
        filers.append((100 + i, "I" if i % 3 else "O", f"SAMPLE FILER {i:02d}",
                       f"000-00-{i:04d}", f"19{60 + i}-0{1 + i % 9}-1{i % 9}",
                       f"filer{i:02d}@example.com", f"555-0{100 + i}",
                       f"{i} Example Way", "SAMPLE CITY", ["VA", "MD", "DE"][i % 3],
                       f"2{i:04d}", f"20{10 + i % 9}-03-01"))
    conn.executemany("INSERT INTO FILER VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", filers)

    examiners = [(1, "SAMPLE EXAMINER A", "OFC-01", "2015-04-01", "B-04"),
                 (2, "SAMPLE EXAMINER B", "OFC-02", "2018-09-15", "B-03"),
                 (3, "SAMPLE EXAMINER C", "OFC-01", "2021-01-11", "B-02")]
    conn.executemany("INSERT INTO EXAMINER VALUES (?,?,?,?,?)", examiners)

    cases, txns, docs, assigns = [], [], [], []
    txn_id, doc_id = 5000, 9000
    for i in range(1, 21):
        case_id = 1000 + i
        status = statuses[i % 4][0]
        office = offices[i % 3][0]
        opened = f"2024-{1 + i % 12:02d}-1{i % 9}"
        closed = f"2025-0{1 + i % 8}-2{i % 8}" if status == "CLOSED" else None
        cases.append((case_id, f"CN-{case_id}", 100 + (i % 12) + 1, status, opened,
                      closed, office, round(1000 + i * 137.5, 2),
                      f"SAMPLE note for case {case_id}"))
        for k in range(1 + i % 3):
            txn_id += 1
            txns.append((txn_id, case_id, 100 + (i % 12) + 1,
                         f"2025-0{1 + k % 8}-1{k % 8}", round(50 + k * 25.25, 2),
                         ["ACH", "CHECK", "CARD"][k % 3], f"{1000 + k}"[-4:], "N"))
        doc_id += 1
        docs.append((doc_id, case_id, ["FORM", "LETTER", "NOTICE"][i % 3],
                     f"2025-0{1 + i % 8}-0{1 + i % 8}", 1 + i % 20,
                     f"SAMPLE scanned text {doc_id}"))
        assigns.append((2000 + i, case_id, 1 + i % 3, opened, closed))

    conn.executemany("INSERT INTO CASE_HEADER VALUES (?,?,?,?,?,?,?,?,?)", cases)
    conn.executemany("INSERT INTO PAYMENT_TXN VALUES (?,?,?,?,?,?,?,?)", txns)
    conn.executemany("INSERT INTO CASE_DOCUMENT VALUES (?,?,?,?,?,?)", docs)
    conn.executemany("INSERT INTO CASE_ASSIGNMENT VALUES (?,?,?,?,?)", assigns)
