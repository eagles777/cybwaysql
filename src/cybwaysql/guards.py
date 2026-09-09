"""The guards: GUARD-001 to GUARD-020, one function each.

Each takes (analysis, policy, question) and returns zero or more Findings. A
finding carries the evidence that produced it, so a reviewer can disagree with
the tool by reading the query rather than by trusting the tool.

The verdict is the worst finding:

  BLOCK    the query does not run. Nothing overrides this in code.
  APPROVE  a person must say yes, in writing, before it runs.
  WARN     it may run; someone should know.
  ALLOW    nothing fired.

Two habits, stated once and applied everywhere. A PASS means "no guard fired
against the policy you supplied", never "this query is safe". And anything the
analyser could not parse is BLOCKed by GUARD-001 before any other guard gets a
chance to have an opinion about it.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

from . import schema
from .oraclesql import Analysis, SqlUnparseable, WRITE_KINDS
from .policy import DANGEROUS_PACKAGES, Policy, SAFE_FUNCTION_PREFIXES
from .schema import PII, PUBLIC, RESTRICTED, SENSITIVITY_ORDER

BLOCK, APPROVE, WARN, ALLOW = "BLOCK", "APPROVE", "WARN", "ALLOW"
VERDICT_ORDER = {BLOCK: 0, APPROVE: 1, WARN: 2, ALLOW: 3}


@dataclass
class Finding:
    guard_id: str
    title: str
    verdict: str
    detail: str                                  # what is true about this query
    evidence: list = field(default_factory=list)
    remedy: str = ""                             # how to ask for the same thing safely
    refs: list = field(default_factory=list)     # published category names

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def sort_key(self):
        return (VERDICT_ORDER.get(self.verdict, 9), self.guard_id)


GUARDS: list = []


def guard(guard_id: str, title: str, refs=()):
    def wrap(fn):
        fn.guard_id, fn.title, fn.refs = guard_id, title, list(refs)
        GUARDS.append(fn)
        return fn
    return wrap


def _f(fn, verdict: str, detail: str, evidence=None, remedy: str = "") -> Finding:
    return Finding(fn.guard_id, fn.title, verdict, detail,
                   list(evidence or []), remedy, list(fn.refs))


# ---------------------------------------------------------------- shape

@guard("GUARD-001", "Statement parses and is a single statement",
       refs=["OWASP SQL Injection"])
def g001_parses(a, p, q):
    """Text that will not tokenise, or that carries more than one statement, is
    refused before any other guard forms an opinion. A stacked query is the
    classic shape: the first statement passes review and the second one runs."""
    out = []
    if a.statements > 1:
        out.append(_f(g001_parses, BLOCK,
                      f"The text contains {a.statements} statements. Only the first would be "
                      f"reviewed, and the rest would run unreviewed.",
                      [f"terminators found: {a.statements - 1}"],
                      "Ask for one question at a time. A generated answer should never "
                      "need a semicolon in the middle."))
    if a.notes:
        for n in a.notes:
            if "could not be determined" in n:
                out.append(_f(g001_parses, BLOCK,
                              "The leading keyword does not identify a statement Cybwaysql "
                              "recognises, so no other guard can be trusted about it.",
                              [n],
                              "Rewrite the request so the model produces a plain SELECT."))
    return out


@guard("GUARD-002", "Read-only enforcement", refs=["OWASP LLM06 Excessive Agency"])
def g002_read_only(a, p, q):
    """Under a read-only policy a SELECT is the only statement kind allowed. A
    write, a DDL, a GRANT or a COMMIT is refused on what it is, not on what it
    touches."""
    if not p.read_only:
        return []
    if a.kind in WRITE_KINDS:
        return [_f(g002_read_only, BLOCK,
                   f"This is a {a.kind}. The policy {p.name!r} permits reads only.",
                   [f"statement kind: {a.kind}", f"objects: {', '.join(a.table_names) or 'none'}"],
                   "A question that needs data changed is not a question for this path. "
                   "Route it through the normal change process.")]
    if a.kind in ("DDL", "DCL"):
        return [_f(g002_read_only, BLOCK,
                   f"This is {a.kind}: it changes the shape of the database or who can "
                   f"reach it, not the data it returns.",
                   [f"statement kind: {a.kind}"],
                   "No generated statement should ever carry DDL or GRANT.")]
    if a.kind == "TCL":
        return [_f(g002_read_only, BLOCK,
                   "This is transaction or session control, not a query.",
                   [f"statement kind: {a.kind}"], "Remove it.")]
    return []


@guard("GUARD-003", "No PL/SQL block", refs=["OWASP LLM05 Improper Output Handling"])
def g003_plsql(a, p, q):
    """A PL/SQL block can loop, branch and call packages. Reviewing one statically
    is a different and much larger problem than reviewing a query, so this
    project does not pretend to."""
    if p.allow_plsql or a.kind != "PLSQL":
        return []
    return [_f(g003_plsql, BLOCK,
               "This is a PL/SQL block, not a query. A block can loop, branch and call "
               "packages, and static review of one is a different and larger problem.",
               [f"statement kind: {a.kind}"] + [f"calls: {f}" for f in a.functions[:4]],
               "Ask for a single SELECT.")]


@guard("GUARD-004", "For-update locking", refs=[])
def g004_for_update(a, p, q):
    """FOR UPDATE takes row locks and holds them until the session ends. A
    reporting query that locks rows will eventually block a real one."""
    if not (p.read_only and a.for_update):
        return []
    return [_f(g004_for_update, BLOCK,
               "The query ends in FOR UPDATE, which takes row locks and holds them until "
               "the session commits or disconnects. A reporting query has no business "
               "locking rows.",
               ["FOR UPDATE present"], "Drop the FOR UPDATE clause.")]


# ---------------------------------------------------------------- objects

@guard("GUARD-005", "Objects are known to the schema", refs=[])
def g005_known_objects(a, p, q):
    """An object the schema has never heard of cannot be checked: its size and its
    sensitivity are both unknown. A model that invents a table has usually
    misread the question, so this refuses rather than guesses."""
    out = []
    for t in a.tables:
        if schema.table(t.name) or t.name in schema.VIEWS:
            continue
        if p.allow_unknown_objects:
            out.append(_f(g005_known_objects, WARN,
                          f"{t.qualified} is not in the schema Cybwaysql was given, so no "
                          f"column, sensitivity or size check applies to it.",
                          [f"unknown object: {t.qualified}"],
                          "Add the object to the schema so it can be checked."))
        else:
            out.append(_f(g005_known_objects, BLOCK,
                          f"{t.qualified} is not in the schema. Cybwaysql will not pass a "
                          f"query against an object it knows nothing about: it cannot tell "
                          f"whether the object holds identifiers or a billion rows.",
                          [f"unknown object: {t.qualified}",
                           f"known: {', '.join(sorted(schema.TABLES)[:6])}, …"],
                          "Check the table name. A model that invents a table usually "
                          "misread the question."))
    return out


@guard("GUARD-006", "Table allowlist", refs=["NIST SP 800-53 AC-3"])
def g006_allowlist(a, p, q):
    """The policy says which tables this caller may read. Adding one is a reviewed
    change to a JSON document, not a decision taken at run time."""
    out = []
    for t in a.tables:
        if not p.allows_table(t.name):
            reason = ("it is not on this policy's allowlist" if p.allowed_tables
                      else "it is on this policy's deny list")
            out.append(_f(g006_allowlist, BLOCK,
                          f"{t.name} may not be read under policy {p.name!r}: {reason}.",
                          [f"allowed: {', '.join(p.allowed_tables) or 'all except denied'}",
                           f"denied: {', '.join(p.denied_tables) or 'none'}"],
                          "If this table genuinely belongs in scope, add it to the policy "
                          "in a reviewed change, not at run time."))
    return out


@guard("GUARD-007", "No database links", refs=["OWASP LLM02 Sensitive Information Disclosure"])
def g007_db_links(a, p, q):
    """A database link reaches an instance where this policy does not apply, and
    the rows leave the instance that was reviewed."""
    if p.allow_database_links or not a.db_links:
        return []
    return [_f(g007_db_links, BLOCK,
               f"The query reaches another database over link {', '.join(sorted(set(a.db_links)))}. "
               f"Whatever policy applies here does not apply there, and the rows leave this "
               f"instance entirely.",
               [f"{t.qualified}" for t in a.tables if t.db_link],
               "Ask the question against local objects.")]


@guard("GUARD-008", "No dangerous package calls",
       refs=["OWASP LLM06 Excessive Agency", "OWASP SQL Injection"])
def g008_packages(a, p, q):
    """Oracle's supplied packages can run text as SQL, read files, open sockets and
    send mail. A reporting query needs none of them; if the answer seems to
    require one, the question is wrong."""
    out = []
    for call in a.functions:
        pkg = call.split(".")[0].upper()
        if pkg in DANGEROUS_PACKAGES:
            out.append(_f(g008_packages, BLOCK,
                          f"The query calls {call}. {DANGEROUS_PACKAGES[pkg]}.",
                          [f"call: {call}"],
                          "A reporting query needs none of these. If the answer seems to "
                          "require one, the question is wrong."))
    return out


@guard("GUARD-009", "Only recognised functions", refs=[])
def g009_unknown_functions(a, p, q):
    """A call that is not on the list of functions reporting queries normally need
    is worth a look before approval: a user-defined function reads whatever its
    definer can read."""
    unknown = []
    for call in a.functions:
        head = call.split(".")[0].upper()
        if head in DANGEROUS_PACKAGES:
            continue                                  # GUARD-008 owns those
        if "." in call or not head.startswith(SAFE_FUNCTION_PREFIXES):
            unknown.append(call)
    if not unknown:
        return []
    return [_f(g009_unknown_functions, WARN,
               f"The query calls {', '.join(sorted(set(unknown))[:4])}, which is not on the "
               f"list of functions a reporting query normally needs.",
               [f"call: {c}" for c in sorted(set(unknown))[:6]],
               "Check what the call does before approving. A user-defined function can "
               "read anything the definer can read.")]


# ---------------------------------------------------------------- columns

def _selected_columns(a: Analysis) -> list:
    """(table, column) pairs the query returns or filters on, best effort."""
    return list(a.columns)


@guard("GUARD-010", "No SELECT *", refs=[])
def g010_select_star(a, p, q):
    """A star hides which columns come back, so no column-level rule can apply to
    it. The finding names how many restricted columns the star would have
    included, which is usually the argument that ends the discussion."""
    if p.allow_select_star or not a.selects_star:
        return []
    exposed = []
    for t in a.tables:
        tbl = schema.table(t.name)
        if tbl:
            exposed += [f"{tbl.name}.{c}" for c in tbl.columns_at_or_above(RESTRICTED)]
    detail = ("A * hides which columns come back, so no column-level rule can be applied "
              "to it.")
    if exposed:
        detail += (f" On these tables a * would include {len(exposed)} restricted or "
                   f"personal columns.")
    return [_f(g010_select_star, BLOCK, detail,
               [f"would include: {', '.join(exposed[:6])}"] if exposed else ["select list: *"],
               "Name the columns. It is also the difference between a query that survives "
               "the next schema change and one that does not.")]


@guard("GUARD-011", "Sensitive columns are not returned",
       refs=["OWASP LLM02 Sensitive Information Disclosure", "NIST SP 800-122"])
def g011_sensitive(a, p, q):
    """The column-level control. Every column carries a sensitivity label, and the
    policy sets a ceiling and a deny list. Identifiers are refused; restricted
    columns are returned only after a named person decides."""
    out = []
    for tbl_name, col_name in _selected_columns(a):
        col = schema.column(tbl_name, col_name)
        if col is None:
            continue
        if p.denies_column(tbl_name, col_name):
            out.append(_f(g011_sensitive, BLOCK,
                          f"{tbl_name}.{col_name} is on this policy's denied list "
                          f"(sensitivity {col.sensitivity}).",
                          [f"{tbl_name}.{col_name} — {col.note or col.type}"],
                          "Ask for the aggregate, or for a surrogate key, rather than the "
                          "identifier itself."))
        elif not p.allows_sensitivity(col.sensitivity):
            out.append(_f(g011_sensitive, BLOCK,
                          f"{tbl_name}.{col_name} is labelled {col.sensitivity} and this "
                          f"policy allows at most {p.max_sensitivity}.",
                          [f"{tbl_name}.{col_name} — {col.note or col.type}"],
                          "Reduce what you ask for, or ask under a policy that permits it "
                          "and records who approved."))
    return out


@guard("GUARD-012", "Ambiguous columns in a multi-table query", refs=[])
def g012_ambiguous(a, p, q):
    """In a multi-table query an unqualified column cannot be attributed to a table.
    Where one of the candidates is sensitive the tool refuses rather than
    guessing in that direction."""
    if len(a.tables) < 2 or not a.unqualified_columns:
        return []
    risky = []
    for col_name in a.unqualified_columns:
        for t in a.tables:
            col = schema.column(t.name, col_name)
            if col and SENSITIVITY_ORDER[col.sensitivity] >= SENSITIVITY_ORDER[RESTRICTED]:
                risky.append(f"{t.name}.{col_name} ({col.sensitivity})")
    verdict = BLOCK if risky else WARN
    detail = (f"{len(a.unqualified_columns)} column reference(s) are not qualified by a "
              f"table or alias, across {len(a.tables)} tables, so Cybwaysql cannot say "
              f"which table they come from.")
    if risky:
        detail += (" At least one of them matches a restricted or personal column, and the "
                   "tool will not guess in that direction.")
    return [_f(g012_ambiguous, verdict, detail,
               [f"unqualified: {', '.join(a.unqualified_columns[:8])}"] +
               ([f"could be: {', '.join(risky[:4])}"] if risky else []),
               "Qualify every column with its table alias. It is also how the query "
               "survives a column being added to the other table.")]


# ---------------------------------------------------------------- cost

def _joined_tables(a: Analysis) -> set:
    """Tables that appear on both sides of a join predicate, in an ON clause or
    in the WHERE. A table reached through a key is not a table being scanned."""
    if len(a.tables) < 2 or a.join_conditions == 0:
        return set()
    aliases = a.alias_map()
    text = f"{a.sql}".upper()
    joined = set()
    for m in re.finditer(r"([A-Z_][A-Z0-9_$#]*)\s*\.\s*[A-Z_][A-Z0-9_$#]*\s*=\s*"
                         r"([A-Z_][A-Z0-9_$#]*)\s*\.\s*[A-Z_][A-Z0-9_$#]*", text):
        left = aliases.get(m.group(1), m.group(1))
        right = aliases.get(m.group(2), m.group(2))
        if left != right:
            joined.add(left)
            joined.add(right)
    return joined


def estimate_rows(a: Analysis) -> dict:
    """An estimate of ROWS EXAMINED, from declared statistics and the predicates
    in the text. Not rows returned: an aggregate examines many and returns one.

    This is arithmetic, not an execution plan. It exists so a guard can refuse
    something obviously enormous, and every message that carries a number says
    where the number came from.
    """
    if not a.tables:
        return {"rows": 0, "basis": "no tables referenced", "driving_table": None,
                "full_scans": [], "known": True}
    known, unknown = [], []
    for t in a.tables:
        n = schema.row_count(t.name)
        (known if n is not None else unknown).append((t.name, n))
    if not known:
        return {"rows": None, "basis": "no statistics for any object referenced",
                "driving_table": None, "full_scans": [], "known": False}

    driving, base = max(known, key=lambda kv: kv[1])
    rows = base
    basis = [f"{driving} has approximately {base:,} declared rows"]

    # A predicate on an indexed column is assumed to cut the set hard; an
    # unindexed one, gently. These are stated assumptions, not measurements.
    indexed_hits, plain_hits, full_scans = 0, 0, []
    where = (a.where_text or "").upper()
    # A table joined to another on a key is reached through that join, not read
    # end to end, so it is not a full-scan candidate even with no predicate of
    # its own. Without this, every lookup table in a correct query looks like an
    # accident.
    joined = _joined_tables(a)
    for tname, _ in known:
        tbl = schema.table(tname)
        if not tbl:
            continue
        hit = False
        for c in tbl.columns:
            if re.search(rf"\b{re.escape(c.name)}\b", where):
                hit = True
                if c.indexed:
                    indexed_hits += 1
                else:
                    plain_hits += 1
        if not hit and tname not in joined and (schema.row_count(tname) or 0) > 1_000_000:
            full_scans.append(tname)

    if indexed_hits:
        rows = max(1, int(rows / (100 ** min(indexed_hits, 2))))
        basis.append(f"{indexed_hits} predicate(s) on indexed columns, assumed highly selective")
    if plain_hits:
        rows = max(1, int(rows / (4 ** min(plain_hits, 3))))
        basis.append(f"{plain_hits} predicate(s) on unindexed columns, assumed weakly selective")
    if not a.has_where:
        basis.append("no WHERE clause, so the whole table is in scope")

    # Every additional table beyond the driving one multiplies, unless joined.
    extra = len(known) - 1
    if extra > 0:
        joined = min(a.join_conditions, extra)
        unjoined = extra - joined
        if unjoined > 0:
            second = sorted((n for _, n in known), reverse=True)[1]
            rows *= max(second, 1)
            basis.append(f"{unjoined} table(s) not joined by any predicate: the row counts "
                         f"multiply rather than match")

    if a.row_limit:
        rows = min(rows, a.row_limit)
        basis.append(f"a row limit of {a.row_limit:,} caps the result")

    return {"rows": int(rows), "basis": "; ".join(basis), "driving_table": driving,
            "full_scans": full_scans, "known": not unknown,
            "unknown_objects": [n for n, _ in unknown]}


@guard("GUARD-013", "Estimated work is within the ceiling",
       refs=["OWASP LLM10 Unbounded Consumption"])
def g013_cost(a, p, q):
    """The estimated rows examined against the policy ceiling. The estimate is
    arithmetic on declared statistics and says so; it is not an execution plan."""
    est = estimate_rows(a)
    if est["rows"] is None:
        return [_f(g013_cost, BLOCK,
                   "No statistics are available for any object in this query, so the cost "
                   "cannot be estimated and the ceiling cannot be applied.",
                   [est["basis"]], "Add the object to the schema with a row count.")]
    if est["rows"] > p.max_estimated_rows:
        return [_f(g013_cost, BLOCK,
                   f"An estimated {est['rows']:,} rows would be examined, against a ceiling of "
                   f"{p.max_estimated_rows:,}.",
                   [est["basis"], "This is arithmetic on declared statistics, not an "
                                  "execution plan."],
                   "Add a predicate on an indexed column, or a row limit, or ask for the "
                   "aggregate instead of the rows.")]
    return []


@guard("GUARD-014", "Large tables carry a predicate", refs=["OWASP LLM10 Unbounded Consumption"])
def g014_missing_where(a, p, q):
    """A large table with no predicate on any of its own columns, and no join
    reaching it by key, is being read end to end."""
    est = estimate_rows(a)
    big = [t for t in est.get("full_scans", [])
           if (schema.row_count(t) or 0) > p.require_where_above_rows]
    if not big:
        return []
    return [_f(g014_missing_where, BLOCK,
               f"{', '.join(big)} would be read end to end: nothing in the WHERE clause "
               f"touches a column of that table.",
               [f"{t}: approximately {schema.row_count(t):,} rows" for t in big],
               "Filter on an indexed column. On these tables a date range or an id is "
               "usually what the question actually meant.")]


@guard("GUARD-015", "A row limit is present where it needs to be", refs=[])
def g015_row_limit(a, p, q):
    """A large result with nothing capping it. This warns rather than blocks: the
    query is correct, it is just unbounded."""
    est = estimate_rows(a)
    if a.row_limit or est["rows"] is None:
        return []
    if est["rows"] <= p.require_row_limit_above_rows:
        return []
    return [_f(g015_row_limit, WARN,
               f"An estimated {est['rows']:,} rows would be examined with no limit on the result.",
               [est["basis"]],
               "Add FETCH FIRST n ROWS ONLY. On Oracle that is the modern form; ROWNUM "
               "still works but interacts badly with ORDER BY.")]


@guard("GUARD-016", "Join count and cartesian products", refs=[])
def g016_joins(a, p, q):
    """Relating n tables needs n-1 join conditions. Fewer means at least one pair
    is a cartesian product, which is the single most expensive mistake in
    generated SQL."""
    out = []
    n = len(a.tables)
    if n > p.max_tables_joined:
        out.append(_f(g016_joins, BLOCK,
                      f"{n} tables are referenced; the policy allows {p.max_tables_joined}.",
                      [f"tables: {', '.join(a.table_names)}"],
                      "Break the question into two."))
    if n >= 2 and a.join_conditions < n - 1 and not p.allow_cartesian:
        out.append(_f(g016_joins, BLOCK,
                      f"{n} tables with only {a.join_conditions} join condition(s). "
                      f"{n - 1} are needed to relate them, so at least one pair is a "
                      f"cartesian product.",
                      [f"tables: {', '.join(a.table_names)}",
                       f"join conditions found: {a.join_conditions}"],
                      "Join every table to the next on a key. A missing join is the most "
                      "expensive single mistake in generated SQL."))
    return out


@guard("GUARD-017", "Subquery depth", refs=[])
def g017_depth(a, p, q):
    """Deeply nested generated SQL is hard for a person to review, and that is the
    point at which the human review stops being real."""
    if a.subquery_depth <= p.max_subquery_depth:
        return []
    return [_f(g017_depth, WARN,
               f"Nesting reaches depth {a.subquery_depth}, past the policy's "
               f"{p.max_subquery_depth}.",
               [f"maximum parenthesis depth: {a.subquery_depth}"],
               "Deeply nested generated SQL is hard for a person to review, which is the "
               "point at which the review stops being real.")]


# ---------------------------------------------------------------- how it is written

_LITERAL_PREDICATE = re.compile(
    r"""(\b[A-Za-z_][A-Za-z0-9_$#]*)\s*(?:=|<>|!=|>=|<=|>|<|\bLIKE\b)\s*'([^']*)'""",
    re.IGNORECASE)


@guard("GUARD-018", "Values are bound, not concatenated",
       refs=["OWASP SQL Injection", "CWE-89"])
def g018_binds(a, p, q):
    """A value written into the SQL rather than bound is an injection surface, and
    on Oracle each distinct literal is also a separate cursor in the shared
    pool. A literal lifted from the question itself is the concatenation
    pattern exactly, and blocks rather than warns."""
    if not p.require_bind_variables or not a.where_text:
        return []
    hits = _LITERAL_PREDICATE.findall(a.where_text)
    if not hits:
        return []
    # A literal that came straight from the question is the one that matters:
    # it means user text was pasted into SQL rather than passed as a parameter.
    from_question = [(c, v) for c, v in hits if v and q and v.lower() in (q or "").lower()]
    verdict = BLOCK if from_question else WARN
    detail = (f"{len(hits)} value(s) are written into the SQL as literals rather than bound. "
              f"That is an injection surface, and on Oracle each distinct literal is also a "
              f"separate cursor in the shared pool.")
    if from_question:
        detail += (" At least one of them is text taken from the question itself, which is "
                   "the concatenation pattern exactly.")
    return [_f(g018_binds, verdict, detail,
               [f"{c} = '{v}'" for c, v in hits[:5]] +
               ([f"from the question: '{from_question[0][1]}'"] if from_question else []),
               "Emit :bind placeholders and pass the values separately. The model should "
               "produce the shape of the query, never the data in it.")]


@guard("GUARD-019", "No optimizer hints", refs=[])
def g019_hints(a, p, q):
    """A hint overrides the optimizer using knowledge the model does not have.
    PARALLEL in particular hands out server resources by the fistful."""
    if p.allow_hints or not a.hints:
        return []
    return [_f(g019_hints, BLOCK,
               f"The query carries {len(a.hints)} optimizer hint(s). A hint overrides the "
               f"optimizer using knowledge the model does not have, and PARALLEL in "
               f"particular hands out server resources by the fistful.",
               [h.strip() for h in a.hints[:3]],
               "Remove the hint. If a query genuinely needs one, that is a decision for a "
               "DBA with a plan in front of them.")]


@guard("GUARD-020", "Injection patterns in the question",
       refs=["OWASP LLM01 Prompt Injection"])
def g020_injection(a, p, q):
    """Published prompt-injection shapes in the question itself, checked separately
    from the SQL. A question can be badly worded rather than hostile, which is
    why the remedy says a person should look at it."""
    if not q:
        return []
    patterns = [
        (r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules)", "instruction override"),
        (r"(?i)disregard\s+(the\s+)?(schema|policy|rules|restrictions)", "policy override"),
        (r"(?i)you\s+are\s+now\s+", "role reassignment"),
        (r"(?i)\bas\s+(sysdba|sys|system)\b", "privilege escalation request"),
        (r"(?i);\s*(drop|delete|update|insert|grant|alter)\b", "stacked statement"),
        (r"(?i)\bunion\s+all\s+select\b", "union-based extraction"),
        (r"(?i)\bor\s+1\s*=\s*1\b", "always-true predicate"),
        (r"(?i)--\s*$", "trailing comment terminator"),
        (r"(?i)\b(dbms_|utl_)[a-z_]+", "package call named in the question"),
        (r"(?i)without\s+(the\s+)?(where|filter|limit)", "guard evasion"),
        (r"(?i)\b(all|every)\s+(ssn|social security|tax id|taxpayer id)", "bulk identifier request"),
    ]
    hits = [(name, re.search(rx, q).group(0)[:60]) for rx, name in patterns if re.search(rx, q)]
    if not hits:
        return []
    return [_f(g020_injection, BLOCK,
               f"The question carries {len(hits)} pattern(s) associated with prompt "
               f"injection rather than with asking for data.",
               [f"{name}: {text!r}" for name, text in hits[:4]],
               "The question is quarantined and the query is not run. Nothing here says "
               "the asker was hostile: a badly worded question can trip this, and a person "
               "should look at it.")]


# ---------------------------------------------------------------- runner

@dataclass
class Review:
    question: str
    sql: str
    verdict: str
    findings: list
    analysis: dict
    estimate: dict
    policy: str

    @property
    def blocked(self) -> bool:
        return self.verdict == BLOCK

    @property
    def needs_person(self) -> bool:
        return self.verdict == APPROVE

    def to_dict(self) -> dict:
        return {"question": self.question, "sql": self.sql, "verdict": self.verdict,
                "policy": self.policy, "findings": [f.to_dict() for f in self.findings],
                "analysis": self.analysis, "estimate": self.estimate}


def _approval_findings(a: Analysis, p: Policy, est: dict) -> list:
    """Things that do not block but must not happen without a person."""
    out = []
    if est.get("rows") and est["rows"] > p.approval_required_above_rows:
        out.append(Finding("GATE-001", "Result size needs a person", APPROVE,
                           f"An estimated {est['rows']:,} rows would be examined, above the "
                           f"{p.approval_required_above_rows:,} at which this policy wants a "
                           f"human decision.",
                           [est["basis"]],
                           "Approve it, narrow it, or ask for the aggregate.", []))
    touched = []
    for tbl_name, col_name in a.columns:
        col = schema.column(tbl_name, col_name)
        if col and p.needs_approval_for(col.sensitivity) and p.allows_sensitivity(col.sensitivity):
            touched.append(f"{tbl_name}.{col_name} ({col.sensitivity})")
    if touched:
        out.append(Finding("GATE-002", "Sensitive columns need a person", APPROVE,
                           f"The query returns {len(touched)} column(s) at or above "
                           f"{p.approval_required_for_sensitivity}.",
                           touched[:6],
                           "A named person approves, and the approval is logged with the "
                           "query it applies to.", ["NIST SP 800-53 AC-3"]))
    return out


def review(question: str, sql: str, pol: Policy) -> Review:
    """Run every guard. The worst verdict wins, and nothing overrides BLOCK."""
    try:
        a = Analysis(sql=sql) if False else __import__(
            "cybwaysql.oraclesql", fromlist=["analyse"]).analyse(sql)
    except SqlUnparseable as e:
        f = Finding("GUARD-001", "Statement parses and is a single statement", BLOCK,
                    f"The SQL could not be read: {e}",
                    [f"length: {len(sql or '')} characters"],
                    "Nothing that cannot be parsed is allowed through. Regenerate the query.",
                    [])
        return Review(question, sql, BLOCK, [f], {}, {}, pol.name)

    findings = []
    for fn in GUARDS:
        try:
            findings += fn(a, pol, question) or []
        except Exception as e:                       # a broken guard fails closed
            findings.append(Finding(fn.guard_id, fn.title, BLOCK,
                                    f"This guard could not run: {type(e).__name__}: {e}. "
                                    f"A guard that cannot run is treated as a block.",
                                    [], "Report this as a bug.", []))
    est = estimate_rows(a)
    if not any(f.verdict == BLOCK for f in findings):
        findings += _approval_findings(a, pol, est)

    verdict = ALLOW
    for f in findings:
        if VERDICT_ORDER[f.verdict] < VERDICT_ORDER[verdict]:
            verdict = f.verdict
    findings.sort(key=lambda f: f.sort_key)
    return Review(question, sql, verdict, findings, a.to_dict(), est, pol.name)


def guard_ids() -> list:
    return [fn.guard_id for fn in GUARDS]
