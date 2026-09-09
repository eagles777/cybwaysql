"""A structural analyser for Oracle SQL, written to be read before it is trusted.

This is the piece every guard depends on, so it states its limits up front.

WHAT IT IS. A tokeniser plus a structural pass. It answers the questions a
reviewer asks in the first ten seconds of reading a generated query: what kind
of statement is this, which objects does it touch, is there a WHERE clause, are
the tables actually joined, does it reach a database link, does it call a
package, are values bound or concatenated in.

WHAT IT IS NOT. An Oracle grammar, a parser, or an optimizer. It does not
resolve views to base tables, does not evaluate expressions, and cannot tell
you what a query means. Where it is unsure it says so, and the caller's rule is
that unsure means blocked.

Why hand-written rather than a library: the runtime is stdlib-only by design,
the dialect specifics that matter here (hints, q-quoted literals, database
links, identifiers containing $ and #) are exactly what generic parsers get
wrong, and a governance tool whose core is a dependency nobody has read is not
much of a governance tool.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------- tokens

WORD, NUMBER, STRING, PUNCT, OPERATOR = "word", "number", "string", "punct", "operator"
COMMENT, HINT, BIND, SUBST, QUOTED_IDENT, TERMINATOR = (
    "comment", "hint", "bind", "substitution", "quoted_ident", "terminator")


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    pos: int
    line: int

    @property
    def upper(self) -> str:
        return self.value.upper()

    def is_word(self, *words: str) -> bool:
        return self.kind == WORD and self.upper in {w.upper() for w in words}


class SqlUnparseable(ValueError):
    """The text could not be tokenised. The caller blocks the query."""


# Oracle identifiers may contain $ and #, which is why a generic tokeniser
# mangles names like V$SESSION or DBA_TAB#COLS.
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_$#]*")
_NUMBER = re.compile(r"\d+(?:\.\d+)?(?:[eE][+-]?\d+)?")
_BIND = re.compile(r":[A-Za-z0-9_$#]+")
_SUBST = re.compile(r"&&?[A-Za-z0-9_$#]+")
# q'[...]' and friends: Oracle's alternative quoting mechanism.
_QQUOTE_OPEN = re.compile(r"[qQ]'(.)", re.S)
_QQUOTE_PAIRS = {"[": "]", "(": ")", "{": "}", "<": ">"}

_MULTI_CHAR_OPS = ("||", "<=", ">=", "<>", "!=", "^=", "..", "=>", ":=", "(+)")


def tokenize(sql: str) -> list:
    """Split Oracle SQL into tokens, keeping comments and hints as their own kinds.

    Whitespace is dropped. Positions and line numbers are kept so a finding can
    point at the offending text rather than describe it.
    """
    if sql is None:
        raise SqlUnparseable("no SQL was supplied")
    out: list = []
    i, n, line = 0, len(sql), 1
    while i < n:
        ch = sql[i]
        if ch in " \t\r\n\f":
            if ch == "\n":
                line += 1
            i += 1
            continue
        # -- line comment
        if sql.startswith("--", i):
            end = sql.find("\n", i)
            end = n if end == -1 else end
            out.append(Token(COMMENT, sql[i:end], i, line))
            i = end
            continue
        # /*+ hint */ is not a comment: it changes the plan, so it is its own kind
        if sql.startswith("/*", i):
            end = sql.find("*/", i + 2)
            if end == -1:
                raise SqlUnparseable(f"unterminated block comment at line {line}")
            body = sql[i:end + 2]
            kind = HINT if sql.startswith("/*+", i) else COMMENT
            out.append(Token(kind, body, i, line))
            line += body.count("\n")
            i = end + 2
            continue
        # q'[...]' alternative quoting
        m = _QQUOTE_OPEN.match(sql, i)
        if m and (i == 0 or not _IDENT.match(sql[i - 1])):
            opener = m.group(1)
            closer = _QQUOTE_PAIRS.get(opener, opener)
            end = sql.find(closer + "'", m.end())
            if end == -1:
                raise SqlUnparseable(f"unterminated q-quoted literal at line {line}")
            body = sql[i:end + 2]
            out.append(Token(STRING, body, i, line))
            line += body.count("\n")
            i = end + 2
            continue
        # n'...' national character literal
        if ch in "nN" and i + 1 < n and sql[i + 1] == "'":
            i += 1
            ch = "'"
        # '...' with '' escaping
        if ch == "'":
            j = i + 1
            while True:
                j = sql.find("'", j)
                if j == -1:
                    raise SqlUnparseable(f"unterminated string literal at line {line}")
                if j + 1 < n and sql[j + 1] == "'":
                    j += 2
                    continue
                break
            body = sql[i:j + 1]
            out.append(Token(STRING, body, i, line))
            line += body.count("\n")
            i = j + 1
            continue
        # "Quoted Identifier"
        if ch == '"':
            j = sql.find('"', i + 1)
            if j == -1:
                raise SqlUnparseable(f"unterminated quoted identifier at line {line}")
            out.append(Token(QUOTED_IDENT, sql[i:j + 1], i, line))
            i = j + 1
            continue
        if ch == ":":
            m = _BIND.match(sql, i)
            if m:
                out.append(Token(BIND, m.group(0), i, line))
                i = m.end()
                continue
        if ch == "&":
            m = _SUBST.match(sql, i)
            if m:
                out.append(Token(SUBST, m.group(0), i, line))
                i = m.end()
                continue
        if ch.isdigit() or (ch == "." and i + 1 < n and sql[i + 1].isdigit()):
            m = _NUMBER.match(sql, i)
            if m:
                out.append(Token(NUMBER, m.group(0), i, line))
                i = m.end()
                continue
        m = _IDENT.match(sql, i)
        if m:
            out.append(Token(WORD, m.group(0), i, line))
            i = m.end()
            continue
        if ch == ";":
            out.append(Token(TERMINATOR, ";", i, line))
            i += 1
            continue
        for op in _MULTI_CHAR_OPS:
            if sql.startswith(op, i):
                out.append(Token(OPERATOR, op, i, line))
                i += len(op)
                break
        else:
            kind = PUNCT if ch in "(),.@" else OPERATOR
            out.append(Token(kind, ch, i, line))
            i += 1
    return out


def significant(tokens: list) -> list:
    """Tokens that change what the statement does. Comments are dropped; hints
    are kept, because a hint is an instruction to the optimizer, not a note."""
    return [t for t in tokens if t.kind != COMMENT]


# ---------------------------------------------------------------- analysis

SELECT, INSERT, UPDATE, DELETE, MERGE = "SELECT", "INSERT", "UPDATE", "DELETE", "MERGE"
DDL, DCL, PLSQL, TCL, UNKNOWN = "DDL", "DCL", "PLSQL", "TCL", "UNKNOWN"

READ_ONLY_KINDS = {SELECT}
WRITE_KINDS = {INSERT, UPDATE, DELETE, MERGE}

_DDL_WORDS = {"CREATE", "ALTER", "DROP", "TRUNCATE", "RENAME", "COMMENT", "ANALYZE",
              "PURGE", "FLASHBACK", "AUDIT", "NOAUDIT", "ASSOCIATE", "DISASSOCIATE"}
_DCL_WORDS = {"GRANT", "REVOKE"}
_TCL_WORDS = {"COMMIT", "ROLLBACK", "SAVEPOINT", "SET", "LOCK"}
_PLSQL_WORDS = {"DECLARE", "BEGIN", "CALL", "EXEC", "EXECUTE"}

# Words after which an object name appears.
_FROM_WORDS = {"FROM", "JOIN", "INTO", "UPDATE", "USING"}
_JOIN_WORDS = {"JOIN"}
_NON_TABLE_AFTER_FROM = {"DUAL"}

_SET_OPERATORS = {"UNION", "INTERSECT", "MINUS", "EXCEPT"}

# Prefixes of Oracle's supplied packages. Used only to tell a package call apart
# from an ordinary alias.column reference.
_PACKAGE_PREFIXES = ("DBMS_", "UTL_", "OWA_", "ORD_", "CTX_", "SDO_", "HTP", "HTF",
                     "XDB", "JAVA_", "SCHEDULER")


def _looks_like_package(name: str) -> bool:
    n = name.upper()
    return n.startswith(_PACKAGE_PREFIXES) or n in {"SYS", "SYSTEM"}

# Clause keywords that end the select list.
_CLAUSE_WORDS = {"FROM", "WHERE", "GROUP", "HAVING", "ORDER", "CONNECT", "START",
                 "UNION", "INTERSECT", "MINUS", "EXCEPT", "FETCH", "OFFSET", "MODEL",
                 "PIVOT", "UNPIVOT", "FOR"}


@dataclass
class TableRef:
    name: str                    # as written, upper-cased, without the link
    schema: str = ""
    alias: str = ""
    db_link: str = ""
    line: int = 0

    @property
    def qualified(self) -> str:
        base = f"{self.schema}.{self.name}" if self.schema else self.name
        return f"{base}@{self.db_link}" if self.db_link else base


@dataclass
class Analysis:
    """Everything the guards need to know, and nothing they have to guess."""

    sql: str
    kind: str = UNKNOWN
    statements: int = 1
    tables: list = field(default_factory=list)          # TableRef
    select_list: list = field(default_factory=list)     # raw text of each item
    columns: list = field(default_factory=list)         # (table_or_alias, column) upper
    unqualified_columns: list = field(default_factory=list)
    has_where: bool = False
    where_text: str = ""
    join_conditions: int = 0
    functions: list = field(default_factory=list)       # upper-cased call names
    db_links: list = field(default_factory=list)
    hints: list = field(default_factory=list)
    comments: list = field(default_factory=list)
    binds: list = field(default_factory=list)
    substitutions: list = field(default_factory=list)
    string_literals: list = field(default_factory=list)
    set_operators: list = field(default_factory=list)
    selects_star: bool = False
    star_tables: list = field(default_factory=list)
    row_limit: int | None = None
    subquery_depth: int = 0
    for_update: bool = False
    notes: list = field(default_factory=list)           # what the analyser was unsure about

    @property
    def is_read_only(self) -> bool:
        return self.kind in READ_ONLY_KINDS and self.statements == 1

    @property
    def writes(self) -> bool:
        return self.kind in WRITE_KINDS

    @property
    def table_names(self) -> list:
        return sorted({t.name for t in self.tables})

    def alias_map(self) -> dict:
        m = {}
        for t in self.tables:
            if t.alias:
                m[t.alias] = t.name
            m[t.name] = t.name
        return m

    def to_dict(self) -> dict:
        return {
            "kind": self.kind, "statements": self.statements,
            "tables": [t.qualified for t in self.tables],
            "aliases": {t.alias: t.name for t in self.tables if t.alias},
            "select_list": self.select_list, "selects_star": self.selects_star,
            "columns": [f"{a}.{c}" if a else c for a, c in self.columns],
            "unqualified_columns": self.unqualified_columns,
            "has_where": self.has_where, "join_conditions": self.join_conditions,
            "functions": self.functions, "db_links": self.db_links,
            "hints": self.hints, "binds": self.binds, "substitutions": self.substitutions,
            "string_literals": len(self.string_literals),
            "set_operators": self.set_operators, "row_limit": self.row_limit,
            "subquery_depth": self.subquery_depth, "for_update": self.for_update,
            "notes": self.notes,
        }


def _statement_kind(words: list) -> str:
    """The first significant word decides, with WITH and set operators handled."""
    if not words:
        return UNKNOWN
    first = words[0]
    if first == "WITH":
        # A WITH clause is a SELECT unless a later top-level word says otherwise.
        for w in words[1:]:
            if w in WRITE_KINDS or w in _DDL_WORDS:
                return w if w in WRITE_KINDS else DDL
        return SELECT
    if first in ("SELECT", "("):
        return SELECT
    if first in WRITE_KINDS:
        return first
    if first in _DDL_WORDS:
        return DDL
    if first in _DCL_WORDS:
        return DCL
    if first in _PLSQL_WORDS:
        return PLSQL
    if first in _TCL_WORDS:
        return TCL
    if first == "EXPLAIN":
        return SELECT
    return UNKNOWN


def _read_object(toks: list, i: int):
    """Read schema.object@link starting at i. Returns (TableRef, next_index)."""
    parts = []
    link = ""
    while i < len(toks):
        t = toks[i]
        if t.kind in (WORD, QUOTED_IDENT):
            parts.append(t.value.strip('"').upper())
            i += 1
            if i < len(toks) and toks[i].value == ".":
                i += 1
                continue
            if i < len(toks) and toks[i].value == "@":
                i += 1
                if i < len(toks) and toks[i].kind in (WORD, QUOTED_IDENT):
                    link = toks[i].value.strip('"').upper()
                    i += 1
            break
        break
    if not parts:
        return None, i
    schema = ".".join(parts[:-1])
    ref = TableRef(name=parts[-1], schema=schema, db_link=link,
                   line=toks[min(i, len(toks) - 1)].line)
    # An alias may follow, optionally after AS. Reserved words are not aliases.
    if i < len(toks) and toks[i].is_word("AS"):
        i += 1
    if (i < len(toks) and toks[i].kind == WORD
            and toks[i].upper not in _CLAUSE_WORDS
            and toks[i].upper not in {"ON", "JOIN", "INNER", "LEFT", "RIGHT", "FULL",
                                      "CROSS", "NATURAL", "OUTER", "SET", "VALUES",
                                      "PARTITION", "WITH", "USING"}):
        ref.alias = toks[i].upper
        i += 1
    return ref, i


def analyse(sql: str) -> Analysis:
    """Tokenise and walk the statement. Raises SqlUnparseable on broken input."""
    if not (sql or "").strip():
        raise SqlUnparseable("the SQL is empty")
    tokens = tokenize(sql)
    toks = significant(tokens)
    a = Analysis(sql=sql)
    a.comments = [t.value for t in tokens if t.kind == COMMENT]
    a.hints = [t.value for t in toks if t.kind == HINT]
    a.binds = sorted({t.value for t in toks if t.kind == BIND})
    a.substitutions = sorted({t.value for t in toks if t.kind == SUBST})
    a.string_literals = [t.value for t in toks if t.kind == STRING]

    body = [t for t in toks if t.kind != HINT]
    if not body:
        raise SqlUnparseable("the SQL contains nothing but comments or hints")

    # More than one statement is a fact about the text, not a style question:
    # a trailing statement after a semicolon is the classic stacked-query shape.
    tails = [i for i, t in enumerate(body) if t.kind == TERMINATOR and i < len(body) - 1]
    a.statements = 1 + len(tails)
    words = [t.upper for t in body if t.kind == WORD] or [body[0].value]
    a.kind = _statement_kind([body[0].upper if body[0].kind == WORD else body[0].value] + words)

    depth = 0
    max_depth = 0
    i = 0
    in_select_list = False
    in_from = False          # commas mean another table only inside the FROM clause
    select_start = None
    while i < len(body):
        t = body[i]
        v = t.upper

        if t.value == "(":
            depth += 1
            max_depth = max(max_depth, depth)
        elif t.value == ")":
            depth = max(0, depth - 1)

        # object references
        if t.kind == WORD and v in _FROM_WORDS:
            if v == "FROM" and in_select_list and depth == 0 and select_start is not None:
                a.select_list = _split_select_list(body[select_start:i])
                in_select_list = False
            in_from = True
            is_join = v in _JOIN_WORDS
            j = i + 1
            # FROM ( subquery ) is not a table
            if j < len(body) and body[j].value != "(":
                ref, j2 = _read_object(body, j)
                if ref and ref.name not in _NON_TABLE_AFTER_FROM:
                    a.tables.append(ref)
                    if ref.db_link:
                        a.db_links.append(ref.db_link)
                    if is_join:
                        a.join_conditions += 0  # counted by ON below
                i = max(j2, i + 1)
                continue
        # comma-separated tables in the FROM list, e.g. FROM a t1, b t2.
        # A comma in a GROUP BY or an ORDER BY separates columns, not tables,
        # which is why in_from has to be tracked rather than assumed.
        if (t.value == "," and in_from and a.tables and depth == 0 and not in_select_list
                and i + 1 < len(body) and body[i + 1].kind in (WORD, QUOTED_IDENT)
                and body[i + 1].upper not in _CLAUSE_WORDS):
            ref, j2 = _read_object(body, i + 1)
            if ref and ref.name not in _NON_TABLE_AFTER_FROM:
                a.tables.append(ref)
                if ref.db_link:
                    a.db_links.append(ref.db_link)
            i = max(j2, i + 1)
            continue

        if t.kind == WORD:
            if v == "SELECT":
                in_select_list = True
                select_start = i + 1
            elif v in _CLAUSE_WORDS and depth == 0:
                if in_select_list and select_start is not None and v == "FROM":
                    a.select_list = _split_select_list(body[select_start:i])
                in_select_list = False
                if v not in ("FROM", "USING"):
                    in_from = False       # the FROM clause has ended
            if v == "WHERE":
                a.has_where = True
            if v == "ON":
                a.join_conditions += 1
            if v in _SET_OPERATORS and depth == 0:
                a.set_operators.append(v)
            if v == "UPDATE" and i + 1 < len(body) and body[i + 1].is_word("SET"):
                a.for_update = a.for_update  # `FOR UPDATE` handled below
            if v == "FOR" and i + 1 < len(body) and body[i + 1].is_word("UPDATE"):
                a.for_update = True
            if v == "ROWNUM" and i + 2 < len(body) and body[i + 2].kind == NUMBER:
                try:
                    a.row_limit = int(body[i + 2].value)
                except ValueError:
                    pass
            if v == "FETCH":
                for k in range(i, min(i + 6, len(body))):
                    if body[k].kind == NUMBER:
                        try:
                            a.row_limit = int(body[k].value)
                        except ValueError:
                            pass
                        break
            # A function or package call is a WORD immediately followed by (
            if i + 1 < len(body) and body[i + 1].value == "(":
                name = v
                if i >= 2 and body[i - 1].value == "." and body[i - 2].kind == WORD:
                    name = f"{body[i - 2].upper}.{v}"   # package.procedure
                a.functions.append(name)
            # A package call with no argument list, e.g. DBMS_OUTPUT.PUT_LINE;
            # Only for names that are packages, because otherwise every
            # alias.column reference would be mistaken for a call.
            elif (_looks_like_package(v) and i + 2 < len(body)
                  and body[i + 1].value == "." and body[i + 2].kind == WORD):
                a.functions.append(f"{v}.{body[i + 2].upper}")

        # A * in the select list means "every column". A * inside parentheses is
        # an argument, as in COUNT(*), and says nothing about what comes back.
        if t.value == "*" and in_select_list and depth == 0:
            prev = body[i - 1] if i else None
            qualified_star = prev is not None and prev.value == "."
            if qualified_star or prev is None or prev.value == "," or (
                    prev.kind == WORD and prev.upper in {"SELECT", "DISTINCT", "ALL", "UNIQUE"}):
                a.selects_star = True
                if qualified_star and i >= 2 and body[i - 2].kind == WORD:
                    a.star_tables.append(body[i - 2].upper)
        i += 1

    a.subquery_depth = max_depth
    a.functions = list(dict.fromkeys(a.functions))
    a.columns, a.unqualified_columns = _columns(body, a)
    a.join_conditions += _where_join_predicates(body, a)
    a.where_text = _where_text(body)
    if a.kind == UNKNOWN:
        a.notes.append("the statement kind could not be determined from the leading keyword")
    if a.selects_star:
        a.notes.append("a * in the select list hides which columns are actually returned")
    return a


def _split_select_list(toks: list) -> list:
    """The select list as written, one entry per top-level comma."""
    items, current, depth = [], [], 0
    for t in toks:
        if t.value == "(":
            depth += 1
        elif t.value == ")":
            depth = max(0, depth - 1)
        if t.value == "," and depth == 0:
            items.append(" ".join(x.value for x in current).strip())
            current = []
            continue
        current.append(t)
    if current:
        items.append(" ".join(x.value for x in current).strip())
    return [i for i in items if i]


_NOT_A_COLUMN = (_CLAUSE_WORDS | _SET_OPERATORS | _DDL_WORDS | _DCL_WORDS | _TCL_WORDS |
                 {"SELECT", "INSERT", "UPDATE", "DELETE", "MERGE", "AS", "AND", "OR", "NOT",
                  "NULL", "IS", "IN", "LIKE", "BETWEEN", "EXISTS", "CASE", "WHEN", "THEN",
                  "ELSE", "END", "DISTINCT", "ALL", "ANY", "SOME", "ON", "JOIN", "INNER",
                  "LEFT", "RIGHT", "FULL", "CROSS", "NATURAL", "OUTER", "USING", "BY",
                  "ASC", "DESC", "VALUES", "SET", "INTO", "DUAL", "ROWNUM", "ROWID",
                  "SYSDATE", "SYSTIMESTAMP", "USER", "LEVEL", "PRIOR", "ONLY", "ROWS",
                  "ROW", "NEXT", "FIRST", "PARTITION", "OVER", "NULLS", "LAST",
                  "TABLE", "INDEX", "VIEW", "SEQUENCE", "SYNONYM", "TRIGGER", "PROCEDURE",
                  "FUNCTION", "PACKAGE", "BEGIN", "DECLARE", "LOOP", "IF", "THEN", "ELSIF",
                  "IMMEDIATE", "TO", "PUBLIC", "SESSION", "SYSTEM", "WITH", "READ", "WRITE"})


def _columns(body: list, a: Analysis):
    """Column references, qualified where the text allows it.

    Unqualified columns in a multi-table query are returned separately: the
    analyser will not guess which table they belong to, and a guard that has to
    decide whether a sensitive column was selected needs to know that.
    """
    aliases = a.alias_map()
    # A database link name and a package name are not columns.
    excluded = set(_NOT_A_COLUMN) | {t.db_link for t in a.tables if t.db_link}
    excluded |= {f.split(".")[0] for f in a.functions}
    qualified, unqualified = [], []
    for i, t in enumerate(body):
        if t.kind not in (WORD, QUOTED_IDENT):
            continue
        name = t.value.strip('"').upper()
        if name in excluded:
            continue
        # a function call, not a column
        if i + 1 < len(body) and body[i + 1].value == "(":
            continue
        prev_dot = i >= 1 and body[i - 1].value == "."
        next_dot = i + 1 < len(body) and body[i + 1].value == "."
        if next_dot:
            continue  # this is the qualifier, the column comes next
        # A name introduced by AS is an output alias, not a column being read.
        if i >= 1 and body[i - 1].kind == WORD and body[i - 1].upper == "AS":
            continue
        if prev_dot and i >= 2 and body[i - 2].kind in (WORD, QUOTED_IDENT):
            qual = body[i - 2].value.strip('"').upper()
            table = aliases.get(qual, qual)
            qualified.append((table, name))
        else:
            if name in aliases:
                continue  # a bare table or alias name, not a column
            unqualified.append(name)
    # With exactly one table there is nothing to be ambiguous about, so an
    # unqualified column is resolved to it. This is what makes the sensitive-
    # column guard work on the single-table queries that make up most of the
    # traffic. With two or more tables the analyser refuses to guess.
    if len(a.tables) == 1:
        only = a.tables[0].name
        qualified += [(only, c) for c in unqualified]
        unqualified = []

    seen, q = set(), []
    for pair in qualified:                      # de-duplicate, keep order stable
        if pair not in seen:
            seen.add(pair)
            q.append(pair)
    return q, sorted(set(unqualified))


def _where_join_predicates(body: list, a: Analysis) -> int:
    """Count cross-table equalities in the WHERE clause: the old-style join.

    a.id = b.a_id counts; a.id = 42 does not. This is how the analyser tells a
    two-table query that is joined from one that is a cartesian product.
    """
    if len(a.tables) < 2:
        return 0
    count = 0
    for i, t in enumerate(body):
        if t.value != "=" or i < 3 or i + 3 >= len(body):
            continue
        left_qual = body[i - 2].value == "." and body[i - 3].kind == WORD
        right_qual = body[i + 2].value == "." and body[i + 1].kind == WORD
        if left_qual and right_qual:
            aliases = a.alias_map()
            lt = aliases.get(body[i - 3].upper, body[i - 3].upper)
            rt = aliases.get(body[i + 1].upper, body[i + 1].upper)
            if lt != rt:
                count += 1
    return count


def _where_text(body: list) -> str:
    start = None
    for i, t in enumerate(body):
        if t.kind == WORD and t.upper == "WHERE":
            start = i + 1
            break
    if start is None:
        return ""
    stop = len(body)
    for i in range(start, len(body)):
        if body[i].kind == WORD and body[i].upper in {"GROUP", "ORDER", "HAVING", "FETCH",
                                                      "UNION", "INTERSECT", "MINUS", "OFFSET"}:
            stop = i
            break
    return " ".join(t.value for t in body[start:stop])


def normalise(sql: str) -> str:
    """Comparable form for the golden set: comments gone, whitespace and case
    regular, string literals kept as written because their values matter."""
    toks = [t for t in tokenize(sql) if t.kind != COMMENT and t.kind != TERMINATOR]
    parts = []
    for t in toks:
        parts.append(t.value if t.kind in (STRING, QUOTED_IDENT) else t.value.upper())
    text = " ".join(parts)
    text = re.sub(r"\s*([(),.])\s*", r"\1", text)
    return re.sub(r"\s+", " ", text).strip()
