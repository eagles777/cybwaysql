"""The analyser: tokenising Oracle's awkward corners, and reading structure out
of a statement. All offline, $0."""

import pytest

from cybwaysql.oraclesql import (
    BIND, COMMENT, HINT, QUOTED_IDENT, STRING, SqlUnparseable,
    analyse, normalise, significant, tokenize,
)


def kinds(sql):
    return [t.kind for t in tokenize(sql)]


def values(sql, kind):
    return [t.value for t in tokenize(sql) if t.kind == kind]


# ---------------------------------------------------------------- tokenising

def test_a_hint_is_not_a_comment():
    """A /*+ ... */ changes the plan. Treating it as a comment loses the fact."""
    sql = "SELECT /*+ PARALLEL(8) */ /* just a note */ a FROM t"
    assert values(sql, HINT) == ["/*+ PARALLEL(8) */"]
    assert values(sql, COMMENT) == ["/* just a note */"]
    assert [t.kind for t in significant(tokenize(sql))].count(COMMENT) == 0


def test_escaped_and_q_quoted_literals():
    assert values("SELECT 'it''s fine' FROM dual", STRING) == ["'it''s fine'"]
    assert values("SELECT q'[don't]' FROM dual", STRING) == ["q'[don't]'"]
    assert values("SELECT q'(a'b)' FROM dual", STRING) == ["q'(a'b)'"]
    assert values("SELECT q'{x}' FROM dual", STRING) == ["q'{x}'"]
    assert values("SELECT n'unicode' FROM dual", STRING) == ["'unicode'"]


def test_identifiers_may_contain_dollar_and_hash():
    """V$SESSION is one name. A tokeniser that splits it reports the wrong object."""
    toks = [t.value for t in tokenize("SELECT sid FROM v$session")]
    assert "v$session" in toks
    assert "a#b" in [t.value for t in tokenize("SELECT a#b FROM t")]


def test_binds_quoted_identifiers_and_substitutions():
    assert values("SELECT a FROM t WHERE x = :name AND y = :2", BIND) == [":name", ":2"]
    assert values('SELECT "Mixed Case" FROM t', QUOTED_IDENT) == ['"Mixed Case"']
    assert values("SELECT &col FROM t", "substitution") == ["&col"]


def test_line_numbers_are_kept():
    toks = tokenize("SELECT a\nFROM t\nWHERE x = 1")
    assert [t.line for t in toks if t.value.upper() == "WHERE"] == [3]


def test_unterminated_text_is_refused_not_guessed():
    for bad in ("SELECT 'oops", "SELECT /* oops", 'SELECT "oops', "SELECT q'[oops"):
        with pytest.raises(SqlUnparseable):
            tokenize(bad)


def test_empty_input_is_refused():
    for bad in ("", "   ", None):
        with pytest.raises(SqlUnparseable):
            analyse(bad)
    with pytest.raises(SqlUnparseable):
        analyse("-- nothing but a comment")


# ---------------------------------------------------------------- structure

def test_statement_kinds():
    assert analyse("SELECT 1 FROM dual").kind == "SELECT"
    assert analyse("WITH x AS (SELECT 1 FROM dual) SELECT * FROM x").kind == "SELECT"
    assert analyse("UPDATE t SET a = 1").kind == "UPDATE"
    assert analyse("DELETE FROM t").kind == "DELETE"
    assert analyse("INSERT INTO t VALUES (1)").kind == "INSERT"
    assert analyse("MERGE INTO t USING s ON (1=1)").kind == "MERGE"
    assert analyse("DROP TABLE t").kind == "DDL"
    assert analyse("GRANT SELECT ON t TO joe").kind == "DCL"
    assert analyse("BEGIN NULL; END;").kind == "PLSQL"
    assert analyse("COMMIT").kind == "TCL"


def test_stacked_statements_are_counted():
    a = analyse("SELECT a FROM t WHERE x = 'q'; DROP TABLE claims")
    assert a.statements == 2
    assert analyse("SELECT a FROM t;").statements == 1     # a trailing semicolon is not a statement


def test_tables_aliases_and_schema_qualification():
    a = analyse("SELECT c.id FROM app.case_header c JOIN office o ON o.code = c.code")
    assert a.table_names == ["CASE_HEADER", "OFFICE"]
    assert a.alias_map()["C"] == "CASE_HEADER"
    assert a.tables[0].schema == "APP"
    assert a.tables[0].qualified == "APP.CASE_HEADER"


def test_comma_joined_tables_are_both_found():
    a = analyse("SELECT c.a, p.b FROM case_header c, payment_txn p WHERE c.id = p.cid")
    assert a.table_names == ["CASE_HEADER", "PAYMENT_TXN"]
    assert a.join_conditions == 1


def test_a_comma_in_group_by_is_not_a_table():
    """The bug this test exists for: GROUP BY a, b once produced a phantom table."""
    a = analyse("SELECT c.office_code, c.status_code, COUNT(*) FROM case_header c "
                "WHERE c.closed_date >= :d GROUP BY c.office_code, c.status_code")
    assert a.table_names == ["CASE_HEADER"]


def test_database_links_are_reported():
    a = analyse("SELECT name FROM employees@PROD_LINK")
    assert a.db_links == ["PROD_LINK"]
    assert a.tables[0].qualified == "EMPLOYEES@PROD_LINK"


def test_count_star_is_not_select_star():
    assert analyse("SELECT COUNT(*) FROM t").selects_star is False
    assert analyse("SELECT * FROM t").selects_star is True
    assert analyse("SELECT t.* FROM t").selects_star is True
    assert analyse("SELECT SUM(x), COUNT(*) FROM t").selects_star is False


def test_where_joins_and_row_limits():
    a = analyse("SELECT a FROM t WHERE x = :x FETCH FIRST 25 ROWS ONLY")
    assert a.has_where and a.row_limit == 25
    assert analyse("SELECT a FROM t WHERE ROWNUM <= 10").row_limit == 10
    assert analyse("SELECT a FROM t").row_limit is None


def test_function_calls_and_packages():
    a = analyse("SELECT UTL_HTTP.request('x'), COUNT(*) FROM t")
    assert "UTL_HTTP.REQUEST" in a.functions and "COUNT" in a.functions


def test_a_column_reference_is_not_a_function():
    """c.case_id was once reported as a call to package c."""
    a = analyse("SELECT c.case_id FROM case_header c")
    assert a.functions == []
    assert ("CASE_HEADER", "CASE_ID") in a.columns


def test_an_output_alias_is_not_a_column():
    a = analyse("SELECT COUNT(*) AS case_count FROM case_header c WHERE c.id = :i")
    assert "CASE_COUNT" not in [col for _, col in a.columns]


def test_single_table_columns_are_resolved_multi_table_are_not():
    one = analyse("SELECT tax_id FROM filer WHERE address_state = :s")
    assert ("FILER", "TAX_ID") in one.columns and one.unqualified_columns == []
    two = analyse("SELECT tax_id FROM filer f, office o WHERE f.id = o.id")
    assert "TAX_ID" in two.unqualified_columns


def test_for_update_and_set_operators_and_depth():
    assert analyse("SELECT a FROM t FOR UPDATE").for_update is True
    assert analyse("SELECT a FROM t UNION ALL SELECT b FROM u").set_operators == ["UNION"]
    assert analyse("SELECT a FROM (SELECT b FROM (SELECT c FROM t))").subquery_depth == 2


def test_normalise_is_comparable_and_keeps_literal_values():
    assert normalise("select  a , b  from T -- note\n") == normalise("SELECT a, b FROM t")
    assert "'Smith'" in normalise("select a from t where n = 'Smith'")
