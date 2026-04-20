import sqlite3
import json
import os


class DB:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")

    def table(self, name: str, columns: dict[str, str], primary_key: str = "id"):
        return Table(self, name, columns, primary_key)

    def execute(self, sql: str, params=()):
        self.conn.execute(sql, params)
        self.conn.commit()

    def query(self, sql: str, params=()):
        return self.conn.execute(sql, params).fetchall()

    def close(self):
        self.conn.close()


class Table:
    def __init__(self, db: DB, name: str, columns: dict[str, str], primary_key: str):
        self.db = db
        self.name = name
        self.primary_key = primary_key
        col_defs = []
        for col, typ in columns.items():
            if col == primary_key:
                col_defs.append(f"{col} {typ} PRIMARY KEY")
            else:
                col_defs.append(f"{col} {typ}")
        db.execute(f"CREATE TABLE IF NOT EXISTS {name} ({', '.join(col_defs)})")
        existing = {row[1] for row in db.query(f"PRAGMA table_info({name})")}
        for col, typ in columns.items():
            if col not in existing:
                db.execute(f"ALTER TABLE {name} ADD COLUMN {col} {typ}")

    def _row_to_dict(self, row) -> dict | None:
        if row is None:
            return None
        d = dict(row)
        for k, v in d.items():
            if isinstance(v, str):
                try:
                    parsed = json.loads(v)
                    if isinstance(parsed, (dict, list)):
                        d[k] = parsed
                except (json.JSONDecodeError, TypeError):
                    pass
        return d

    def insert(self, data: dict) -> int:
        cols = ", ".join(data.keys())
        placeholders = ", ".join(["?"] * len(data))
        values = tuple(
            json.dumps(v) if isinstance(v, (dict, list)) else v for v in data.values()
        )
        cur = self.db.conn.execute(
            f"INSERT INTO {self.name} ({cols}) VALUES ({placeholders})", values
        )
        self.db.conn.commit()
        return cur.lastrowid  # type: ignore

    def get(self, **kwargs) -> dict | None:
        col, val = next(iter(kwargs.items()))
        if isinstance(val, (dict, list)):
            val = json.dumps(val)
        row = self.db.query(f"SELECT * FROM {self.name} WHERE {col} = ?", (val,))
        return self._row_to_dict(row[0]) if row else None

    def search(self, **kwargs) -> list[dict]:
        if not kwargs:
            rows = self.db.query(f"SELECT * FROM {self.name}")
            return [self._row_to_dict(r) for r in rows] # type: ignore
        conditions = []
        values = []
        for col, val in kwargs.items():
            conditions.append(f"{col} = ?")
            if isinstance(val, (dict, list)):
                values.append(json.dumps(val))
            else:
                values.append(val)
        rows = self.db.query(
            f"SELECT * FROM {self.name} WHERE {' AND '.join(conditions)}", tuple(values)
        )
        return [self._row_to_dict(r) for r in rows]  # type: ignore

    def update(self, data: dict, **kwargs) -> int:
        sets = []
        values = []
        for col, val in data.items():
            sets.append(f"{col} = ?")
            if isinstance(val, (dict, list)):
                values.append(json.dumps(val))
            else:
                values.append(val)
        conditions = []
        for col, val in kwargs.items():
            conditions.append(f"{col} = ?")
            values.append(val)
        where = " AND ".join(conditions) if conditions else "1=1"
        cur = self.db.conn.execute(
            f"UPDATE {self.name} SET {', '.join(sets)} WHERE {where}", tuple(values)
        )
        self.db.conn.commit()
        return cur.rowcount

    def remove(self, **kwargs) -> int:
        conditions = []
        values = []
        for col, val in kwargs.items():
            conditions.append(f"{col} = ?")
            values.append(val)
        where = " AND ".join(conditions) if conditions else "1=1"
        cur = self.db.conn.execute(
            f"DELETE FROM {self.name} WHERE {where}", tuple(values)
        )
        self.db.conn.commit()
        return cur.rowcount
