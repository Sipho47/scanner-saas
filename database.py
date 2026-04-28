from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json
import os
import sqlite3


DATABASE_URL = os.getenv("DATABASE_URL")
SQLITE_PATH = os.getenv("SQLITE_PATH", "scanner.db")


def init_db() -> None:
    if _using_postgres():
        with _postgres_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS scan_results (
                        id SERIAL PRIMARY KEY,
                        user_email TEXT,
                        target TEXT NOT NULL,
                        hostname TEXT,
                        status_code INTEGER,
                        issue_count INTEGER NOT NULL DEFAULT 0,
                        result_json JSONB NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
                cursor.execute(
                    """
                    ALTER TABLE scan_results
                    ADD COLUMN IF NOT EXISTS user_email TEXT
                    """
                )
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS payment_events (
                        id SERIAL PRIMARY KEY,
                        stripe_event_id TEXT UNIQUE NOT NULL,
                        event_type TEXT NOT NULL,
                        event_json JSONB NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        email TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL,
                        plan TEXT NOT NULL DEFAULT 'free',
                        plan_expires_at TIMESTAMPTZ,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
                cursor.execute(
                    """
                    ALTER TABLE users
                    ADD COLUMN IF NOT EXISTS plan_expires_at TIMESTAMPTZ
                    """
                )
            conn.commit()
        return

    with _sqlite_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_email TEXT,
                target TEXT NOT NULL,
                hostname TEXT,
                status_code INTEGER,
                issue_count INTEGER NOT NULL DEFAULT 0,
                result_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        _sqlite_add_column_if_missing(conn, "scan_results", "user_email", "TEXT")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS payment_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stripe_event_id TEXT UNIQUE NOT NULL,
                event_type TEXT NOT NULL,
                event_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                plan TEXT NOT NULL DEFAULT 'free',
                plan_expires_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        _sqlite_add_column_if_missing(conn, "users", "plan_expires_at", "TEXT")
        conn.commit()


def create_user(email: str, password_hash: str) -> dict:
    normalized_email = _normalize_email(email)

    if _using_postgres():
        with _postgres_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO users (email, password, plan_expires_at)
                    VALUES (%s, %s, %s)
                    RETURNING id, email, plan, plan_expires_at, created_at
                    """,
                    (normalized_email, password_hash, None),
                )
                row = cursor.fetchone()
            conn.commit()

        return _format_user(row[0], row[1], None, row[2], row[3], row[4])

    with _sqlite_connection() as conn:
        cursor = conn.execute(
            "INSERT INTO users (email, password, plan_expires_at) VALUES (?, ?, ?)",
            (normalized_email, password_hash, None),
        )
        conn.commit()
        row = conn.execute(
            """
            SELECT id, email, password, plan, plan_expires_at, created_at
            FROM users
            WHERE id = ?
            """,
            (cursor.lastrowid,),
        ).fetchone()

    return _format_user(
        row["id"],
        row["email"],
        row["password"],
        row["plan"],
        row["plan_expires_at"],
        row["created_at"],
    )


def get_user_by_email(email: str) -> dict | None:
    normalized_email = _normalize_email(email)

    if _using_postgres():
        with _postgres_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT id, email, password, plan, plan_expires_at, created_at
                    FROM users
                    WHERE email = %s
                    """,
                    (normalized_email,),
                )
                row = cursor.fetchone()

        if not row:
            return None

        return _format_user(row[0], row[1], row[2], row[3], row[4], row[5])

    with _sqlite_connection() as conn:
        row = conn.execute(
            """
            SELECT id, email, password, plan, plan_expires_at, created_at
            FROM users
            WHERE email = ?
            """,
            (normalized_email,),
        ).fetchone()

    if not row:
        return None

    return _format_user(
        row["id"],
        row["email"],
        row["password"],
        row["plan"],
        row["plan_expires_at"],
        row["created_at"],
    )


def update_user_plan(email: str, plan: str, days: int | None = None) -> bool:
    normalized_email = _normalize_email(email)
    expires_at = _future_datetime(days) if days else None

    if _using_postgres():
        with _postgres_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE users
                    SET plan = %s, plan_expires_at = %s
                    WHERE email = %s
                    """,
                    (plan, expires_at, normalized_email),
                )
                updated = cursor.rowcount > 0
            conn.commit()
        return updated

    with _sqlite_connection() as conn:
        cursor = conn.execute(
            """
            UPDATE users
            SET plan = ?, plan_expires_at = ?
            WHERE email = ?
            """,
            (plan, _format_datetime(expires_at) if expires_at else None, normalized_email),
        )
        conn.commit()

    return cursor.rowcount > 0


def downgrade_expired_plan(user: dict) -> dict:
    if user["plan"] == "free":
        return user

    if not user.get("plan_expires_at"):
        update_user_plan(user["email"], "free")
        refreshed = get_user_by_email(user["email"])
        return refreshed or user

    expires_at = _parse_datetime(user["plan_expires_at"])
    if expires_at and expires_at < datetime.now(timezone.utc):
        update_user_plan(user["email"], "free")
        refreshed = get_user_by_email(user["email"])
        return refreshed or user

    return user


def save_scan_result(
    result: dict,
    fallback_target: str,
    user_email: str | None = None,
) -> dict:
    target = result.get("target") or fallback_target
    hostname = result.get("hostname")
    status_code = result.get("status_code")
    issue_count = len(result.get("issues") or [])
    result_json = json.dumps(result)
    normalized_email = _normalize_email(user_email) if user_email else None

    if _using_postgres():
        with _postgres_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO scan_results
                        (user_email, target, hostname, status_code, issue_count, result_json)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING id, created_at
                    """,
                    (
                        normalized_email,
                        target,
                        hostname,
                        status_code,
                        issue_count,
                        result_json,
                    ),
                )
                row = cursor.fetchone()
            conn.commit()

        return {"id": row[0], "created_at": _format_datetime(row[1])}

    with _sqlite_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO scan_results
                (user_email, target, hostname, status_code, issue_count, result_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                normalized_email,
                target,
                hostname,
                status_code,
                issue_count,
                result_json,
            ),
        )
        conn.commit()
        row = conn.execute(
            "SELECT id, created_at FROM scan_results WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()

    return {"id": row["id"], "created_at": row["created_at"]}


def list_scan_results(limit: int = 20, user_email: str | None = None) -> list[dict]:
    limit = max(1, min(limit, 100))
    normalized_email = _normalize_email(user_email) if user_email else None

    if _using_postgres():
        with _postgres_connection() as conn:
            with conn.cursor() as cursor:
                if normalized_email:
                    cursor.execute(
                        """
                        SELECT id, target, hostname, status_code, issue_count, created_at
                        FROM scan_results
                        WHERE user_email = %s
                        ORDER BY created_at DESC, id DESC
                        LIMIT %s
                        """,
                        (normalized_email, limit),
                    )
                else:
                    cursor.execute(
                        """
                        SELECT id, target, hostname, status_code, issue_count, created_at
                        FROM scan_results
                        ORDER BY created_at DESC, id DESC
                        LIMIT %s
                        """,
                        (limit,),
                    )
                rows = cursor.fetchall()

        return [
            {
                "id": row[0],
                "target": row[1],
                "hostname": row[2],
                "status_code": row[3],
                "issue_count": row[4],
                "created_at": _format_datetime(row[5]),
            }
            for row in rows
        ]

    with _sqlite_connection() as conn:
        if normalized_email:
            rows = conn.execute(
                """
                SELECT id, target, hostname, status_code, issue_count, created_at
                FROM scan_results
                WHERE user_email = ?
                ORDER BY created_at DESC, id DESC
                LIMIT ?
                """,
                (normalized_email, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT id, target, hostname, status_code, issue_count, created_at
                FROM scan_results
                ORDER BY created_at DESC, id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

    return [dict(row) for row in rows]


def get_scan_result(scan_id: int, user_email: str | None = None) -> dict | None:
    normalized_email = _normalize_email(user_email) if user_email else None

    if _using_postgres():
        with _postgres_connection() as conn:
            with conn.cursor() as cursor:
                if normalized_email:
                    cursor.execute(
                        """
                        SELECT id, target, hostname, status_code, issue_count,
                            result_json, created_at
                        FROM scan_results
                        WHERE id = %s AND user_email = %s
                        """,
                        (scan_id, normalized_email),
                    )
                else:
                    cursor.execute(
                        """
                        SELECT id, target, hostname, status_code, issue_count,
                            result_json, created_at
                        FROM scan_results
                        WHERE id = %s
                        """,
                        (scan_id,),
                    )
                row = cursor.fetchone()

        if not row:
            return None

        return _format_scan_detail(
            row[0], row[1], row[2], row[3], row[4], row[5], row[6]
        )

    with _sqlite_connection() as conn:
        if normalized_email:
            row = conn.execute(
                """
                SELECT id, target, hostname, status_code, issue_count, result_json,
                    created_at
                FROM scan_results
                WHERE id = ? AND user_email = ?
                """,
                (scan_id, normalized_email),
            ).fetchone()
        else:
            row = conn.execute(
                """
                SELECT id, target, hostname, status_code, issue_count, result_json,
                    created_at
                FROM scan_results
                WHERE id = ?
                """,
                (scan_id,),
            ).fetchone()

    if not row:
        return None

    return _format_scan_detail(
        row["id"],
        row["target"],
        row["hostname"],
        row["status_code"],
        row["issue_count"],
        row["result_json"],
        row["created_at"],
    )


def save_payment_event(event: dict) -> dict:
    event_id = event.get("id")
    event_type = event.get("type")

    if not event_id or not event_type:
        raise ValueError("Stripe event must include id and type")

    event_json = json.dumps(event)

    if _using_postgres():
        with _postgres_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO payment_events
                        (stripe_event_id, event_type, event_json)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (stripe_event_id) DO NOTHING
                    RETURNING id, created_at
                    """,
                    (event_id, event_type, event_json),
                )
                row = cursor.fetchone()
                if row is None:
                    cursor.execute(
                        """
                        SELECT id, created_at
                        FROM payment_events
                        WHERE stripe_event_id = %s
                        """,
                        (event_id,),
                    )
                    row = cursor.fetchone()
            conn.commit()

        return {"id": row[0], "created_at": _format_datetime(row[1])}

    with _sqlite_connection() as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO payment_events
                (stripe_event_id, event_type, event_json)
            VALUES (?, ?, ?)
            """,
            (event_id, event_type, event_json),
        )
        conn.commit()
        row = conn.execute(
            """
            SELECT id, created_at
            FROM payment_events
            WHERE stripe_event_id = ?
            """,
            (event_id,),
        ).fetchone()

    return {"id": row["id"], "created_at": row["created_at"]}


def _format_scan_detail(
    scan_id: int,
    target: str,
    hostname: str | None,
    status_code: int | None,
    issue_count: int,
    result_json: str | dict,
    created_at,
) -> dict:
    result = result_json if isinstance(result_json, dict) else json.loads(result_json)
    return {
        "id": scan_id,
        "target": target,
        "hostname": hostname,
        "status_code": status_code,
        "issue_count": issue_count,
        "created_at": _format_datetime(created_at),
        "result": result,
    }


def _format_user(
    user_id: int,
    email: str,
    password: str | None,
    plan: str,
    plan_expires_at,
    created_at,
) -> dict:
    return {
        "id": user_id,
        "email": email,
        "password": password,
        "plan": plan,
        "plan_expires_at": _format_datetime(plan_expires_at) if plan_expires_at else None,
        "created_at": _format_datetime(created_at),
    }


def _normalize_email(email: str) -> str:
    return email.strip().lower()


def _using_postgres() -> bool:
    return bool(DATABASE_URL and DATABASE_URL.startswith(("postgres://", "postgresql://")))


@contextmanager
def _postgres_connection():
    import psycopg2

    conn = psycopg2.connect(DATABASE_URL)
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def _sqlite_connection():
    conn = sqlite3.connect(SQLITE_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def _sqlite_add_column_if_missing(
    conn: sqlite3.Connection,
    table: str,
    column: str,
    column_type: str,
) -> None:
    columns = [row["name"] for row in conn.execute(f"PRAGMA table_info({table})")]
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {column_type}")


def _format_datetime(value) -> str:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    return str(value)


def _future_datetime(days: int) -> datetime:
    return datetime.now(timezone.utc) + timedelta(days=days)


def _parse_datetime(value: str | datetime | None) -> datetime | None:
    if not value:
        return None

    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value

    try:
        normalized = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)

    return parsed
