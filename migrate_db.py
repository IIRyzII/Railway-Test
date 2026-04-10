"""
One-time migration script — adds missing columns to an existing database.
Run this ONCE from the same folder as App.py:
    python migrate_db.py
"""
import sqlite3
import os

DB_PATH = os.path.join("instance", "secure_future.db")

if not os.path.exists(DB_PATH):
    print("❌ Database not found at", DB_PATH)
    print("   Run create_admin.py instead to create a fresh one.")
    exit(1)

conn = sqlite3.connect(DB_PATH)
cur  = conn.cursor()

# ── Helper ────────────────────────────────────────────────────────────────────
def column_exists(table, column):
    cur.execute(f"PRAGMA table_info({table})")
    return any(row[1] == column for row in cur.fetchall())

def table_exists(table):
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,))
    return cur.fetchone() is not None

changes = []

# ── user table ────────────────────────────────────────────────────────────────
if not column_exists("user", "totp_secret"):
    cur.execute("ALTER TABLE user ADD COLUMN totp_secret VARCHAR(32)")
    changes.append("user.totp_secret")

# ── login_log table ───────────────────────────────────────────────────────────
if not table_exists("login_log"):
    cur.execute("""
        CREATE TABLE login_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            username        VARCHAR(64)  NOT NULL,
            ip_address      VARCHAR(45)  NOT NULL,
            success         BOOLEAN      NOT NULL,
            role            VARCHAR(20),
            sql_flagged     BOOLEAN      NOT NULL DEFAULT 0,
            flagged_fields  VARCHAR(255)
        )
    """)
    changes.append("login_log table")

# ── invitation table ──────────────────────────────────────────────────────────
if not table_exists("invitation"):
    cur.execute("""
        CREATE TABLE invitation (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            token       VARCHAR(64)  UNIQUE NOT NULL,
            email       VARCHAR(120) NOT NULL,
            role        VARCHAR(20)  NOT NULL DEFAULT 'employee',
            created_by  INTEGER      NOT NULL REFERENCES user(id),
            created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at  DATETIME     NOT NULL,
            used        BOOLEAN      NOT NULL DEFAULT 0
        )
    """)
    changes.append("invitation table")

conn.commit()
conn.close()

if changes:
    print("✅ Migration complete. Changes applied:")
    for c in changes:
        print("   +", c)
else:
    print("✅ Database already up to date — no changes needed.")

print()
print("You can now run:  python App.py")
