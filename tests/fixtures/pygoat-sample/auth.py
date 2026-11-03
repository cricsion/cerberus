"""Auth sample: safe parameterized query (FP trap for CWE-89)."""
import sqlite3


def get_user_safe(username):
    conn = sqlite3.connect("app.db")
    # Safe: parameterized query, NOT vulnerable to CWE-89.
    cur = conn.execute("SELECT * FROM users WHERE name = ?", (username,))
    return cur.fetchall()
