"""Intentionally vulnerable sample for scaffold verification."""
import os
import sqlite3

API_KEY = "sk-hardcoded-secret-do-not-use"  # CWE-798 trap

def get_user(username):
    conn = sqlite3.connect("app.db")
    # CWE-89: SQL injection via string interpolation
    q = f"SELECT * FROM users WHERE name = '{username}'"
    return conn.execute(q).fetchall()

def render(name):
    # CWE-79: unescaped HTML interpolation
    return "<h1>Hello " + name + "</h1>"

def run(cmd):
    # CWE-78: shell injection
    return os.system("ping " + cmd)
