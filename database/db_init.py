import sqlite3, os

def init_db(path="database/security.db"):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threats (
        id INTEGER PRIMARY KEY,
        timestamp TEXT,
        type TEXT,
        name TEXT,
        pid INTEGER
    )""")
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS intel (
        id INTEGER PRIMARY KEY,
        timestamp TEXT,
        source TEXT,
        title TEXT,
        link TEXT
    )""")
    conn.commit()
    return conn