import sqlite3

def create_or_connect_db(filename):
    conn = sqlite3.connect(filename)
    # Create table if it doesn't exist:
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS rusthole_analytics (
                        id INTEGER PRIMARY KEY,
                        blocked_site TEXT NOT NULL UNIQUE,
                        count INTEGER DEFAULT "1" NOT NULL
                    )''')
    cursor.close()
    conn.close()

def insert_or_update_db(filename, data):
    conn = sqlite3.connect(filename)
    cursor = conn.cursor()

    cursor.execute('''
                   INSERT INTO
                    RUSTHOLE_ANALYTICS
                    (blocked_site)
                   VALUES
                    (?)
                   ON CONFLICT(blocked_site) do UPDATE SET
                    count = count + 1
                   ''',
                   (data,))
    conn.commit()
    cursor.execute('select * from RUSTHOLE_ANALYTICS')
    for row in cursor.fetchall():
        print(row)
    cursor.close()
    conn.close()