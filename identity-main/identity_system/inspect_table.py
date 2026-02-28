import sqlite3
conn=sqlite3.connect('database.db')
cur=conn.cursor()
cur.execute("PRAGMA table_info(People)")
cols=cur.fetchall()
print(len(cols))
for c in cols:
    print(c)
conn.close()
