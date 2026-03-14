import sqlite3
conn=sqlite3.connect('database.db')
cur=conn.cursor()
print('table info:')
cur.execute("PRAGMA table_info(People)")
cols=cur.fetchall()
print(len(cols))
for c in cols:
    print(c)

print('\nindex list:')
cur.execute("PRAGMA index_list('People')")
indexes = cur.fetchall()
for idx in indexes:
    print(idx)
    if idx[2]:  # unique
        cur.execute(f"PRAGMA index_info('{idx[1]}')")
        print(' columns:', cur.fetchall())
conn.close()
