import os, sys, sqlite3

# ensure path
sys.path.insert(0, os.path.join(os.getcwd(), 'identity-main', 'identity-main', 'identity_system'))
from app import init_db, get_db_connection

# remove any existing database to start fresh
dbfile = 'database.db'
if os.path.exists(dbfile):
    os.remove(dbfile)

init_db()
conn = get_db_connection()
cur = conn.cursor()

cur.execute("INSERT INTO People (id,type,sub_category,first_name,last_name,dob,email,phone,status,status_changed_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            ('A1','Student','Undergraduate','T','S','2000-01-01','dup@example.com','1','Pending','2024-01-01'))
conn.commit()
print('first insert done')

try:
    cur.execute("INSERT INTO People (id,type,sub_category,first_name,last_name,dob,email,phone,status,status_changed_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                ('A2','Faculty','Tenured','F','P','1980-02-02','dup@example.com','2','Pending','2024-01-01'))
    conn.commit()
    print('second insert succeeded, duplicates allowed')
except Exception as e:
    print('second insert failed:', e)

cur.execute("PRAGMA index_list('People')")
print('indexes after inserts:', cur.fetchall())
conn.close()
