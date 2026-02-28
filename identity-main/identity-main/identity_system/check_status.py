from app import get_db_connection

conn = get_db_connection()
cur = conn.cursor()
cur.execute("SELECT id, type, first_name, last_name, status, status_changed_at FROM People LIMIT 1")
person = cur.fetchone()
if person:
    print("ID:", person['id'])
    print("Type:", person['type'])
    print("Name:", person['first_name'], person['last_name'])
    print("Status:", person['status'])
    print("Status Changed At:", person['status_changed_at'])
else:
    print("No records found")
conn.close()
