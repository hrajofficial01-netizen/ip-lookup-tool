from sqlalchemy import create_engine, MetaData, Table, select, insert
from datetime import timedelta

DATABASE_URL = "postgresql://iplookupdb_user:KqXJnRYDvJjKVML1ImbcQAz8KyJhAMyZ@dpg-d28d60h5pdvs738fdejg-a.singapore-postgres.render.com:5432/iplookupdb"

engine = create_engine(DATABASE_URL)
metadata = MetaData()

old_search_log = Table('search_log', metadata, autoload_with=engine)
new_search_log = Table('search_log_new', metadata, autoload_with=engine)

with engine.connect() as conn:
    with conn.begin():  # Begin a transaction to ensure commit
        rows = conn.execute(select(
            old_search_log.c.entry,
            old_search_log.c.client_name,
            old_search_log.c.first_searched,
            old_search_log.c.last_searched,
            old_search_log.c.lookup_count
        )).fetchall()

        all_inserts = []
        for row in rows:
            print(f"Processing entry={row.entry}, client={row.client_name}, first_searched={row.first_searched}, last_searched={row.last_searched}, lookup_count={row.lookup_count}")
            entry = row.entry
            client_name = row.client_name
            first_searched = row.first_searched
            last_searched = row.last_searched or first_searched
            count = row.lookup_count if row.lookup_count and row.lookup_count > 1 else 2

            if not first_searched:
                print("Skipped row due to missing first_searched timestamp.")
                continue  # Skip rows without a timestamp

            interval = (last_searched - first_searched) / (count - 1) if count > 1 else timedelta(0)

            for i in range(count):
                searched_at = first_searched + interval * i
                all_inserts.append({
                    'entry': entry,
                    'client_name': client_name,
                    'searched_at': searched_at
                })

        if all_inserts:
            print(f"Inserting {len(all_inserts)} rows into search_log_new.")
            conn.execute(new_search_log.insert(), all_inserts)
        else:
            print("No rows to insert.")

print("Data migration completed.")