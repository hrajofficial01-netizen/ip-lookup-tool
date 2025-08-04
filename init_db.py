# init_db.py

from db import engine, Base
import models   # noqa: F401 — ensures LookupData & SearchLog are imported

def recreate_all():
    """Drop & recreate all tables from models.py."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    print("✅ All tables dropped & (re)created.")

if __name__ == "__main__":
    recreate_all()
