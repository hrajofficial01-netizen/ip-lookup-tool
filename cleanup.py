from datetime import datetime, timedelta
import pytz
from db import SessionLocal
from models import LookupData

def purge_expired_lookup_data(ttl_hours=48):
    """
    Delete records from lookup_data older than ttl_hours.
    """
    session = SessionLocal()
    try:
        # Calculate the cutoff timestamp (current UTC time minus TTL)
        expiry_cutoff = datetime.now(pytz.utc) - timedelta(hours=ttl_hours)

        # Perform a bulk delete of all records older than expiry_cutoff
        deleted_count = session.query(LookupData).filter(LookupData.created_at < expiry_cutoff).delete()
        session.commit()

        print(f"Purged {deleted_count} lookup_data records older than {ttl_hours} hours.")
    except Exception as ex:
        session.rollback()
        print(f"Error during purge operation: {ex}")
    finally:
        session.close()

if __name__ == "__main__":
    # Run the purge with default TTL (24 hours)
    purge_expired_lookup_data()
