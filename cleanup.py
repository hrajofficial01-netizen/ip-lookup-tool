from datetime import datetime, timedelta
import pytz
import logging
import sys
from db import SessionLocal
from models import LookupData

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

def purge_expired_lookup_data(ttl_hours=48, dry_run=False):
    """
    Delete records from lookup_data older than ttl_hours.
    Works with PostgreSQL when created_at is TIMESTAMPTZ (timezone-aware).
    """
    session = SessionLocal()
    try:
        # Calculate cutoff timestamp in UTC
        expiry_cutoff = datetime.now(pytz.utc) - timedelta(hours=ttl_hours)
        logging.info(f"Purging records created before: {expiry_cutoff.isoformat()}")

        # Build query for expired records
        query = session.query(LookupData).filter(
            LookupData.created_at < expiry_cutoff
        )

        if dry_run:
            count = query.count()
            logging.info(f"[Dry Run] {count} records would be deleted.")
            session.rollback()  # ensure nothing persists
            return

        # Real deletion
        deleted_count = query.delete(synchronize_session=False)
        session.commit()
        logging.info(f"Purged {deleted_count} lookup_data records older than {ttl_hours} hours.")

    except Exception as ex:
        session.rollback()
        logging.error(f"Error during purge operation: {ex}", exc_info=True)
    finally:
        session.close()

if __name__ == "__main__":
    # Command-line args: python cleanup.py dry_run=True
    dry_run_arg = any(arg.lower() == "dry_run=true" for arg in sys.argv[1:])
    purge_expired_lookup_data(dry_run=dry_run_arg)
