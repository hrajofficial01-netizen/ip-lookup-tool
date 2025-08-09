# models.py

from sqlalchemy import Column, String, Integer, DateTime, PrimaryKeyConstraint
from sqlalchemy.sql import func
from db import Base


from sqlalchemy import Column, String, Integer, DateTime
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import JSONB  # Import JSONB type
from db import Base

class LookupData(Base):
    __tablename__ = "lookup_data"

    entry = Column(String, primary_key=True)  # IP or URL
    entry_type = Column(String, nullable=False)  # e.g. "IP" or "URL"
    isp = Column(String, nullable=True)
    asn = Column(String, nullable=True)
    country = Column(String, nullable=True)
    detection_count = Column(Integer, nullable=False, default=0)
    threat_actor = Column(String, nullable=True)  # or String if JSON not supported
    country_origin = Column(JSONB, nullable=True)
    threat_category = Column(JSONB, nullable=True)
    campaign_name = Column(String, nullable=True)
    target_sector = Column(JSONB, nullable=True)
    malware_families = Column(String, nullable=True)
    associated_ip = Column(String, nullable=True)

    # New columns added here:
    
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class SearchLog(Base):
    __tablename__ = "search_log"

    entry         = Column(String,   nullable=False)
    client_name   = Column(String,   nullable=False)
    first_searched= Column(DateTime, server_default=func.now(), nullable=False)
    last_searched = Column(DateTime, server_default=func.now(),
                                         onupdate=func.now(), nullable=False)
    lookup_count  = Column(Integer,  nullable=False, default=1)

    __table_args__ = (
        PrimaryKeyConstraint("entry", "client_name", name="pk_search_log"),
    )
