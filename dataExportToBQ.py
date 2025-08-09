import os
import json
import psycopg2
from google.oauth2 import service_account
from google.cloud import storage, bigquery

# ---------- Google Cloud Authentication ----------
# If running outside of GCP (e.g., in Render), load creds from ENV
if os.getenv("google_service_account_json"):
    service_account_info = json.loads(os.getenv("google_service_account_json"))
    credentials = service_account.Credentials.from_service_account_info(service_account_info)
    GCP_PROJECT_ID = service_account_info["project_id"]
else:
    # If running in Cloud Functions, credentials are automatically provided
    credentials = None
    GCP_PROJECT_ID = "lookuptool-468508"

# ---------- Configurations ----------
PG_HOST = "dpg-d28d60h5pdvs738fdejg-a.singapore-postgres.render.com"
PG_PORT = 5432
PG_USER = "iplookupdb_user"
PG_PASSWORD = "KqXJnRYDvJjKVML1ImbcQAz8KyJhAMyZ"
PG_DATABASE = "iplookupdb"

GCS_BUCKET_NAME = "lookup_db"
BQ_PROJECT = GCP_PROJECT_ID
BQ_DATASET = "SOC_Data"

LOOKUP_CSV = "/tmp/lookup_data.csv"       # must use /tmp in Cloud Functions
SEARCH_LOG_CSV = "/tmp/search_log.csv"

# ---------- Functions ----------
def export_table_to_csv(table_name, csv_file):
    """Export data from Postgres table to local CSV file"""
    conn = psycopg2.connect(
        host=PG_HOST,
        port=PG_PORT,
        user=PG_USER,
        password=PG_PASSWORD,
        dbname=PG_DATABASE
    )
    cur = conn.cursor()
    with open(csv_file, 'w', encoding='utf-8') as f:
        sql = f"COPY {table_name} TO STDOUT WITH CSV HEADER"
        cur.copy_expert(sql, f)
    cur.close()
    conn.close()
    print(f"Exported {table_name} to {csv_file}")

def upload_to_gcs(local_file, bucket_name, destination_blob_name):
    """Upload a file to Google Cloud Storage"""
    storage_client = storage.Client(credentials=credentials, project=GCP_PROJECT_ID)
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(destination_blob_name)
    blob.upload_from_filename(local_file)
    print(f"Uploaded {local_file} to gs://{bucket_name}/{destination_blob_name}")

def load_csv_to_bigquery(table_name, gcs_uri):
    """Load CSV data from GCS into BigQuery table, overwriting existing data"""
    bq_client = bigquery.Client(credentials=credentials, project=BQ_PROJECT)
    table_id = f"{BQ_PROJECT}.{BQ_DATASET}.{table_name}"

    job_config = bigquery.LoadJobConfig(
        source_format=bigquery.SourceFormat.CSV,
        skip_leading_rows=1,
        write_disposition=bigquery.WriteDisposition.WRITE_TRUNCATE,  # overwrite table
        autodetect=True
    )

    load_job = bq_client.load_table_from_uri(
        gcs_uri,
        table_id,
        job_config=job_config
    )
    load_job.result()
    print(f"Loaded data into {table_id} from {gcs_uri}")

# ---------- Cloud Function entry point ----------
def main(request):
    export_table_to_csv("lookup_data", LOOKUP_CSV)
    export_table_to_csv("search_log", SEARCH_LOG_CSV)

    upload_to_gcs(LOOKUP_CSV, GCS_BUCKET_NAME, "lookup_data.csv")
    upload_to_gcs(SEARCH_LOG_CSV, GCS_BUCKET_NAME, "search_log.csv")

    load_csv_to_bigquery("lookup_data", f"gs://{GCS_BUCKET_NAME}/lookup_data.csv")
    load_csv_to_bigquery("search_log", f"gs://{GCS_BUCKET_NAME}/search_log.csv")

    return "Sync completed successfully", 200
