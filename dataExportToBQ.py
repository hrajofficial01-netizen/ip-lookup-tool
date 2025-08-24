import os
import json
import psycopg2
from google.oauth2 import service_account
from google.cloud import storage, bigquery, secretmanager

# ---------- Google Cloud Authentication ----------
if os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON"):  # local / non-GCP run
    service_account_info = json.loads(os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON"))
    credentials = service_account.Credentials.from_service_account_info(service_account_info)
    GCP_PROJECT_ID = service_account_info["project_id"]
else:  # running in Cloud Functions / Cloud Run
    credentials = None
    GCP_PROJECT_ID = os.getenv("GCP_PROJECT_ID", "lookuptool-468508")

# ---------- Get Secrets Helper ----------
def get_secret(secret_id: str) -> str:
    """Fetch secret value from Google Secret Manager"""
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{GCP_PROJECT_ID}/secrets/{secret_id}/versions/latest"
    response = client.access_secret_version(request={"name": name})
    return response.payload.data.decode("UTF-8")

# ---------- Database Config ----------
DB_HOST = os.getenv("DB_HOST") or get_secret("PG_HOST")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_USER = os.getenv("DB_USER") or get_secret("PG_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD") or get_secret("PG_PASSWORD")
DB_DATABASE = os.getenv("DB_NAME") or get_secret("PG_DATABASE")

# ---------- GCS & BQ Config ----------
GCS_BUCKET_NAME = os.getenv("GCS_BUCKET_NAME", "lookup_db")
BQ_PROJECT = GCP_PROJECT_ID
BQ_DATASET = os.getenv("BQ_DATASET", "SOC_Data")

# Temp file paths for Cloud Functions (/tmp is writable)
LOOKUP_CSV = "/tmp/lookup_data.csv"
SEARCH_LOG_CSV = "/tmp/search_log.csv"
SEARCH_LOG_NEW_CSV = "/tmp/search_log_new.csv"  # New CSV for search_log_new

# ---------- Helper function to check row count ----------
def check_row_count(table_name: str) -> int:
    conn = psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        dbname=DB_DATABASE
    )
    cur = conn.cursor()
    cur.execute(f"SELECT COUNT(*) FROM {table_name}")
    count = cur.fetchone()[0]
    cur.close()
    conn.close()
    return count

# ---------- Functions ----------
def export_table_to_csv(table_name: str, csv_file: str):
    conn = psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        dbname=DB_DATABASE
    )
    cur = conn.cursor()
    with open(csv_file, 'w', encoding='utf-8') as f:
        # Modified to export data correctly from TimescaleDB hypertable
        sql = f"COPY (SELECT * FROM {table_name}) TO STDOUT WITH CSV HEADER"
        cur.copy_expert(sql, f)
    cur.close()
    conn.close()
    size = os.path.getsize(csv_file)
    print(f"Exported {table_name} to {csv_file} ({size} bytes)")

def upload_to_gcs(local_file: str, bucket_name: str, destination_blob_name: str):
    storage_client = storage.Client(credentials=credentials, project=GCP_PROJECT_ID)
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(destination_blob_name)
    blob.upload_from_filename(local_file)
    print(f"Uploaded {local_file} to gs://{bucket_name}/{destination_blob_name}")

def load_csv_to_bigquery(table_name: str, gcs_uri: str):
    bq_client = bigquery.Client(credentials=credentials, project=BQ_PROJECT)
    table_id = f"{BQ_PROJECT}.{BQ_DATASET}.{table_name}"
    job_config = bigquery.LoadJobConfig(
        source_format=bigquery.SourceFormat.CSV,
        skip_leading_rows=1,
        write_disposition=bigquery.WriteDisposition.WRITE_TRUNCATE,
        autodetect=True
    )
    load_job = bq_client.load_table_from_uri(gcs_uri, table_id, job_config=job_config)
    load_job.result()
    print(f"Loaded data into {table_id} from {gcs_uri}")

# ---------- Cloud Function Entry Point ----------
def main(request):
    """HTTP-triggered Cloud Function"""
    if request.method == "GET":
        # Health check endpoint
        return "OK", 200

    try:
        # Check data presence before export
        for tbl in ("lookup_data", "search_log", "search_log_new"):
            count = check_row_count(tbl)
            print(f"Table {tbl} has {count} rows")

        export_table_to_csv("lookup_data", LOOKUP_CSV)
        export_table_to_csv("search_log", SEARCH_LOG_CSV)
        export_table_to_csv("search_log_new", SEARCH_LOG_NEW_CSV)  # Export the new table

        upload_to_gcs(LOOKUP_CSV, GCS_BUCKET_NAME, "lookup_data.csv")
        upload_to_gcs(SEARCH_LOG_CSV, GCS_BUCKET_NAME, "search_log.csv")
        upload_to_gcs(SEARCH_LOG_NEW_CSV, GCS_BUCKET_NAME, "search_log_new.csv")  # Upload new table CSV

        load_csv_to_bigquery("lookup_data", f"gs://{GCS_BUCKET_NAME}/lookup_data.csv")
        load_csv_to_bigquery("search_log", f"gs://{GCS_BUCKET_NAME}/search_log.csv")
        load_csv_to_bigquery("search_log_new", f"gs://{GCS_BUCKET_NAME}/search_log_new.csv")  # Load new table data

        return "Sync completed successfully", 200
    except Exception as e:
        print(f"[ERROR] Sync failed: {e}")
        return f"Internal Server Error: {e}", 500
