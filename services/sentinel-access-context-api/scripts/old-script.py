import requests
import csv
import time
from datetime import datetime, timedelta, timezone
import os
import json
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from dotenv import load_dotenv  # only for local dev, not needed in GCP Cloud Functions

load_dotenv()

# ========= CONFIG =========

# API keys
VPN_API_KEY = os.getenv("VPN_ACCESS_KEY")


# File paths
INPUT_CSV = "logins.csv"
VPN_RESULTS_CSV = "vpnapi_results.csv"
ENRICHED_OUTPUT_CSV = "logins_enriched.csv"


# ========= Generate logins.csv if .env contains GOOGLE_SERVICE_ACCOUNT_KEY_JSON =========

def generate_logins_csv_from_env(): 
    """Generates logins.csv from Google Sheets if service account key is provided."""
    # Time window for events (change as needed)
    DAYS_BACK = 30
    # Output CSV file
    OUTPUT_CSV = "logins.csv"

    delegated_admin_email = os.getenv("GOOGLE_DELEGATED_ADMIN_EMAIL")  # set this in env vars
    # If no delegated admin email is provided, skip this function and assume logins.csv already exists
    if not delegated_admin_email:
        print("GOOGLE_DELEGATED_ADMIN_EMAIL not set; skipping generation of logins.csv.")
        return


    # ======== HELPER: SET UP GOOGLE REPORTS API SERVICE USING JSON FROM .ENV =========
    def get_google_reports_service(): 
        """Sets up Google Admin Reports API service with delegated credentials."""
        SCOPES = ["https://www.googleapis.com/auth/admin.reports.audit.readonly"]
        
    
        key_json_str = os.getenv("GOOGLE_SERVICE_ACCOUNT_KEY_JSON")
        if not key_json_str:
            raise ValueError("Missing GOOGLE_SERVICE_ACCOUNT_KEY in environment variables.")
    
        # Parse JSON from env var into a dict
        key_data = json.loads(key_json_str)

        creds = service_account.Credentials.from_service_account_info(
            key_data,
            scopes=SCOPES,
        )

        delegated_creds = creds.with_subject(delegated_admin_email)

        service = build("admin", "reports_v1", credentials=delegated_creds)
        return service
    

    # ======== HELPER: EXTRACT LOGIN RECORD FROM A GIVEN ACTIVITY =========
    def extract_login_record(activity):
        """Extracts timestamp, userEmail, userIp, loginType, isSuspicious from an activity."""
        # Basic structures
        activity_id = activity.get("id", {}) or {}
        actor_info = activity.get("actor", {}) or {}

        timestamp = activity_id.get("time")
        user_email = actor_info.get("email")
        user_ip = activity.get("ipAddress")

        # Events array (usually one main event for logins)
        events = activity.get("events", []) or []
        if not events:
            return None
        
        primary_event = events[0]
        event_type = primary_event.get("type")  # e.g. "login"
        parameters = primary_event.get("parameters", []) or []

        # Defaults
        login_type = "unknown"
        is_suspicious = False

        # Walk parameters and pull what we need by name
        for param in parameters:
            name = param.get("name")
            if name == "login_type":
                value = param.get("value")
                if value:
                    login_type = value
            elif name == "is_suspicious":
                if "boolValue" in param:
                    is_suspicious = bool(param["boolValue"])
                elif "value" in param:
                    val = str(param["value"]).lower()
                    is_suspicious = (val == "true")

        # Description: userEmail + event type (if available)
        if user_email and event_type:
            description = f"{user_email} {event_type}"
        else:
            description = user_email or ""

        # Enforce required fields
        if not timestamp or not user_email or not user_ip:
            return None
        
        return {
            "timestamp": timestamp,
            "userEmail": user_email,
            "userIp": user_ip,
            "loginType": login_type,
            "isSuspicious": is_suspicious,
            "description": description,
        }



    # ======== FETCH LOGIN EVENTS FROM GOOGLE WORKSPACE ADMIN REPORTS API =========
    def fetch_user_login_events():
        """Fetches user login events from Google Workspace Admin Reports API."""
        service = get_google_reports_service()
        login_event_records = []

        # Calculate time window
        now = datetime.now(timezone.utc)
        start_time = (now - timedelta(days=DAYS_BACK)).isoformat()

        print(f"Requesting login events since {start_time} ...")

        # Initial request
        try:
            request = service.activities().list(
                userKey="all",
                applicationName="login",
                startTime=start_time,
                maxResults=1000,
            )
        except HttpError as e:
            print("HTTP error from Google API when making initial request to Google Admin Reports API:")
            print(e)
            return {}

        # Execute first page
        try:
            response = request.execute()
        except HttpError as e:
            print("HTTP error from Google API on first page fetch:")
            print(e)
            return {}
        
        # Process first page
        items = response.get("items", [])
    
        # Extract records from first page
        for activity in items:
            login_event_records.append(extract_login_record(activity))

        # Pagination loop
        while True:
            try:
                request = service.activities().list_next(
                previous_request=request,
                previous_response=response
            )
            except HttpError as e:
                print("HTTP error during pagination (list_next):")
                print(e)
                break

            # break if no more pages
            if request is None:
                break

            try:
                response = request.execute()
            except HttpError as e:
                print("HTTP error fetching a subsequent page:")
                print(e)
                break

            # Extract records from each subsequent page
            for activity in items:
                login_event_records.append(extract_login_record(activity))
        
        return login_event_records


    # ======== WRITE EVENTS TO CSV =========
    def write_events_to_csv(login_event_records, output_csv_path):
        """
        Writes one row per user in the format:
        Timestamp, User Email, IP Address, Description, Login Type, Is Suspicious
        """

        # Build dynamic header
        header = [
            "Timestamp",
            "User",
            "IP address",
            "Description",
            "Login Type",
            "Is Suspicious"
        ]

        with open(output_csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=header)
            writer.writeheader()

            for record in login_event_records:
                if record is None:
                    continue

                writer.writerow({
                    "Timestamp": record["timestamp"],
                    "User": record["userEmail"],
                    "IP address": record["userIp"],
                    "Description": record["description"],
                    "Login Type": record["loginType"],
                    "Is Suspicious": record["isSuspicious"],
                })
            
        print(f"Login events written to {output_csv_path}")
    
    extracted_records = fetch_user_login_events()
    write_events_to_csv(extracted_records, OUTPUT_CSV)












# ========= HELPER: GET UNIQUE IPS =========

def get_ips_from_csv(logins_csv_path: str):
    """
    Reads a CSV file with a column named 'IP address'
    and returns a set of unique IP addresses.
    """
    unique_ips = set()

    with open(logins_csv_path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)

        if "IP address" not in reader.fieldnames:
            raise ValueError(
                f"CSV does not contain a column named 'IP address'. "
                f"Columns found: {reader.fieldnames}"
            )

        for row in reader:
            ip = row.get("IP address")
            if ip:
                unique_ips.add(ip)

    return unique_ips


# ========= HELPER: CALL VPN API =========

def fetch_ip_info(ip):
    """Fetch information for a single IP from vpnapi.io."""
    url = f"https://vpnapi.io/api/{ip}?key={VPN_API_KEY}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Error retrieving {ip}: {e}")
        return None


# ========= HELPER: LOAD VPN RESULTS AS LOOKUP =========

def load_vpn_results_as_lookup(results_csv_path: str):
    """
    Reads vpnapi_results.csv and returns a dict mapping:
        ip -> row_dict (vpn/proxy/tor/... fields)
    """
    lookup = {}

    with open(results_csv_path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)

        for row in reader:
            ip = row.get("ip")
            if ip:
                lookup[ip] = row  # last one wins, which is fine here

    return lookup


# ========= STEP 1: FETCH VPN DATA AND WRITE vpnapi_results.csv =========

def build_vpn_results():
    # Columns for the vpnapi_results.csv file
    fieldnames = [
        "ip",
        "vpn",
        "proxy",
        "tor",
        "relay",
        "city",
        "region",
        "country",
        "continent",
        "latitude",
        "longitude",
        "asn",
        "aso"
    ]

    with open(VPN_RESULTS_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        ip_addresses = get_ips_from_csv(INPUT_CSV)

        for ip in ip_addresses:
            print(f"Querying {ip} ...")
            data = fetch_ip_info(ip)
            if not data:
                continue

            # Flatten JSON for CSV
            row = {
                "ip": data.get("ip"),
                "vpn": data.get("security", {}).get("vpn"),
                "proxy": data.get("security", {}).get("proxy"),
                "tor": data.get("security", {}).get("tor"),
                "relay": data.get("security", {}).get("relay"),
                "city": data.get("location", {}).get("city"),
                "region": data.get("location", {}).get("region"),
                "country": data.get("location", {}).get("country"),
                "continent": data.get("location", {}).get("continent"),
                "latitude": data.get("location", {}).get("latitude"),
                "longitude": data.get("location", {}).get("longitude"),
                "asn": data.get("network", {}).get("autonomous_system_number"),
                "aso": data.get("network", {}).get("autonomous_system_organization"),
            }

            writer.writerow(row)

            # Be polite — avoid hammering the API too fast
            time.sleep(0.3)

    print(f"VPN results saved to {VPN_RESULTS_CSV}")


# ========= STEP 2: JOIN vpnapi_results.csv BACK ONTO logins.csv =========

def enrich_logins_with_vpn_data():
    """
    Reads:
        - logins.csv (original login events)
        - vpnapi_results.csv (per-IP VPN info)

    Writes:
        - logins_enriched.csv (original columns + VPN/IP info per row)
    """
    # Load VPN results into a lookup: ip -> vpn_row
    vpn_lookup = load_vpn_results_as_lookup(VPN_RESULTS_CSV)

    with open(INPUT_CSV, newline='', encoding='utf-8') as in_f:
        reader = csv.DictReader(in_f)
        login_fieldnames = reader.fieldnames or []

        # These are the columns from the vpn results (except 'ip' which
        # we already effectively have as 'IP address' in the logins file)
        vpn_fieldnames = [
            "vpn",
            "proxy",
            "tor",
            "relay",
            "city",
            "region",
            "country",
            "continent",
            "latitude",
            "longitude",
            "asn",
            "aso"
        ]

        # Combined header: original login columns + appended VPN columns
        combined_fieldnames = login_fieldnames + vpn_fieldnames

        with open(ENRICHED_OUTPUT_CSV, "w", newline="", encoding="utf-8") as out_f:
            writer = csv.DictWriter(out_f, fieldnames=combined_fieldnames)
            writer.writeheader()

            for row in reader:
                ip = row.get("IP address")

                # Get VPN info by IP, or empty dict if not found
                vpn_row = vpn_lookup.get(ip, {})

                # Start with original row, then append VPN fields
                enriched_row = row.copy()
                for col in vpn_fieldnames:
                    enriched_row[col] = vpn_row.get(col)

                writer.writerow(enriched_row)

    print(f"Enriched login data saved to {ENRICHED_OUTPUT_CSV}")


# ========= MAIN =========

def main():
    generate_logins_csv_from_env()
    build_vpn_results()
    enrich_logins_with_vpn_data()


if __name__ == "__main__":
    main()
