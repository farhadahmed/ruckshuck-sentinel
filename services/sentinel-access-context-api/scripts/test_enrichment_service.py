"""
Test script for the full enrichment pipeline.

This tests the complete flow:
1. Fetch Google Workspace login events
2. Extract unique IPs
3. Enrich IPs with VPN/geo data
4. Return enriched events
"""

import os
import json
import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone

# Add parent directory to path so we can import app modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv
from app.services.enrichment_service import enrich_login_events

load_dotenv()


def test_full_pipeline():
    """Test the complete enrichment pipeline."""

    print("=== Testing Full Enrichment Pipeline ===\n")

    # Load credentials
    service_account_json_str = os.getenv("GOOGLE_SERVICE_ACCOUNT_KEY_JSON")
    delegated_admin_email = os.getenv("GOOGLE_DELEGATED_ADMIN_EMAIL")
    vpn_api_key = os.getenv("VPN_API_KEY")

    # Validate
    if not service_account_json_str:
        print("✗ ERROR: GOOGLE_SERVICE_ACCOUNT_KEY_JSON not found in .env")
        return False

    if not delegated_admin_email:
        print("✗ ERROR: GOOGLE_DELEGATED_ADMIN_EMAIL not found in .env")
        return False

    if not vpn_api_key:
        print("✗ ERROR: VPN_API_KEY not found in .env")
        return False

    # Parse service account JSON
    try:
        service_account_json = json.loads(service_account_json_str)
    except json.JSONDecodeError as e:
        print(f"✗ ERROR: Failed to parse service account JSON: {e}")
        return False

    # Define date range (last 100 days for testing)
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=100)
    start_date = start_time.isoformat()
    end_date = end_time.isoformat()

    print(f"Date range: {start_date} to {end_date}\n")

    # Run enrichment pipeline
    try:
        enriched_events = enrich_login_events(
            service_account_json=service_account_json,
            delegated_admin_email=delegated_admin_email,
            start_date=start_date,
            end_date=end_date,
            vpn_api_key=vpn_api_key,
        )

        print(f"\n✓ Pipeline complete!")
        print(f"Total enriched events: {len(enriched_events)}")

        # Show sample enriched event
        if enriched_events:
            print("\n--- Sample Enriched Event ---")
            sample = enriched_events[0]
            print(f"Timestamp:     {sample.get('timestamp')}")
            print(f"User:          {sample.get('user')}")
            print(f"IP:            {sample.get('ip')}")
            print(f"Login Type:    {sample.get('login_type')}")
            print(f"Is Suspicious: {sample.get('is_suspicious')}")
            print(f"VPN:           {sample.get('vpn')}")
            print(f"Proxy:         {sample.get('proxy')}")
            print(f"Location:      {sample.get('city')}, {sample.get('region')}, {sample.get('country')}")
            print(f"Continent:     {sample.get('continent')}")
            print(f"Coordinates:   {sample.get('latitude')}, {sample.get('longitude')}")
            print(f"ASN:           {sample.get('asn')}")
            print(f"ASO:           {sample.get('aso')}")

        return True

    except Exception as e:
        print(f"\n✗ ERROR: Pipeline failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_full_pipeline()
    sys.exit(0 if success else 1)
