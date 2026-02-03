"""
Test script for Google Workspace connector authentication.

This script verifies that the connector can:
1. Load service account credentials from .env
2. Build an authenticated Google Admin Reports API service
3. Make a simple API call to verify access
"""

import os
import json
import sys
from pathlib import Path

# Add parent directory to path so we can import app modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
from app.connectors.google_workspace import build_admin_service, fetch_login_events

load_dotenv()


def test_authentication():
    """Test Google Workspace connector authentication."""

    print("=== Testing Google Workspace Connector ===\n")

    # Load credentials from environment
    service_account_json_str = os.getenv("GOOGLE_SERVICE_ACCOUNT_KEY_JSON")
    delegated_admin_email = os.getenv("GOOGLE_DELEGATED_ADMIN_EMAIL")

    # Validate environment variables
    if not service_account_json_str:
        print("✗ ERROR: GOOGLE_SERVICE_ACCOUNT_KEY_JSON not found in .env")
        return False

    if not delegated_admin_email:
        print("✗ ERROR: GOOGLE_DELEGATED_ADMIN_EMAIL not found in .env")
        return False

    print(f"Delegated admin email: {delegated_admin_email}")

    # Parse JSON string into dict
    try:
        service_account_json = json.loads(service_account_json_str)
        print("✓ Parsed service account JSON from environment")
    except json.JSONDecodeError as e:
        print(f"✗ ERROR: Failed to parse GOOGLE_SERVICE_ACCOUNT_KEY_JSON: {e}")
        return False

    # Build authenticated service
    print("\nBuilding Google Admin Reports API service...")
    try:
        service = build_admin_service(service_account_json, delegated_admin_email)
        print("✓ Service created successfully")
    except Exception as e:
        print(f"✗ ERROR: Failed to build service: {e}")
        return False

    # Test API access with minimal query
    print("\nTesting API access with minimal query...")
    try:
        request = service.activities().list(
            userKey="all",
            applicationName="login",
            maxResults=1
        )
        response = request.execute()

        items = response.get("items", [])
        print(f"✓ API call successful - received {len(items)} login event(s)")

        if items:
            print(f"  Sample event: {items[0].get('id', {}).get('time')} - {items[0].get('actor', {}).get('email')}")

    except Exception as e:
        print(f"✗ ERROR: API call failed: {e}")
        return False

    print("\n=== All tests passed ===")
    return True


def test_fetch_login_events():
    """Test fetching login events for a date range."""

    print("\n=== Testing Login Event Fetching ===\n")

    # Load credentials
    service_account_json_str = os.getenv("GOOGLE_SERVICE_ACCOUNT_KEY_JSON")
    delegated_admin_email = os.getenv("GOOGLE_DELEGATED_ADMIN_EMAIL")

    if not service_account_json_str or not delegated_admin_email:
        print("✗ ERROR: Missing credentials in .env")
        return False

    try:
        service_account_json = json.loads(service_account_json_str)
    except json.JSONDecodeError as e:
        print(f"✗ ERROR: Failed to parse service account JSON: {e}")
        return False

    # Define date range (last 100 days)
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=100)

    start_date = start_time.isoformat()
    end_date = end_time.isoformat()

    print(f"Fetching login events from {start_date} to {end_date}...")

    # Fetch events
    try:
        events = fetch_login_events(
            service_account_json,
            delegated_admin_email,
            start_date,
            end_date
        )
        print(f"✓ Successfully fetched {len(events)} login event(s)")

        # Show sample events
        if events:
            print("\nSample events (first 3):")
            for event in events[:3]:
                print(f"  - {event['timestamp']} | {event['user']} | {event['ip']} | {event['login_type']}")
        else:
            print("  (No events found in this date range)")

        return True

    except Exception as e:
        print(f"✗ ERROR: Failed to fetch events: {e}")
        return False


if __name__ == "__main__":
    # Test 1: Authentication
    auth_success = test_authentication()

    if not auth_success:
        sys.exit(1)

    # Test 2: Fetch login events
    fetch_success = test_fetch_login_events()

    sys.exit(0 if fetch_success else 1)
