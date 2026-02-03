"""
Test script for VPN API connector.

This script tests IP enrichment using vpnapi.io.
"""

import os
import sys
from pathlib import Path

# Add parent directory to path so we can import app modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv
from app.connectors.vpn_api import enrich_ip

load_dotenv()


def test_ip_enrichment():
    """Test IP enrichment with a sample public IP."""

    print("=== Testing VPN API Connector ===\n")

    # Load API key
    api_key = os.getenv("VPN_API_KEY")

    if not api_key:
        print("✗ ERROR: VPN_API_KEY not found in .env")
        return False

    # Test with a well-known public IP (Google DNS)
    test_ip = "8.8.8.8"
    print(f"Testing IP enrichment for: {test_ip}")

    # Enrich IP
    try:
        result = enrich_ip(test_ip, api_key)

        if result:
            print(f"✓ Successfully enriched IP: {test_ip}\n")
            print("Enrichment data:")
            print(f"  IP:        {result.get('ip')}")
            print(f"  VPN:       {result.get('vpn')}")
            print(f"  Proxy:     {result.get('proxy')}")
            print(f"  Tor:       {result.get('tor')}")
            print(f"  Location:  {result.get('city')}, {result.get('region')}, {result.get('country')}")
            print(f"  Continent: {result.get('continent')}")
            print(f"  Coords:    {result.get('latitude')}, {result.get('longitude')}")
            print(f"  ASN:       {result.get('asn')}")
            print(f"  ASO:       {result.get('aso')}")
            return True
        else:
            print("✗ ERROR: Failed to enrich IP (returned None)")
            return False

    except Exception as e:
        print(f"✗ ERROR: {e}")
        return False


if __name__ == "__main__":
    success = test_ip_enrichment()
    sys.exit(0 if success else 1)
