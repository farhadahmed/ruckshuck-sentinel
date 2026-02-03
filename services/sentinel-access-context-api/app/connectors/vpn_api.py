"""
VPN API connector for IP enrichment.

This module calls vpnapi.io to enrich IP addresses with:
- Security flags (VPN, proxy, tor, relay)
- Geolocation (city, region, country, continent, coordinates)
- Network info (ASN, ASO)
"""

from typing import Dict, Any, Optional
import requests


def enrich_ip(ip_address: str, api_key: str) -> Optional[Dict[str, Any]]:
    """
    Enrich an IP address with VPN, geolocation, and network data.

    Args:
        ip_address: IP address to enrich (e.g., "203.0.113.42")
        api_key: vpnapi.io API key

    Returns:
        Dict with enrichment data:
        - ip: The IP address
        - vpn: Boolean - is VPN
        - proxy: Boolean - is proxy
        - tor: Boolean - is Tor exit node
        - relay: Boolean - is relay
        - city: City name
        - region: Region/state name
        - country: Country name
        - continent: Continent name
        - latitude: Latitude coordinate
        - longitude: Longitude coordinate
        - asn: Autonomous System Number
        - aso: Autonomous System Organization

        Returns None if API call fails or IP is invalid.

    Raises:
        ValueError: If api_key is missing
    """
    if not api_key:
        raise ValueError("VPN API key is required")

    url = f"https://vpnapi.io/api/{ip_address}?key={api_key}"

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()

        # Flatten nested JSON structure into flat dict
        return {
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

    except requests.exceptions.RequestException as e:
        # Log error but return None instead of raising
        print(f"Warning: Failed to enrich IP {ip_address}: {e}")
        return None
    except Exception as e:
        print(f"Warning: Unexpected error enriching IP {ip_address}: {e}")
        return None
