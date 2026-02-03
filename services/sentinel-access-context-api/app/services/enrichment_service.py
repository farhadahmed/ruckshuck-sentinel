"""
Enrichment service that orchestrates the login event enrichment pipeline.

This service:
1. Fetches login events from Google Workspace
2. Extracts unique IPs
3. Enriches each IP with VPN/geo data
4. Joins enriched data back to login events
"""

from typing import Dict, Any, List, Optional
from app.connectors.google_workspace import fetch_login_events
from app.connectors.vpn_api import enrich_ip


def enrich_login_events(
    service_account_json: Dict[str, Any],
    delegated_admin_email: str,
    start_date: str,
    end_date: Optional[str],
    vpn_api_key: str,
) -> List[Dict[str, Any]]:
    """
    Fetch and enrich Google Workspace login events with IP intelligence.

    This function orchestrates the full enrichment pipeline:
    1. Fetches login events from Google Workspace
    2. Extracts unique IP addresses
    3. Enriches each IP with VPN/geo/network data
    4. Joins enriched data back to original events

    Args:
        service_account_json: Google service account credentials as a dict
        delegated_admin_email: Admin email for domain-wide delegation
        start_date: Start date in RFC 3339 format (e.g., "2024-01-01T00:00:00Z")
        end_date: Optional end date in RFC 3339 format
        vpn_api_key: vpnapi.io API key

    Returns:
        List of enriched login event dictionaries with fields:
        - timestamp: ISO 8601 timestamp
        - user: User email
        - ip: Source IP address
        - login_type: Type of login
        - is_suspicious: Google's suspicious flag
        - description: Event description
        - vpn: VPN detection flag
        - proxy: Proxy detection flag
        - tor: Tor detection flag
        - relay: Relay detection flag
        - city: City name
        - region: Region/state
        - country: Country
        - continent: Continent
        - latitude: Latitude
        - longitude: Longitude
        - asn: Autonomous System Number
        - aso: Autonomous System Organization

    Raises:
        ValueError: If required parameters are missing
        Exception: If API requests fail
    """
    # Step 1: Fetch login events from Google Workspace
    print(f"Fetching login events from {start_date} to {end_date or 'now'}...")
    login_events = fetch_login_events(
        service_account_json,
        delegated_admin_email,
        start_date,
        end_date,
    )
    print(f"✓ Fetched {len(login_events)} login event(s)")

    if not login_events:
        print("No events to enrich")
        return []

    # Step 2: Extract unique IP addresses
    unique_ips = {event["ip"] for event in login_events}
    print(f"Found {len(unique_ips)} unique IP address(es)")

    # Step 3: Enrich each IP with VPN/geo data
    print("Enriching IP addresses...")
    ip_enrichment_lookup: Dict[str, Dict[str, Any]] = {}

    for ip in unique_ips:
        enrichment_data = enrich_ip(ip, vpn_api_key)
        if enrichment_data:
            ip_enrichment_lookup[ip] = enrichment_data

    print(f"✓ Enriched {len(ip_enrichment_lookup)}/{len(unique_ips)} IP(s)")

    # Step 4: Join enriched data back to login events
    enriched_events = []
    for event in login_events:
        # Start with original event data
        enriched_event = event.copy()

        # Get enrichment data for this IP
        ip_data = ip_enrichment_lookup.get(event["ip"], {})

        # Add VPN/geo fields (use None if not available)
        enriched_event["vpn"] = ip_data.get("vpn")
        enriched_event["proxy"] = ip_data.get("proxy")
        enriched_event["tor"] = ip_data.get("tor")
        enriched_event["relay"] = ip_data.get("relay")
        enriched_event["city"] = ip_data.get("city")
        enriched_event["region"] = ip_data.get("region")
        enriched_event["country"] = ip_data.get("country")
        enriched_event["continent"] = ip_data.get("continent")
        enriched_event["latitude"] = ip_data.get("latitude")
        enriched_event["longitude"] = ip_data.get("longitude")
        enriched_event["asn"] = ip_data.get("asn")
        enriched_event["aso"] = ip_data.get("aso")

        enriched_events.append(enriched_event)

    print(f"✓ Enrichment complete - {len(enriched_events)} event(s) ready")
    return enriched_events
