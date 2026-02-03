"""
Google Workspace connector for fetching login audit events.
"""

from typing import Dict, Any, List, Optional
from google.oauth2 import service_account
from googleapiclient.discovery import build


SCOPES = ["https://www.googleapis.com/auth/admin.reports.audit.readonly"]


def build_admin_service(
    service_account_json: Dict[str, Any],
    delegated_admin_email: str
):
    """
    Build authenticated Google Admin Reports API service.

    Args:
        service_account_json: Google service account credentials as a dict
        delegated_admin_email: Admin email for domain-wide delegation

    Returns:
        Authenticated Google Admin Reports API service client

    Raises:
        ValueError: If required parameters are missing
    """
    if not service_account_json:
        raise ValueError("Service account JSON is required")
    if not delegated_admin_email:
        raise ValueError("Delegated admin email is required")

    # Create credentials from service account
    creds = service_account.Credentials.from_service_account_info(
        service_account_json,
        scopes=SCOPES,
    )

    # Delegate to admin user
    delegated_creds = creds.with_subject(delegated_admin_email)

    # Build and return API service
    return build(
        "admin",
        "reports_v1",
        credentials=delegated_creds,
        cache_discovery=False,  # Avoid filesystem writes in containers/Cloud Run
    )


def fetch_login_events(
    service_account_json: Dict[str, Any],
    delegated_admin_email: str,
    start_date: str,
    end_date: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Fetch Google Workspace login events for a date range.

    Args:
        service_account_json: Google service account credentials as a dict
        delegated_admin_email: Admin email for domain-wide delegation
        start_date: Start date in RFC 3339 format (e.g., "2024-01-01T00:00:00Z")
        end_date: Optional end date in RFC 3339 format (defaults to current time)

    Returns:
        List of login event dictionaries with fields:
        - timestamp: ISO 8601 timestamp string
        - user: User email address
        - ip: Source IP address
        - login_type: Type of login (e.g., "exchange", "saml", "google_password")
        - is_suspicious: Boolean indicating if Google flagged as suspicious
        - description: Human-readable description of the event

    Raises:
        ValueError: If required parameters are missing
        Exception: If API request fails
    """
    service = build_admin_service(service_account_json, delegated_admin_email)
    login_events = []

    # Build initial request parameters
    request_params = {
        "userKey": "all",
        "applicationName": "login",
        "startTime": start_date,
        "maxResults": 1000,
    }
    if end_date:
        request_params["endTime"] = end_date

    # Execute initial request
    request = service.activities().list(**request_params)
    response = request.execute()

    # Process first page
    items = response.get("items", [])
    for activity in items:
        record = _extract_login_record(activity)
        if record:
            login_events.append(record)

    # Pagination loop
    while True:
        request = service.activities().list_next(
            previous_request=request,
            previous_response=response
        )

        if request is None:
            break

        response = request.execute()
        items = response.get("items", [])

        for activity in items:
            record = _extract_login_record(activity)
            if record:
                login_events.append(record)

    return login_events


def _extract_login_record(activity: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Extract login event fields from a Google Admin Reports API activity.

    Args:
        activity: Raw activity dict from Google Admin Reports API

    Returns:
        Normalized login event dict, or None if required fields are missing
    """
    # Extract basic structures
    activity_id = activity.get("id", {}) or {}
    actor_info = activity.get("actor", {}) or {}

    timestamp = activity_id.get("time")
    user_email = actor_info.get("email")
    user_ip = activity.get("ipAddress")

    # Require timestamp, user, and IP
    if not timestamp or not user_email or not user_ip:
        return None

    # Extract event parameters
    events = activity.get("events", []) or []
    if not events:
        return None

    primary_event = events[0]
    event_type = primary_event.get("type")  # e.g., "login"
    parameters = primary_event.get("parameters", []) or []

    # Defaults
    login_type = "unknown"
    is_suspicious = False

    # Parse parameters
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

    # Build description
    if user_email and event_type:
        description = f"{user_email} {event_type}"
    else:
        description = user_email or ""

    return {
        "timestamp": timestamp,
        "user": user_email,
        "ip": user_ip,
        "login_type": login_type,
        "is_suspicious": is_suspicious,
        "description": description,
    }
