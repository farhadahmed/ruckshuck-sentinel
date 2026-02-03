from pydantic import BaseModel, Field
from typing import Any, Dict, Optional

class RunRequest(BaseModel):
    service_account_json: Dict[str, Any] = Field(
        ...,
        description="Google service account credentials as JSON object"
    )
    delegated_admin_email: str = Field(
        ...,
        description="Admin email for domain-wide delegation"
    )
    start_date: str = Field(
        ...,
        description="Start date in RFC 3339 format (e.g., '2024-01-01T00:00:00Z')"
    )
    end_date: Optional[str] = Field(
        None,
        description="End date in RFC 3339 format (defaults to current time if not provided)"
    )
