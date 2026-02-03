import os
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from app.schemas.requests import RunRequest
from app.schemas.responses import RunResponse
from app.services.enrichment_service import enrich_login_events

# Load environment variables from .env file
load_dotenv()

app = FastAPI(title="Sentinel Access Context API", version="0.1.0")


@app.get("/health")
def health():
    """Health check endpoint."""
    return {"status": "ok"}


@app.post("/access-context/run", response_model=RunResponse)
def run_access_context(payload: RunRequest):
    """
    Enrich Google Workspace login events with IP intelligence.

    Fetches login events for the specified date range and enriches each
    event with VPN detection, geolocation, and network information.
    """
    # Load VPN API key from environment
    vpn_api_key = os.getenv("VPN_API_KEY")
    if not vpn_api_key:
        raise HTTPException(
            status_code=500,
            detail="VPN_API_KEY not configured in environment"
        )

    try:
        # Run enrichment pipeline
        enriched_events = enrich_login_events(
            service_account_json=payload.service_account_json,
            delegated_admin_email=payload.delegated_admin_email,
            start_date=payload.start_date,
            end_date=payload.end_date,
            vpn_api_key=vpn_api_key,
        )

        return RunResponse(rows=enriched_events)

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Enrichment failed: {str(e)}")