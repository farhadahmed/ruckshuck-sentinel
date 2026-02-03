# Sentinel Access Context API

The **Sentinel Access Context API** is a lightweight backend service that enriches access and login events with network, geolocation, and contextual signals to support security investigation.

This service is the **first foundational component** of the Ruckshuck Sentinel platform. It is intentionally scoped, conservative, and designed to deliver immediate visibility while establishing a clean path toward more advanced detection and advisory capabilities in the future.

---

## What This Service Does

At a high level, the service:

1. Retrieves **Google Workspace login events** using a provided Google Cloud service account
2. Extracts IP addresses associated with each login event
3. Enriches each login with **network and geolocation context**, including:
   - VPN indicator
   - Proxy indicator
   - City
   - Region
   - Country
   - Continent
   - Latitude / Longitude
   - ASN (Autonomous System Number)
   - ASO (Autonomous System Organization)
4. Returns the enriched data in a **table-friendly JSON format** for display in the Sentinel web UI

This service is **investigative only**. It does not generate alerts, suppress events, or take any automated response actions.

---

## What This Service Is *Not*

To avoid ambiguity and overreach, the Sentinel Access Context API explicitly does **not**:

- Perform threat detection or alerting
- Execute automated response actions
- Train or run AI agents
- Modify client infrastructure
- Persist long-term identity or behavior profiles
- Replace a SIEM, SOC, or IAM platform

These capabilities may be layered on later as separate services.

---

## Intended Use Case

This service is designed for:

- Security teams that want **clear access visibility** without introducing automation risk
- Investigations such as:
  - Logins from new countries or networks
  - VPN or proxy-based access
  - Administrative or sensitive account access review

---

## Architecture Overview

- **API Framework:** FastAPI (ASGI)
- **Execution Model:** Synchronous pipeline (MVP)
- **External Integrations:**
  - Google Workspace Admin Reports API
  - IP geolocation / VPN intelligence provider
- **Deployment Target:** Containerized service (Cloud Run / VM / local)

The service is designed as a **standalone deployable** with clean internal boundaries to allow future decomposition into additional services.

---

## API Overview (MVP)

### `POST /access-context/run`

Runs the access context enrichment pipeline for a given date range.

**Request Body**
```json
{
  "service_account_json": { "...": "Google service account JSON" },
  "start_date": "YYYY-MM-DD",
  "end_date": "YYYY-MM-DD"
}
```

***Response***
```json
{
  "rows": [
    {
      "timestamp": "...",
      "user": "...",
      "ip": "...",
      "vpn": true,
      "proxy": false,
      "city": "...",
      "region": "...",
      "country": "...",
      "continent": "...",
      "latitude": 0.0,
      "longitude": 0.0,
      "asn": "...",
      "aso": "..."
    }
  ]
}
```

* Note: This endpoint is synchronous in the MVP. If execution time grows, it will be migrated to a job-based async model.


## Local Development Setup

***Prerequisites***
* Python 3.10+
* Google Cloud service account with read-only access to:
* Google Workspace Admin Reports API
* VPN / IP intelligence API key

1. Create and activate a virtual environment
    * python3 -m venv .venv
    * source .venv/bin/activate

2. Install dependencies
    * pip install --upgrade pip
    * pip install -r requirements.txt

3. Configure environment variables
    * Create a .env file (based on .env.example):
        * ```VPN_API_KEY=your_api_key_here```
        * .env files are intended for local development only. In production, secrets should be injected via environment variables or a cloud secret manager.

4. Run the API locally
    * ```uvicorn app.main:app --reload --port 8000```
    * Verify the service is running:
        * Health check: http://localhost:8000/health 
        * API docs (Swagger): http://localhost:8000/docs

## Security Notes
* Service account credentials are used only for the duration of a request
* Credentials are not logged
* The API is intended to be protected behind:
    * An API gateway
    * Network restrictions
    * Or application-level authentication (added later)
* All enrichment is read-only and non-destructive
* For detailed dependency justification, see DEPENDENCIES.md.