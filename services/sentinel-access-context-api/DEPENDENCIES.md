# DEPENDENCIES.md  
**Sentinel Access Context API**

This document explains the purpose and justification for each third-party dependency used by the Sentinel Access Context API. Dependencies are intentionally minimal and selected to reduce attack surface while supporting secure, auditable operation.

The service follows these principles:
- Prefer **small, widely adopted, well-maintained libraries**
- Avoid unnecessary frameworks or abstraction layers
- Use **schema validation** to reduce malformed input risk
- Favor transparency and auditability over “magic”

---

## Direct (Intentional) Dependencies

These libraries were explicitly chosen and are required for core functionality.

### fastapi
**Purpose:** Web API framework  
FastAPI provides a minimal ASGI-based API layer with:
- Explicit request/response schemas
- Automatic OpenAPI documentation for transparency
- Built-in input validation using Pydantic
- Dependency injection to support future auth and security controls

FastAPI is chosen over heavier frameworks due to its small footprint and clarity.

---

### uvicorn
**Purpose:** ASGI application server  
Uvicorn is a lightweight, high-performance ASGI server used to run the FastAPI application locally and in containerized deployments.

It does not include business logic and is responsible only for HTTP request handling.

---

### pydantic / pydantic-core
**Purpose:** Data validation and schema enforcement  
Pydantic enforces strict data schemas for:
- Incoming API requests
- Outgoing API responses
- Internal normalized data models

This reduces the risk of malformed input, unexpected data types, and downstream processing errors. Pydantic v2 uses `pydantic-core` for performance and correctness.

---

### requests
**Purpose:** Outbound HTTP client  
The `requests` library is used for outbound HTTPS calls to:
- IP geolocation providers
- VPN / proxy intelligence services

It is a mature, widely used library with predictable behavior and no hidden async execution.

---

### python-dotenv
**Purpose:** Local development configuration  
Used only for local development to load environment variables from a `.env` file.

In production environments, secrets are expected to be injected via:
- Container environment variables
- Cloud-native secret managers (e.g., GCP Secret Manager)

---

## Transitive Dependencies

The following dependencies are **not chosen directly**, but are required by the libraries above. They are documented here for transparency.

---

### starlette
**Purpose:** ASGI toolkit (used by FastAPI)  
Starlette provides the underlying routing, middleware, and ASGI primitives used by FastAPI.

FastAPI is built on Starlette; it is not an independent framework choice.

---

### anyio
**Purpose:** Async concurrency abstraction  
AnyIO provides a consistent async API for concurrency handling used internally by FastAPI/Starlette.

It allows non-blocking I/O without tying the application to a single event loop implementation.

---

### h11
**Purpose:** HTTP/1.1 protocol implementation  
A small, pure-Python library used by Uvicorn to handle HTTP/1.1 semantics.

It does not perform application logic.

---

### click
**Purpose:** Command-line interface support  
Used by Uvicorn for command-line startup and options handling.

---

### urllib3
**Purpose:** Low-level HTTP client  
Provides connection pooling, TLS handling, and retries for `requests`.

---

### certifi
**Purpose:** Trusted CA certificate bundle  
Ensures HTTPS requests use an up-to-date certificate authority store.

---

### charset-normalizer
**Purpose:** Character encoding detection  
Used by `requests` to safely decode HTTP responses.

---

### idna
**Purpose:** Internationalized domain name handling  
Used by `requests` and `urllib3` for correct URL parsing.

---

### annotated-types / annotated-doc
**Purpose:** Typing metadata support  
Used by Pydantic v2 to support advanced type annotations and validation metadata.

---

### typing-extensions / typing-inspection
**Purpose:** Runtime typing compatibility  
Provides forward-compatible typing features required by Pydantic on supported Python versions.

---

## Dependency Management Policy

- Dependencies are pinned via `requirements.txt` to ensure reproducible builds
- Regular review for security advisories (CVEs) is expected
- Dependencies are updated deliberately, not automatically
- No dependency performs autonomous actions, network scanning, or execution of untrusted code

---

## Summary

The Sentinel Access Context API uses a **small, transparent dependency set** focused on:
- Secure API handling
- Explicit data validation
- Controlled outbound HTTP calls
- Minimal runtime complexity

All dependencies are industry-standard, well-maintained, and widely audited.
