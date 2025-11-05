#!/usr/bin/env python3
"""
Central configuration for the demo-friendly access provisioning app.

The original project depended on company-specific infrastructure (Keycloak realms,
VPN hostnames, etc.). This module now ships with safe defaults that can run
entirely on a developer laptop while still allowing optional overrides for more
advanced deployments.
"""

import os

# -----------------------------------------------------------------------------
# Feature toggles
# -----------------------------------------------------------------------------
AUTH_MODE = os.getenv("AUTH_MODE", "demo").strip().lower()

# -----------------------------------------------------------------------------
# LLM Configuration
# -----------------------------------------------------------------------------
# Switch models by changing the string below or setting LLM_MODEL_NAME env var.
LLM_MODEL_NAME = os.getenv("LLM_MODEL_NAME", "gemma3:4b")

# Ollama configuration (host.docker.internal works for Docker-based runs; override if needed)
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434")

# Extraction backend: "regex" (default) or "ollama"
EXTRACTION_BACKEND = os.getenv("EXTRACTION_BACKEND", "regex").strip().lower()

# -----------------------------------------------------------------------------
# Authentication / Session settings
# -----------------------------------------------------------------------------
SECRET_KEY = os.getenv("SECRET_KEY", "demo-secret-change-me")

# Optional OIDC (only used when AUTH_MODE=oidc)
KEYCLOAK_SERVER_URL = os.getenv("KEYCLOAK_SERVER_URL")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID")
KEYCLOAK_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET")

OIDC_ENABLED = (
    AUTH_MODE == "oidc"
    and KEYCLOAK_SERVER_URL
    and KEYCLOAK_REALM
    and KEYCLOAK_CLIENT_ID
    and KEYCLOAK_CLIENT_SECRET
)

if AUTH_MODE == "oidc" and not OIDC_ENABLED:
    raise RuntimeError(
        "AUTH_MODE=oidc requires KEYCLOAK_SERVER_URL, KEYCLOAK_REALM, "
        "KEYCLOAK_CLIENT_ID, and KEYCLOAK_CLIENT_SECRET environment variables."
    )

OIDC_CONFIG = (
    {
        "issuer": f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}",
        "authorization_endpoint": f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/auth",
        "token_endpoint": f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token",
        "userinfo_endpoint": f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/userinfo",
        "jwks_uri": f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/certs",
        "server_metadata_url": f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/.well-known/openid-configuration",
    }
    if OIDC_ENABLED
    else None
)

DEMO_USER = {
    "id": "demo-user",
    "email": os.getenv("DEMO_USER_EMAIL", "demo.user@example.com"),
    "name": os.getenv("DEMO_USER_NAME", "Demo User"),
    "preferred_username": os.getenv("DEMO_USER_USERNAME", "demo.user"),
    "roles": ["demo-admin"],
}

# -----------------------------------------------------------------------------
# Database configuration
# -----------------------------------------------------------------------------
DB_USER = os.getenv("DB_USER", "admin")
DB_PASSWORD = os.getenv("DB_PASSWORD", "admin123")

APPS = {
    "ACCESS_PORTAL": {
        "label": "Access Portal (Demo)",
        "default_env": "PROD",
        "databases": {
            "PROD": {
                "host": "postgres_prod",
                "port": 5432,
                "database": "access_portal_prod",
                "user": DB_USER,
                "password": DB_PASSWORD,
            },
            "STAGING": {
                "host": "postgres_staging",
                "port": 5432,
                "database": "access_portal_staging",
                "user": DB_USER,
                "password": DB_PASSWORD,
            },
            "DEV": {
                "host": "postgres_dev",
                "port": 5432,
                "database": "access_portal_dev",
                "user": DB_USER,
                "password": DB_PASSWORD,
            },
        },
    },
}

# Global defaults
DEFAULT_APP = "ACCESS_PORTAL"

# -----------------------------------------------------------------------------
# Logging configuration
# -----------------------------------------------------------------------------
LOG_FILE = os.getenv("LOG_FILE", "/app/logs/web-app-access.log")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
