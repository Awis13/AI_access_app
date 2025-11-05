# Access Provisioning Demo
## AI-powered Infrastructure Automation Example

A lightweight, privacy-focused web app that demonstrates how to provision application accounts:
generate bcrypt hashes, build SQL statements, run quick duplicate checks and
optionally execute the statements against sandbox PostgreSQL environments. This
repository is a NDA-safe rewrite of an internal tool and runs entirely on your
machine with dummy data. It is built for internal teams and can be deployed on
standard CPU-only infrastructure—no GPU required. The app demonstrates principles of AI Ops and integration of LLM in infrastructure processes.

## Key Features
- Single-page UI with copy-ready SQL transactions and password previews.
- Real bcrypt hashing via the `/hash` backend endpoint.
- AI-powered field extraction via Ollama (login, full name, email in one click).
- Multiple demo environments (`PROD`, `STAGING`, `DEV`) powered by Docker.
- Log rotation and password-hash masking for safer diagnostics.
- Pluggable auth: demo mode out-of-the-box, OpenID Connect when needed.
- CPU-friendly deployment: the default Ollama setup runs comfortably without a GPU.
- Jenkins/Ansible-ready design for real-world automation pipelines.

## Demo Walkthrough (3 minutes)
1. Start the stack with `docker-compose up --build` (spins up Flask + three Postgres instances).
2. Paste a request like `Need access for Jana Novaková (jana.novakova@example.com)` into the AI extractor and click **🤖 Extract with AI**.
3. Watch the form auto-populate, generate fresh credentials, and render the SQL transaction.
4. Run **🔎 Check if user exists** to show duplicate detection, then hit **Send to Database** to create the account in the demo DB.
5. Point out the rotating log files (`logs/`) and the masked hashes to underscore production-readiness.

![Demo walkthrough showing AI extraction through user creation](demo-walkthrough.gif)

## Getting Started

### Prerequisites
- Python 3.11+
- Docker & Docker Compose (for the full stack)
- [Ollama](https://ollama.com/) running locally with a pulled model: `ollama pull gemma3:4b`
  - Ollama’s CPU backend is sufficient; GPU acceleration is optional.

### 1. Local Python Run
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export DB_USER=admin
export DB_PASSWORD=admin123
python server_with_extraction.py
```
Open http://localhost:5000 to load the UI.

### 2. Docker Compose (API + demo databases)
```bash
export DB_USER=admin
export DB_PASSWORD=admin123
docker-compose up --build
```
The Flask server is available at http://localhost:5000 and three isolated
PostgreSQL instances run on:

- PROD: `postgresql://admin:admin123@localhost:5542/access_portal_prod`
- STAGING: `postgresql://admin:admin123@localhost:5433/access_portal_staging`
- DEV: `postgresql://admin:admin123@localhost:5434/access_portal_dev`

Run quick smoke checks after the server starts:

```bash
curl -s localhost:5000/api/config
curl -s "localhost:5000/api/db/test?app=ACCESS_PORTAL&env=PROD"
curl -s -X POST localhost:5000/api/db/execute \
  -H 'Content-Type: application/json' \
  -d '{"app":"ACCESS_PORTAL","env":"DEV","query":"SELECT 1;"}'
```

## Configuration
- `config.py` holds app/env definitions. Update `APPS` to point at your own
  databases (keep `docker-compose.yml` in sync).
- **Authentication**: by default `AUTH_MODE=demo` auto-signs a dummy user.
  Set `AUTH_MODE=oidc` together with the Keycloak variables
  (`KEYCLOAK_SERVER_URL`, `KEYCLOAK_REALM`, `KEYCLOAK_CLIENT_ID`,
  `KEYCLOAK_CLIENT_SECRET`) to enable SSO.
- **AI extraction**: defaults to the `gemma3:4b` model. Adjust `OLLAMA_BASE_URL` and
  `LLM_MODEL_NAME` if you run a different model/server.
  - For CPU-only servers set `OLLAMA_NUM_PARALLEL=1` (or similar) to keep inference responsive.
- **Logging**: `LOG_FILE` and `LOG_LEVEL` configure application logs. See
  `setup-log-rotation.sh` for optional system logrotate integration.

## API Overview
- `GET /api/config` – list demo apps, environments and auth mode.
- `POST /hash` – return a bcrypt hash for the provided password.
- `POST /api/extract` – use Ollama to parse login/name/email.
- `GET /api/db/test` – run a connectivity check and list sample users.
- `POST /api/db/execute` – execute arbitrary SQL (intended for sandbox use).
- `POST /api/db/user_exists` – check duplicates by login and/or email.

## Architecture at a Glance
- `server_with_extraction.py` – Flask backend (auth, hashing, Ollama orchestration, DB helpers).
- `index_with_extraction.html` / `script.js` / `extraction.js` – single-page UX for extraction, duplication checks, SQL previews, and execution.
- `docker-compose.yml` – three isolated Postgres services plus the Flask app.
- `init.sql` – schema + seed users copied into each database at container start.
- `config.py` – environment overrides, Keycloak toggle, Ollama settings, logging targets.
- The stack easily integrates into existing CI/CD pipelines (e.g., Jenkins or GitLab CI) and Keycloak/Active Directory environments.

## Troubleshooting
- **Ollama connection refused**: start the Ollama service (`ollama serve`) and pull the configured model (`ollama pull gemma3:4b`).
- **Database errors**: ensure `docker-compose` is up and that the ports above are
  free; verify `DB_USER/DB_PASSWORD`.
- **Auth redirect loops**: if you set `AUTH_MODE=oidc`, double-check all Keycloak
  settings and redirect URLs.

# AI_access_app

## Security Notes
- Shipping demo credentials is intentional. Replace them before targeting non-demo
  infrastructure.
- `/api/db/execute` runs whatever SQL you send. Keep it behind a firewall and use
  trusted input only.
- Password hashes and similar secrets are masked in application logs, and log
  rotation is enabled by default.

