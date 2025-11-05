# Repository Guidelines

## Project Structure & Module Organization
- `server_with_extraction.py`: Flask API (hashing, AI extraction, DB endpoints, multi-app/env).
- Frontend: `index_with_extraction.html`, `script.js`, `extraction.js`, `style.css`.
- Data/DB: `init.sql` (schema + seed), `docker-compose.yml`, `Dockerfile`.
- Logic: `generate_access_queries.py` (SQL builder, bcrypt), `extract_user_info.py` (AI + regex).
- Config: `config.py` defines `APPS` with per-app environments and DB creds (host, port, db, user, password).
- Tooling: `requirements.txt`, `activate_venv.sh`.

## Build, Test, and Development Commands
- Create venv and install deps:
  - `python -m venv .venv && source .venv/bin/activate`
  - `pip install -r requirements.txt`
- Run API locally (port 5000):
  - `python server_with_extraction.py`
- Docker (API + Postgres PROD/UAT/TEST):
  - `docker-compose up --build`
- Quick checks:
  - `curl -s localhost:5000/api/config` (apps/envs for UI)
  - `curl -s "localhost:5000/api/db/test?app=WEB&env=UAT"`
  - `curl -s -X POST localhost:5000/api/db/execute -H 'Content-Type: application/json' -d '{"app":"WEB","env":"TEST","query":"SELECT 1;"}'`

## Coding Style & Naming Conventions
- Python: 4-space indent, snake_case for functions/vars, module-level constants in ALL_CAPS, docstrings for public functions.
- JavaScript: camelCase for vars/functions; avoid global leakage; keep DOM IDs stable (`login`, `name`, `email`).
- Files: descriptive, lowercase with underscores for Python; hyphen-less for JS/CSS/HTML.
- Keep real secrets out of code; `config.py` holds local/dev DB creds per app/env.

## Testing Guidelines
- No formal test suite yet. Validate via:
  - Browser: open `http://localhost:5000` and use the UI (App/Env dropdowns).
  - API: use the curl examples above.
- Extraction: ensure Ollama (or your AI server) is running; adjust `LLM_MODEL_NAME` in `config.py` if needed.
- Prefer deterministic samples in PRs (input text → expected JSON fields).

## Commit & Pull Request Guidelines
- Commits: short, imperative subjects (e.g., "Add database integration", "Improve extraction UI").
- PRs must include:
  - Purpose and summary of changes
  - How to run locally (commands) and manual test evidence (curl output or screenshots)
  - Linked issue(s) if applicable
- Notes on security/config (DB URL, AI/Ollama requirements)

## Security & Configuration Tips
- DB ports (compose): PROD 5542, UAT 5433, TEST 5434. Update in `docker-compose.yml` and `config.py` together.
- Configure per-app DB creds in `config.py`; do not commit production secrets.
- Ollama/AI: ensure server available; see `config.py` for model/base URL.
- Avoid logging secrets; exclude password values from responses and commits.

## Quickstart
- Create venv: `python -m venv .venv && source .venv/bin/activate`
- Install deps: `pip install -r requirements.txt`
- Run API: `python server_with_extraction.py` then open `http://localhost:5000`
- Docker stack: `docker-compose up --build` (API + Postgres for PROD/UAT/TEST)
- Smoke tests:
  - `curl -s localhost:5000/api/config`
  - `curl -s "localhost:5000/api/db/test?app=WEB&env=UAT"`
  - `curl -s -X POST localhost:5000/api/db/execute -H 'Content-Type: application/json' -d '{"app":"WEB","env":"TEST","query":"SELECT 1;"}'`

## Agent Workflow
- Plan first: break work into small steps and validate incrementally.
- Be surgical: change only what’s required; keep style consistent.
- Keep secrets out: never hardcode real passwords or tokens.
- Update docs: reflect any user-visible changes in README/DOCKER.
- Validate locally: use the curl checks and UI to confirm behavior.
- Prefer determinism: include example inputs and expected outputs for extraction changes.

## Common Tasks
- Add app or environment:
  - Edit `config.py` `APPS[...]` with `host`, `port`, `db`, `user`, `password`.
  - Mirror ports/services in `docker-compose.yml` (PROD 5542, UAT 5433, TEST 5434).
  - Verify with `GET /api/config` and `GET /api/db/test?app=...&env=...`.
- Add API endpoint:
  - Implement in `server_with_extraction.py` (Flask route, input validation, JSON response).
  - Reuse existing DB helpers and avoid logging sensitive values.
  - Add a minimal curl example to README or this doc.
- Adjust extraction behavior:
  - Configure `LLM_MODEL_NAME` and base URL in `config.py`.
  - Ensure Ollama (or your AI server) is running; test via UI and `extract_user_info.py`.
  - Favor regex/post-processing for small, deterministic fixes.

## Troubleshooting
- Ollama connection refused:
  - Start the Ollama server and confirm base URL/model in `config.py`.
- DB connection errors:
  - Ensure compose ports match `config.py` (PROD 5542, UAT 5433, TEST 5434).
  - Check creds in `config.py` and service health: `docker-compose ps` and `docker-compose logs`.
- CORS or UI fetch issues:
  - Confirm API on `http://localhost:5000`; review browser network tab and server logs.

## PR Checklist
- Purpose and summary of changes
- Local run instructions and output (curl/UI screenshots)
- Deterministic samples for extraction changes (input → expected JSON)
- Security/config notes (DB URLs, AI/Ollama requirements)
- Scope is minimal; unrelated changes deferred
