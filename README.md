# helion

FastAPI backend with modular structure, Postgres, and environment-based config.

## Structure

- `app/main.py` – FastAPI app, CORS, router wiring
- `app/api/` – API route modules (v1: health, upload, clusters, reasoning)
- `app/core/` – config (env loading), database (Postgres session)
- `app/models/` – SQLAlchemy models (Base, Finding)
- `app/schemas/` – Pydantic request/response schemas
- `app/services/` – business logic (clustering, normalization, reasoning)
- `web/` – minimal Next.js UI: upload page (file input, submit, status) and results summary page (raw/cluster counts, severity breakdown, Export to Jira)

## Setup

1. **Create a virtualenv** (from project root):

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate   # Linux/macOS
   # or: .venv\Scripts\activate  # Windows
   ```

2. **Install dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

3. **Environment variables**  
   Copy the example file and set real values (do not commit `.env`):

   ```bash
   cp .env.example .env
   # Edit .env with your DATABASE_URL and other settings
   ```

   Required for running with DB: `DATABASE_URL` (Postgres URL). Optional: `APP_ENV`, `DEBUG`, `API_V1_PREFIX` (see `.env.example`).

4. **Postgres**  
   Ensure PostgreSQL is running and the database in `DATABASE_URL` exists (e.g. `createdb helion`).

5. **Database migrations**  
   Create the `findings` table (and any future schema) with Alembic:

   ```bash
   alembic upgrade head
   ```

6. **Create the first user**  
   There is no registration UI. Create an admin (or normal user) via the CLI:

   ```bash
   python -m app.scripts.create_user admin your-secure-password admin
   # Or a normal user: python -m app.scripts.create_user alice secret123 user
   ```

   Then log in at **POST /api/v1/auth** with `{"username":"admin","password":"your-secure-password"}` to get a JWT. Use `Authorization: Bearer <access_token>` on all protected endpoints (e.g. curl or Postman for API-first auth).

7. **Local LLM (optional)**  
   For the reasoning endpoint (POST /api/v1/reasoning), install [Ollama](https://ollama.com) and pull Llama 3:

   ```bash
   # Install Ollama from https://ollama.com for your OS, then:
   ollama pull llama3.2
   ```

   Ensure the Ollama API is available (default: `http://localhost:11434`). Configure via `.env`: `OLLAMA_BASE_URL`, `OLLAMA_MODEL`, `OLLAMA_REQUEST_TIMEOUT_SEC` (see `.env.example`). LLM calls are **deterministic by default** (temperature 0 and a fixed seed) for reproducible reasoning and exploitability outputs. To get more creative or varied reasoning, you can override these optional env vars: `OLLAMA_TEMPERATURE`, `OLLAMA_TOP_P`, `OLLAMA_REPEAT_PENALTY`, `OLLAMA_SEED` (see `.env.example` for names and example values).

## Authentication and access control

- **Login**: **POST /api/v1/auth** with JSON `{"username","password"}` returns `{"access_token","token_type":"bearer"}`. All protected API routes require the header `Authorization: Bearer <access_token>`.
- **Roles**: Users have `admin` or `user`. **GET /api/v1/auth/users** (list users) is admin-only; other protected routes allow any authenticated user.

## Run the server

From the **project root**:

```bash
uvicorn app.main:app --reload
```

- API base: `http://localhost:8000`
- Interactive docs: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

## Health check

- **URL:** `GET http://localhost:8000/api/v1/health`
- **Example:** `curl http://localhost:8000/api/v1/health`

Response includes `status`, `environment`, and `database` (connected/disconnected).

## Upload findings (SAST/SCA JSON)

- **URL:** `POST http://localhost:8000/api/v1/upload`
- **JSON body:** Send `Content-Type: application/json` with a single finding object or an array of finding objects (each validated as RawFinding).
- **File upload:** Send `Content-Type: multipart/form-data` with a field named `file` containing a `.json` file (same structure; max 50 MB, max 10 000 findings per request).

Response (201): `{ "accepted": N, "ids": [ ... ] }` with the count and database IDs of persisted findings.

### Upload UI (frontend)

A minimal Next.js app in the `web/` folder provides:

- **Upload page** (http://localhost:3000): Select a `.json` file and submit it to the upload API.
- **Results summary** (http://localhost:3000/results): Shows raw findings count, cluster count, risk tier (severity) breakdown in a summary table, and an **Export to Jira** button that calls `POST /api/v1/jira/export` with current DB clusters. Jira env vars must be set for export to succeed.

1. **Install dependencies** (from project root):

   ```bash
   cd web && npm install
   ```

2. **Environment**: Optionally copy `web/.env.local.example` to `web/.env.local` and set `NEXT_PUBLIC_API_URL` if your API is not at `http://localhost:8000`.

3. **Run the API** first (from project root: `uvicorn app.main:app --reload`), then start the frontend:

   ```bash
   cd web && npm run dev
   ```

   Open http://localhost:3000. Use the upload page to submit a JSON file; use **Results summary** to view counts and export to Jira.

## Reasoning (local LLM) and risk tiers

- **URL:** `POST http://localhost:8000/api/v1/reasoning`
- **Body:** `{ "clusters": [ ... ] }` (list of VulnerabilityCluster) or `{ "use_db": true }` to use current clusters from the database.
- **Response:** `{ "summary": "...", "cluster_notes": [ { "vulnerability_id", "priority", "reasoning", "assigned_tier", "override_applied" }, ... ] }`. The LLM (Ollama / Llama 3) provides `priority` and `reasoning`; **assigned risk tiers** (Tier 1/2/3) are computed deterministically by the backend (e.g. CVSS > 9 → Tier 1 unless dev-only). Final tier is AI-assisted, not AI-dependent. The reasoning and exploitability endpoints use the same deterministic LLM settings by default; the optional env vars above allow overriding for more creative behavior. Requires Ollama running and the model pulled (e.g. `ollama pull llama3.2`).
