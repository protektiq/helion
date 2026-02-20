# helion

FastAPI backend with modular structure, Postgres, and environment-based config.

## Structure

- `app/main.py` – FastAPI app, CORS, router wiring
- `app/api/` – API route modules (v1 with health)
- `app/core/` – config (env loading), database (Postgres session)
- `app/models/` – SQLAlchemy models (placeholder)
- `app/schemas/` – Pydantic request/response schemas
- `app/services/` – business logic (placeholder)

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
