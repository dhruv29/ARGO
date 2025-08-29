# Secrets & Keys

Copy `.env.example` → `.env` and set:

## Required
- `OPENAI_API_KEY` — embeddings (and limited vision later if enabled).

## Optional
- **ServiceNow VR (read-only):**
  - `SNOW_BASE_URL`, `SNOW_USER`, `SNOW_PASSWORD`

## Rules
- No secrets in git.
- Local-first: app must run with only `OPENAI_API_KEY`.
- Use mocks in CI; never use live keys in tests.
