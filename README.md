# AegisForge Backend Starter

Includes a FastAPI API, Pydantic schemas, basic policy engine, tool registry/gateway, simulated demo tool, and pytest tests.

## Install (PowerShell)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Test
```powershell
python -m pytest -v
```

## Run API from the folder containing `backend`
```powershell
uvicorn backend.main:app --reload --reload-dir backend
```
Open http://127.0.0.1:8000/docs

## Security note
Prototype only, not a production security boundary. The demo tool is simulated and does not access real files or databases. Production needs isolation, audit logging, strict tool/action mapping, robust approval workflows, and protection against filesystem race conditions.


## Contextual AI Risk Analysis (Groq)

The Risk Assessment page now calls `POST /risk/analyze`. It combines a transparent deterministic score with contextual analysis of asset details, exposure, data sensitivity, agent permissions, and up to 30 findings from the latest file scan. The score is a prioritization heuristic, not a probability of compromise. If Groq is unavailable, the API returns a clearly labeled local fallback rather than claiming AI analysis succeeded. The legacy `POST /risk/assess` endpoint remains available for compatibility.

### Configure Groq locally

1. From the `AegisForge` project directory, copy `.env.example` to `.env`.
2. Open `.env` and replace `your_groq_api_key_here` with your own Groq API key. Do not share the key or commit `.env`.
3. The default model is `openai/gpt-oss-120b`; change `GROQ_MODEL` only to a model enabled for your Groq account.
4. Install backend dependencies and restart the API:

   ```powershell
   python -m pip install -r requirements.txt
   python -m uvicorn backend.main:app --reload --reload-dir backend
   ```

5. Open the frontend, choose **Risk Assessment**, enter real context, and click **Run Contextual Risk Analysis**. If you have run File Security Scanner first, its latest findings are attached automatically (up to 30).

Without `GROQ_API_KEY`, the endpoint still calculates the local evidence-aware score and marks the result as a rule-based fallback. A real Groq API call has not been made by this package build; verify it locally after adding your key.


**Data handling:** the risk-analysis endpoint sends the supplied asset descriptions, agent permissions, and scanner finding metadata/evidence to Groq when the key is configured. It does not send the original uploaded file through this endpoint. Scanner redaction is best-effort, not a guarantee; avoid submitting real credentials or sensitive source snippets.
