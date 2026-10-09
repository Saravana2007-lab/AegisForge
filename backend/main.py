
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi import File, HTTPException, UploadFile
from backend.security.file_scanner import MAX_FILE_BYTES, scan_file

from backend.models.schemas import (
    PolicyRequest,
    PolicyResponse,
    RiskAssessmentRequest,
    RiskAssessmentResponse,
    ContextualRiskAssessmentRequest,
    ContextualRiskAssessmentResponse,
    InvestmentRequest,
    InvestmentResponse,
    InvestmentRankingRequest,
    InvestmentRankingResponse,
)
from backend.security.policy_engine import evaluate_action
from backend.security.risk_engine import calculate_risk, analyze_contextual_risk
from backend.security.investment_engine import evaluate_investment
from backend.security.prioritization_engine import rank_investments


app = FastAPI(
    title="AegisForge API",
    description="AI Agent Security and Cyber Risk Platform",
    version="0.1.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"name": "AegisForge", "status": "running"}


@app.get("/health")
def health_check():
    return {"status": "healthy"}


@app.post("/policy/evaluate", response_model=PolicyResponse)
def evaluate_policy(request: PolicyRequest):
    return evaluate_action(
        action=request.action,
        target=request.target,
    )


@app.post("/risk/assess", response_model=RiskAssessmentResponse)
def assess_risk(request: RiskAssessmentRequest):
    return calculate_risk(
        asset_criticality=request.asset_criticality,
        threat_likelihood=request.threat_likelihood,
        vulnerability_severity=request.vulnerability_severity,
        control_effectiveness=request.control_effectiveness,
    )


@app.post("/risk/analyze", response_model=ContextualRiskAssessmentResponse)
def analyze_risk(request: ContextualRiskAssessmentRequest):
    """Analyze contextual evidence and optionally enrich the report with Groq."""
    try:
        return analyze_contextual_risk(request.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/investment/evaluate", response_model=InvestmentResponse)
def assess_investment(request: InvestmentRequest):
    return evaluate_investment(
        current_risk=request.current_risk,
        expected_risk_reduction=request.expected_risk_reduction,
        implementation_cost=request.implementation_cost,
    )


@app.post(
    "/investment/rank",
    response_model=InvestmentRankingResponse,
)
def rank_security_investments(request: InvestmentRankingRequest):
    rankings = rank_investments(
        current_risk=request.current_risk,
        investments=[
            investment.model_dump()
            for investment in request.investments
        ],
    )
    return {"rankings": rankings}

@app.post("/scan/file")
async def scan_uploaded_file(file: UploadFile = File(...)):
    filename = file.filename or ""

    try:
        # Read only up to the size limit plus one byte.
        content = await file.read(MAX_FILE_BYTES + 1)

        if len(content) > MAX_FILE_BYTES:
            raise HTTPException(
                status_code=413,
                detail="File exceeds the 1 MB limit.",
            )

        return scan_file(filename, content)

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    finally:
        await file.close()
