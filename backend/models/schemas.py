
from typing import Literal

from pydantic import BaseModel, Field


class PolicyRequest(BaseModel):
    action: str = Field(min_length=1, max_length=100)
    target: str = Field(min_length=1, max_length=1000)


class PolicyResponse(BaseModel):
    decision: Literal["ALLOW", "APPROVAL_REQUIRED", "BLOCK"]
    action: str
    reason: str


class RiskAssessmentRequest(BaseModel):
    asset_criticality: int = Field(ge=1, le=5)
    threat_likelihood: int = Field(ge=1, le=5)
    vulnerability_severity: int = Field(ge=1, le=5)
    control_effectiveness: float = Field(ge=0, le=100)


class RiskAssessmentResponse(BaseModel):
    inherent_risk: float
    residual_risk: float
    risk_level: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    control_effectiveness: float


class ContextualRiskAssessmentRequest(BaseModel):
    asset_criticality: int = Field(ge=1, le=5)
    threat_likelihood: int = Field(ge=1, le=5)
    vulnerability_severity: int = Field(ge=1, le=5)
    control_effectiveness: float = Field(ge=0, le=100)
    asset_name: str = Field(default="", max_length=160)
    asset_description: str = Field(default="", max_length=1500)
    business_impact: str = Field(default="", max_length=1500)
    environment: Literal["development", "staging", "production", "unknown"] = "unknown"
    exposure: Literal["isolated", "internal", "internet", "unknown"] = "internet"
    data_sensitivity: Literal["public", "internal", "confidential", "restricted"] = "internal"
    agent_permissions: list[str] = Field(default_factory=list, max_length=20)
    scanner_findings: list[dict] = Field(default_factory=list, max_length=30)


class ContextualRiskAssessmentResponse(BaseModel):
    inherent_risk: float
    residual_risk: float
    risk_score: int
    risk_level: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    control_effectiveness: float
    factors: dict[str, float]
    scanner_bonus: float
    scanner_findings_analyzed: int
    analysis_summary: str
    attack_scenarios: list[str]
    key_findings: list[dict]
    recommendations: list[str]
    assumptions: list[str]
    confidence: Literal["LOW", "MODERATE", "HIGH"]
    ai_used: bool
    ai_status: str


class InvestmentRequest(BaseModel):
    current_risk: float = Field(ge=0)
    expected_risk_reduction: float = Field(ge=0, le=100)
    implementation_cost: float = Field(gt=0)


class InvestmentResponse(BaseModel):
    current_risk: float
    risk_reduced: float
    projected_risk: float
    implementation_cost: float
    cost_effectiveness: float


class InvestmentOption(BaseModel):
    name: str = Field(min_length=1)
    expected_risk_reduction: float = Field(ge=0, le=100)
    implementation_cost: float = Field(gt=0)


class InvestmentRankingRequest(BaseModel):
    current_risk: float = Field(ge=0)
    investments: list[InvestmentOption] = Field(min_length=1)


class RankedInvestment(InvestmentResponse):
    name: str
    rank: int = Field(ge=1)


class InvestmentRankingResponse(BaseModel):
    rankings: list[RankedInvestment]
