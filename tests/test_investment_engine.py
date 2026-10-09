
import pytest
from backend.main import rank_security_investments
from backend.models.schemas import InvestmentRankingRequest
from backend.security.investment_engine import evaluate_investment


def test_evaluate_investment():
    result = evaluate_investment(
        current_risk=16,
        expected_risk_reduction=50,
        implementation_cost=10000,
    )

    assert result["risk_reduced"] == 8
    assert result["projected_risk"] == 8
    assert result["cost_effectiveness"] == 0.0008


def test_zero_percent_risk_reduction():
    result = evaluate_investment(16, 0, 10000)

    assert result["risk_reduced"] == 0
    assert result["projected_risk"] == 16


def test_full_risk_reduction():
    result = evaluate_investment(16, 100, 10000)

    assert result["risk_reduced"] == 16
    assert result["projected_risk"] == 0


def test_negative_current_risk():
    with pytest.raises(ValueError):
        evaluate_investment(-1, 50, 10000)


def test_invalid_risk_reduction():
    with pytest.raises(ValueError):
        evaluate_investment(16, 120, 10000)


def test_invalid_implementation_cost():
    with pytest.raises(ValueError):
        evaluate_investment(16, 50, 0)


def test_investment_ranking_api_accepts_schema_models_and_returns_rankings():
    request = InvestmentRankingRequest(
        current_risk=20,
        investments=[
            {
                "name": "Endpoint Protection",
                "expected_risk_reduction": 60,
                "implementation_cost": 25000,
            },
            {
                "name": "Multi-Factor Authentication",
                "expected_risk_reduction": 40,
                "implementation_cost": 10000,
            },
        ],
    )

    response = rank_security_investments(request)

    assert response["rankings"][0]["name"] == "Multi-Factor Authentication"
    assert response["rankings"][0]["rank"] == 1
    assert response["rankings"][1]["name"] == "Endpoint Protection"
    assert response["rankings"][1]["rank"] == 2
