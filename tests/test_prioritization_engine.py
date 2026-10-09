
import pytest

from backend.security.prioritization_engine import rank_investments


def test_investments_are_ranked_by_cost_effectiveness():
    investments = [
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
        {
            "name": "Automated Backups",
            "expected_risk_reduction": 30,
            "implementation_cost": 8000,
        },
    ]

    results = rank_investments(
        current_risk=20,
        investments=investments,
    )

    assert results[0]["name"] == "Multi-Factor Authentication"
    assert results[1]["name"] == "Automated Backups"
    assert results[2]["name"] == "Endpoint Protection"

    assert results[0]["rank"] == 1
    assert results[1]["rank"] == 2
    assert results[2]["rank"] == 3


def test_empty_investment_list_is_rejected():
    with pytest.raises(ValueError):
        rank_investments(current_risk=20, investments=[])


def test_negative_current_risk_is_rejected():
    with pytest.raises(ValueError):
        rank_investments(current_risk=-1, investments=[
            {
                "name": "MFA",
                "expected_risk_reduction": 40,
                "implementation_cost": 10000,
            }
        ])


def test_equal_cost_effectiveness():
    investments = [
        {
            "name": "Control A",
            "expected_risk_reduction": 50,
            "implementation_cost": 10000,
        },
        {
            "name": "Control B",
            "expected_risk_reduction": 25,
            "implementation_cost": 5000,
        },
    ]

    results = rank_investments(20, investments)

    assert results[0]["cost_effectiveness"] == results[1]["cost_effectiveness"]
    assert {item["rank"] for item in results} == {1, 2}
