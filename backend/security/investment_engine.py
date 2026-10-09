
from typing import Any


def evaluate_investment(
    current_risk: float,
    expected_risk_reduction: float,
    implementation_cost: float,
) -> dict[str, Any]:
    """Estimate the cost-effectiveness of a security investment."""

    if current_risk < 0:
        raise ValueError("Current risk cannot be negative.")

    if not 0 <= expected_risk_reduction <= 100:
        raise ValueError("Expected risk reduction must be between 0 and 100.")

    if implementation_cost <= 0:
        raise ValueError("Implementation cost must be greater than zero.")

    risk_reduced = current_risk * (
        expected_risk_reduction / 100
    )

    cost_effectiveness = risk_reduced / implementation_cost

    return {
        "current_risk": round(current_risk, 2),
        "risk_reduced": round(risk_reduced, 2),
        "projected_risk": round(current_risk - risk_reduced, 2),
        "implementation_cost": round(implementation_cost, 2),
        "cost_effectiveness": round(cost_effectiveness, 6),
    }
