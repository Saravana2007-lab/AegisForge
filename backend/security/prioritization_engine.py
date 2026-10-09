
from typing import Any

from backend.security.investment_engine import evaluate_investment


def rank_investments(
    current_risk: float,
    investments: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Rank security investments by estimated risk reduction per unit cost."""

    if current_risk < 0:
        raise ValueError("Current risk cannot be negative.")

    if not investments:
        raise ValueError("At least one investment is required.")

    results = []

    for investment in investments:
        result = evaluate_investment(
            current_risk=current_risk,
            expected_risk_reduction=investment["expected_risk_reduction"],
            implementation_cost=investment["implementation_cost"],
        )

        results.append({
            "name": investment["name"],
            **result,
        })

    results.sort(
        key=lambda item: item["cost_effectiveness"],
        reverse=True,
    )

    for rank, investment in enumerate(results, start=1):
        investment["rank"] = rank

    return results
