
import pytest

from backend.security.risk_engine import calculate_risk


def test_critical_risk_calculation():
    result = calculate_risk(5, 4, 5, 20)

    assert result["inherent_risk"] == 20.0
    assert result["residual_risk"] == 16.0
    assert result["risk_level"] == "CRITICAL"


def test_perfect_controls_reduce_residual_risk_to_zero():
    result = calculate_risk(5, 5, 5, 100)

    assert result["inherent_risk"] == 25.0
    assert result["residual_risk"] == 0.0
    assert result["risk_level"] == "LOW"


def test_no_controls_leave_risk_unchanged():
    result = calculate_risk(4, 3, 2, 0)

    assert result["inherent_risk"] == 4.8
    assert result["residual_risk"] == 4.8


def test_invalid_asset_criticality_is_rejected():
    with pytest.raises(ValueError):
        calculate_risk(6, 4, 5, 20)


def test_invalid_control_effectiveness_is_rejected():
    with pytest.raises(ValueError):
        calculate_risk(5, 4, 5, 120)
