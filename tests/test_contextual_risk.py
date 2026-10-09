from backend.security.risk_engine import analyze_contextual_risk


def test_contextual_analysis_uses_scanner_evidence_and_never_zeroes_risk(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    result = analyze_contextual_risk({
        "asset_criticality": 5,
        "threat_likelihood": 4,
        "vulnerability_severity": 5,
        "control_effectiveness": 100,
        "asset_name": "Production agent",
        "asset_description": "Agent can read application files.",
        "business_impact": "Credential exposure and unauthorized actions.",
        "environment": "production",
        "exposure": "internet",
        "data_sensitivity": "restricted",
        "agent_permissions": ["read files", "execute tools"],
        "scanner_findings": [{
            "rule_id": "CODE_EVAL",
            "title": "Dynamic eval detected",
            "severity": "HIGH",
            "description": "Dynamic execution may run untrusted input.",
            "recommendation": "Avoid eval for untrusted data.",
            "evidence": "eval(userInput)",
        }],
    })
    assert result["scanner_findings_analyzed"] == 1
    assert result["scanner_bonus"] > 0
    assert result["inherent_risk"] > 0
    assert result["residual_risk"] > 0  # self-reported 100% controls cannot erase risk
    assert result["ai_used"] is False
    assert result["key_findings"][0]["severity"] == "HIGH"
    assert result["recommendations"]


def test_contextual_analysis_returns_transparent_fallback_without_api_key(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    result = analyze_contextual_risk({
        "asset_criticality": 3,
        "threat_likelihood": 3,
        "vulnerability_severity": 3,
        "control_effectiveness": 20,
        "asset_name": "Test service",
        "environment": "development",
        "exposure": "unknown",
        "data_sensitivity": "internal",
        "agent_permissions": [],
        "scanner_findings": [],
    })
    assert result["ai_status"] == "GROQ_API_KEY_NOT_CONFIGURED"
    assert "prioritization heuristic" in result["analysis_summary"]


def test_contextual_risk_api_endpoint_uses_response_schema(monkeypatch):
    from fastapi.testclient import TestClient
    from backend.main import app

    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    client = TestClient(app)
    response = client.post("/risk/analyze", json={
        "asset_criticality": 5,
        "threat_likelihood": 4,
        "vulnerability_severity": 5,
        "control_effectiveness": 100,
        "asset_name": "Production agent",
        "asset_description": "Reads repository files",
        "business_impact": "Credential exposure",
        "environment": "production",
        "exposure": "internet",
        "data_sensitivity": "restricted",
        "agent_permissions": ["read files", "execute tools"],
        "scanner_findings": [{
            "rule_id": "CODE_EVAL", "title": "Dynamic eval detected", "severity": "HIGH",
            "description": "Dynamic execution", "recommendation": "Avoid eval", "evidence": "eval(userInput)"
        }],
    })
    assert response.status_code == 200
    body = response.json()
    assert body["scanner_findings_analyzed"] == 1
    assert body["risk_score"] > 0
    assert body["ai_used"] is False
