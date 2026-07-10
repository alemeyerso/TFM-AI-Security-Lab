from lab.server import AttackRequest, AttackResponse


def test_attack_request_defense_defaults_to_false():
    request = AttackRequest(
        model="gemma4:e2b",
        vector="direct",
        payload_id="direct_001",
    )

    assert request.with_defense is False


def test_attack_request_accepts_defense_flag():
    request = AttackRequest(
        model="gemma4:e2b",
        vector="direct",
        payload_id="direct_001",
        with_defense=True,
    )

    assert request.with_defense is True


def test_attack_response_contains_defense_metadata():
    response = AttackResponse(
        outcome="refused",
        prompt="test prompt",
        response="I cannot help with that request.",
        latency_ms=100,
        model="gemma4:e2b",
        vector="direct",
        payload_id="direct_001",
        defense_applied=True,
        defense_blocked=False,
        defense_verdict="passed",
        input_analysis={"risk_score": 2.5},
        output_analysis={},
    )

    assert response.defense_applied is True
    assert response.defense_blocked is False
    assert response.defense_verdict == "passed"
    assert response.input_analysis["risk_score"] == 2.5
