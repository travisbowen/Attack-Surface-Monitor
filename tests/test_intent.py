"""
Characterization tests for asm_lite.intent.

The module answers two separate questions and the tests keep them separate:
  1. what does this surface look like  -> intent
  2. does that conflict with it being reachable -> exposure_mismatch

Note the deliberate asymmetry pinned below: an internal-looking hostname wins
the intent label over an admin signal, but the admin signal still raises a
mismatch on its own.
"""

from asm_lite.intent import annotate_http_findings, infer_intent_for_finding


def test_ordinary_reachable_endpoint_is_user_facing_with_no_mismatch():
    finding = {
        "url": "https://www.example.com",
        "final_url": "https://www.example.com/",
        "status_code": 200,
        "title": "Welcome",
        "error": None,
    }

    result = infer_intent_for_finding(finding)

    assert result["intent"] == "user-facing"
    assert result["exposure_mismatch"] is False
    assert result["mismatch_reasons"] == []


def test_internal_hostname_that_answers_is_an_exposure_mismatch():
    finding = {
        "url": "https://staging.example.com",
        "status_code": 200,
        "title": "Staging",
    }

    result = infer_intent_for_finding(finding)

    assert result["intent"] == "internal-looking"
    assert result["exposure_mismatch"] is True
    assert len(result["mismatch_reasons"]) == 1


def test_admin_path_makes_the_intent_admin():
    finding = {
        "url": "https://www.example.com/admin",
        "status_code": 200,
        "title": "Dashboard",
    }

    result = infer_intent_for_finding(finding)

    assert result["intent"] == "admin"
    assert result["exposure_mismatch"] is True


def test_internal_label_outranks_admin_but_both_reasons_are_kept():
    finding = {
        "url": "https://dev.example.com/login",
        "status_code": 401,
        "title": "Sign In",
    }

    result = infer_intent_for_finding(finding)

    # Internal naming is the more actionable label, so it wins the slot.
    assert result["intent"] == "internal-looking"
    assert len(result["intent_reasons"]) == 2
    # Both conditions raise a mismatch, so both reasons are recorded.
    assert len(result["mismatch_reasons"]) == 2


def test_unreachable_internal_host_keeps_its_label_but_raises_no_mismatch():
    finding = {
        "url": "https://internal.example.com",
        "status_code": None,
        "error": "ConnectTimeout: timed out",
    }

    result = infer_intent_for_finding(finding)

    assert result["intent"] == "internal-looking"
    # Nothing was proven reachable, so there is nothing to call a mismatch.
    assert result["exposure_mismatch"] is False


def test_a_404_is_reachable_enough_to_classify_but_not_to_flag():
    finding = {"url": "https://www.example.com", "status_code": 404, "error": None}

    result = infer_intent_for_finding(finding)

    assert result["intent"] == "user-facing"
    assert result["exposure_mismatch"] is False


def test_auth_wall_statuses_count_as_exposed_surface():
    for status in (401, 403):
        finding = {"url": "https://staging.example.com", "status_code": status}

        assert infer_intent_for_finding(finding)["exposure_mismatch"] is True


def test_redirect_statuses_count_as_exposed_surface():
    for status in (301, 302, 307, 308):
        finding = {"url": "https://staging.example.com", "status_code": status}

        assert infer_intent_for_finding(finding)["exposure_mismatch"] is True


def test_admin_signal_in_the_final_url_is_caught_after_a_redirect():
    # The landing URL looks innocuous; the redirect target is the tell.
    finding = {
        "url": "https://portal.example.com",
        "final_url": "https://portal.example.com/console/dashboard",
        "status_code": 200,
        "title": "Portal",
    }

    result = infer_intent_for_finding(finding)

    assert result["intent"] == "admin"
    assert result["exposure_mismatch"] is True


def test_annotation_preserves_original_keys_and_does_not_mutate_input():
    findings = [
        {"url": "https://www.example.com", "status_code": 200, "server": "nginx"},
        {"url": "https://dev.example.com", "status_code": 200},
    ]

    annotated = annotate_http_findings(findings)

    assert len(annotated) == 2
    assert annotated[0]["server"] == "nginx"
    assert annotated[1]["intent"] == "internal-looking"
    # Inputs untouched.
    assert "intent" not in findings[0]
    assert "intent" not in findings[1]
