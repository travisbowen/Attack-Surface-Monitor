"""
Characterization tests for asm_lite.score.

These pin the raw scoring arithmetic and its normalized 0..100 output. They are
deliberately explicit about the individual point contributions so that changing
a weight fails loudly rather than silently shifting every report's ordering.
"""

from asm_lite.score import score_http_finding, score_http_findings


def test_plain_https_endpoint_scores_tls_unknown_plus_reachable():
    # https with no captured TLS expiry (+5), 200 response (+5)
    finding = {
        "url": "https://www.example.com",
        "final_url": None,
        "status_code": 200,
        "title": "Welcome",
        "server": None,
        "tls_not_after": None,
        "error": None,
    }

    result = score_http_finding(finding)

    assert result["risk_score"] == 11
    assert result["tags"] == ["tls-unknown"]


def test_cleartext_http_scores_higher_than_https():
    # http (+10), 200 (+5). No tls-unknown penalty: that branch is https-only.
    finding = {
        "url": "http://www.example.com",
        "final_url": "http://www.example.com",
        "status_code": 200,
    }

    result = score_http_finding(finding)

    assert result["risk_score"] == 17
    assert "http" in result["tags"]
    assert "tls-unknown" not in result["tags"]
    # final_url equal to url is not a redirect
    assert "redirect" not in result["tags"]


def test_captured_tls_expiry_suppresses_the_tls_unknown_penalty():
    finding = {
        "url": "https://www.example.com",
        "status_code": 200,
        "tls_not_after": "Jan  1 00:00:00 2030 GMT",
    }

    result = score_http_finding(finding)

    assert result["risk_score"] == 6
    assert "tls-unknown" not in result["tags"]


def test_admin_surface_on_internal_hostname_accumulates_every_signal():
    # redirect (+5), admin title (+35), nginx (+2), 401 (+12), staging host (+20)
    finding = {
        "url": "https://admin.staging.example.com",
        "final_url": "https://admin.staging.example.com/login",
        "status_code": 401,
        "title": "Login",
        "server": "nginx/1.24.0",
        "tls_not_after": "Jan  1 00:00:00 2030 GMT",
        "error": None,
    }

    result = score_http_finding(finding)

    assert result["risk_score"] == 83
    assert set(result["tags"]) == {
        "redirect",
        "admin-surface",
        "common-webserver",
        "auth-wall",
        "internal-looking",
    }
    # Five tags but four reasons: the "common-webserver" tag is scored silently,
    # with no matching human-readable reason.
    assert len(result["reasons"]) == 4


def test_uat_hostname_gets_internal_naming_risk_points():
    # reachable (+5), uat host (+20)
    finding = {
        "url": "https://uat.example.com",
        "status_code": 200,
        "tls_not_after": "Jan  1 00:00:00 2030 GMT",
    }

    result = score_http_finding(finding)

    assert result["risk_score"] == 28
    assert "internal-looking" in result["tags"]


def test_request_error_still_produces_a_triageable_score():
    finding = {
        "url": "https://dead.example.com",
        "status_code": None,
        "error": "ConnectTimeout: timed out",
    }

    result = score_http_finding(finding)

    # error (+5) + tls-unknown (+5)
    assert result["risk_score"] == 11
    assert "error" in result["tags"]


def test_server_error_status_is_scored():
    finding = {
        "url": "https://www.example.com",
        "status_code": 503,
        "tls_not_after": "Jan  1 00:00:00 2030 GMT",
    }

    result = score_http_finding(finding)

    assert result["risk_score"] == 9
    assert "server-error" in result["tags"]


def test_unrecognised_status_contributes_nothing():
    # 404 is not in any scoring bucket.
    finding = {
        "url": "https://www.example.com",
        "status_code": 404,
        "tls_not_after": "Jan  1 00:00:00 2030 GMT",
    }

    assert score_http_finding(finding)["risk_score"] == 0


def test_worst_case_reaches_documented_maximum_score():
    # Every signal the module can award, stacked onto one finding.
    worst = {
        "url": "http://admin.internal.example.com/login",
        "final_url": "http://admin.internal.example.com/login/sso",
        "status_code": 401,
        "title": "Admin Console Login",
        "server": "nginx",
        "tls_not_after": None,
        "error": "ReadTimeout: timed out",
    }

    result = score_http_finding(worst)

    assert result["risk_score"] == 100


def test_scoring_does_not_mutate_the_input_finding():
    finding = {"url": "https://www.example.com", "status_code": 200}

    score_http_finding(finding)

    assert "risk_score" not in finding
    assert "tags" not in finding


def test_findings_are_returned_highest_risk_first():
    findings = [
        {"url": "https://www.example.com", "status_code": 404, "tls_not_after": "x"},
        {
            "url": "https://admin.staging.example.com",
            "final_url": "https://admin.staging.example.com/login",
            "status_code": 401,
            "title": "Login",
            "server": "nginx",
            "tls_not_after": "x",
        },
        {"url": "http://www.example.com", "status_code": 200},
    ]

    scored = score_http_findings(findings)

    assert [f["risk_score"] for f in scored] == [83, 17, 0]
    assert len(scored) == len(findings)
