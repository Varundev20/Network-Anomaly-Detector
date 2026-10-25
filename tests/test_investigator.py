import json

from agent import investigator

GOOD_REPORT = {
    "summary": "Source 172.16.0.1 contacted 79 service ports; this is not confirmed as an attack.",
    "observed_evidence": ["79 distinct service ports in 60 s, threshold 50."],
    "possible_explanations": ["Port scan", "Inventory tool run by IT"],
    "confidence": "medium",
    "uncertainty": "Only flow summaries are available.",
    "recommended_checks": ["Identify the device owner."],
    "missing_information": ["Authorisation records"],
}
TOOL_OUTPUT = [{"peak_value": 79, "threshold": 50, "window_seconds": 60}]


def test_valid_report_passes():
    errors, warnings = investigator.validate_report(GOOD_REPORT, TOOL_OUTPUT)
    assert errors == [] and warnings == []


def test_missing_fields_and_bad_confidence_fail():
    errors, _ = investigator.validate_report({"summary": "x", "confidence": "sure"}, TOOL_OUTPUT)
    assert any("observed_evidence" in e for e in errors)
    assert any("confidence" in e for e in errors)


def test_overconfident_wording_fails_but_negation_is_fine():
    bad = dict(GOOD_REPORT, summary="This is a confirmed port scan.")
    errors, _ = investigator.validate_report(bad, TOOL_OUTPUT)
    assert any("over-confident" in e for e in errors)
    ok = dict(GOOD_REPORT, summary="Intent cannot be confirmed from flow data.")
    assert investigator.validate_report(ok, TOOL_OUTPUT)[0] == []


def test_shares_quoted_as_percentages_are_grounded():
    report = dict(GOOD_REPORT, observed_evidence=["32.1% of flows had no reply."])
    _, warnings = investigator.validate_report(report, [{"share": 0.321}])
    assert warnings == []


def test_invented_numbers_are_flagged():
    report = dict(GOOD_REPORT, observed_evidence=["4500 ports were scanned."])
    _, warnings = investigator.validate_report(report, TOOL_OUTPUT)
    assert any("4500" in w for w in warnings)


def test_unreachable_model_gives_fallback_report(db, stored_alert):
    inv = investigator.investigate(stored_alert.alert_id, db_path=db, base_url="http://127.0.0.1:9")
    assert inv.status == "fallback"
    assert "Could not reach" in inv.error
    assert inv.report["confidence"] == "low"
    assert "79" in json.dumps(inv.report["observed_evidence"])


def test_agent_loop_runs_requested_tools(db, stored_alert, monkeypatch):
    aid = stored_alert.alert_id
    replies = iter([
        {"message": {"content": "", "tool_calls": [
            {"function": {"name": "get_alert_details", "arguments": {"alert_id": aid}}}]}},
        {"message": {"content": "", "tool_calls": [
            {"function": {"name": "count_distinct_ports", "arguments": {"alert_id": aid}}},
            {"function": {"name": "summarize_time_window", "arguments": {"alert_id": aid}}}]}},
        {"message": {"content": json.dumps(GOOD_REPORT)}, "eval_count": 100, "eval_duration": 10**10},
    ])
    monkeypatch.setattr(investigator, "chat", lambda *a, **k: next(replies))
    inv = investigator.investigate(aid, db_path=db)
    assert inv.status == "ok", inv.error
    assert [tc.name for tc in inv.tool_calls] == ["get_alert_details", "count_distinct_ports",
                                                  "summarize_time_window"]
    assert all(tc.requested_by == "model" for tc in inv.tool_calls)
    assert inv.tokens_per_second == 10.0


def test_progress_callback_sees_every_tool_call(db, stored_alert, monkeypatch):
    aid = stored_alert.alert_id
    replies = iter([
        {"message": {"content": "", "tool_calls": [
            {"function": {"name": "get_alert_details", "arguments": {"alert_id": aid}}}]}},
        {"message": {"content": "done"}},
        {"message": {"content": json.dumps(GOOD_REPORT)}},
    ])
    monkeypatch.setattr(investigator, "chat", lambda *a, **k: next(replies))
    seen = []
    investigator.investigate(aid, db_path=db, on_tool_call=lambda call: seen.append(call.name))
    assert seen == ["get_alert_details"]


def test_app_supplies_details_when_model_skips_tools(db, stored_alert, monkeypatch):
    replies = iter([{"message": {"content": "I will just answer."}},
                    {"message": {"content": json.dumps(GOOD_REPORT)}}])
    monkeypatch.setattr(investigator, "chat", lambda *a, **k: next(replies))
    inv = investigator.investigate(stored_alert.alert_id, db_path=db)
    assert inv.tool_calls[0].requested_by == "app"
    assert any("did not request" in w for w in inv.warnings)


def test_rejected_report_is_retried_then_falls_back(db, stored_alert, monkeypatch):
    bad = json.dumps(dict(GOOD_REPORT, summary="Definitely an attack."))
    replies = iter([{"message": {"content": ""}}, {"message": {"content": bad}},
                    {"message": {"content": bad}}])
    monkeypatch.setattr(investigator, "chat", lambda *a, **k: next(replies))
    inv = investigator.investigate(stored_alert.alert_id, db_path=db)
    assert inv.status == "fallback"
    assert "over-confident" in inv.error
