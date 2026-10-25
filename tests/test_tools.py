import json

from agent import tools


def test_tools_return_facts_and_never_the_label(db, stored_alert):
    for name in tools.TOOLS:
        result = tools.run_tool(name, {"alert_id": stored_alert.alert_id}, stored_alert.alert_id, db_path=db)
        assert "error" not in result, result
        text = json.dumps(result)
        assert "PortScan" not in text and '"label"' not in text

    ports = tools.count_distinct_ports(stored_alert.alert_id, db_path=db)
    assert ports["distinct_service_ports_below_1024"] == 79


def test_only_the_selected_alert_can_be_queried(db, stored_alert):
    result = tools.run_tool("get_alert_details", {"alert_id": 999}, stored_alert.alert_id, db_path=db)
    assert "error" in result


def test_unknown_tools_and_bad_arguments_are_rejected(db, stored_alert):
    assert "error" in tools.run_tool("run_shell", {"alert_id": 1}, stored_alert.alert_id, db_path=db)
    assert "error" in tools.run_tool("get_alert_details", {"alert_id": "x"}, stored_alert.alert_id, db_path=db)
