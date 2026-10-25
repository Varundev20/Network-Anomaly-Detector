from backend import config
from conftest import burst, make_flows
from backend.data_loader import load_flows
from backend.detector import detect


def test_normal_traffic_has_no_alerts():
    flows = make_flows(burst("10.0.0.1", 0, 50, label="BENIGN"))
    assert detect(flows, burst_threshold=100) == []


def test_value_equal_to_threshold_does_not_alert():
    flows = make_flows(burst("10.0.0.1", 0, 100))
    assert detect(flows, burst_threshold=100) == []


def test_value_above_threshold_alerts_with_evidence():
    flows = make_flows(burst("10.0.0.1", 0, 101))
    [alert] = detect(flows, burst_threshold=100)
    assert alert.rule_name == "connection_burst"
    assert alert.source == "10.0.0.1"
    assert alert.measured_value == 101
    assert alert.threshold == 100
    assert alert.window_start == "2017-07-07T15:00:00"
    assert alert.window_end == "2017-07-07T15:01:00"


def test_consecutive_windows_merge_and_far_ones_do_not():
    rows = burst("10.0.0.1", 0, 150) + burst("10.0.0.1", 1, 120) + burst("10.0.0.1", 10, 130)
    alerts = detect(make_flows(rows), burst_threshold=100)
    assert [a.window_count for a in alerts] == [2, 1]
    assert alerts[0].measured_value == 150


def test_port_spread_counts_only_service_ports():
    # 200 different *high* ports (e.g. server replies) must not trigger the rule.
    high = [("2017-07-07 15:00:00", "10.0.0.9", "10.0.0.1", 40000 + p) for p in range(200)]
    low = [("2017-07-07 15:00:00", "10.0.0.2", "10.0.0.1", p) for p in range(1, 61)]
    alerts = detect(make_flows(high + low), burst_threshold=10_000, port_spread_threshold=50)
    assert [(a.rule_name, a.source, a.measured_value) for a in alerts] == [("port_spread", "10.0.0.2", 60)]


def test_empty_input():
    assert detect(make_flows([])) == []


def test_sample_files_produce_expected_alerts():
    expected = {
        "benign_sample.csv": set(),
        "ddos_sample.csv": {("connection_burst", "172.16.0.1")},
        "portscan_sample.csv": {("connection_burst", "172.16.0.1"), ("port_spread", "172.16.0.1")},
    }
    for name, rules in expected.items():
        flows, _ = load_flows(config.SAMPLE_DIR / name)
        assert {(a.rule_name, a.source) for a in detect(flows)} == rules, name
