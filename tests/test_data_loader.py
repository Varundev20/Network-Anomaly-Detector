import io

import pandas as pd
import pytest

from backend import config
from backend.data_loader import DataLoadError, load_flows, parse_timestamps

HEADER = " Source IP, Destination IP, Destination Port, Timestamp, Label\n"


def test_afternoon_times_without_am_pm_are_read_as_pm():
    parsed = parse_timestamps(pd.Series(["7/7/2017 3:05", "7/7/2017 9:30"]))
    assert parsed[0] == pd.Timestamp("2017-07-07 15:05")
    assert parsed[1] == pd.Timestamp("2017-07-07 09:30")


def test_timestamps_with_seconds_are_supported():
    parsed = parse_timestamps(pd.Series(["03/07/2017 08:55:58"]))
    assert parsed[0] == pd.Timestamp("2017-07-03 08:55:58")


def test_column_names_with_spaces_and_bad_rows():
    csv = HEADER + (
        "1.1.1.1,2.2.2.2,80,7/7/2017 3:05,BENIGN\n"
        "1.1.1.1,2.2.2.2,80,not a time,BENIGN\n"
        ",,,,\n"
        "1.1.1.1,2.2.2.2,abc,7/7/2017 3:06,BENIGN\n"
    )
    flows, report = load_flows(io.StringIO(csv), name="t.csv")
    assert len(flows) == 1
    assert report.rows_read == 4
    assert report.dropped == {"blank rows": 1, "invalid timestamp/IP/port": 2}


def test_en_dash_in_labels_is_normalised():
    # Byte 0x96 is how the en dash is stored in the CICIDS2017 files.
    csv = HEADER.encode() + b"1.1.1.1,2.2.2.2,80,7/7/2017 9:05,Web Attack \x96 XSS\n"
    flows, _ = load_flows(io.BytesIO(csv))
    assert flows.loc[0, "label"] == "Web Attack - XSS"


def test_missing_columns_raise():
    with pytest.raises(DataLoadError, match="Missing required columns"):
        load_flows(io.StringIO("a,b\n1,2\n"))


def test_empty_file_raises():
    with pytest.raises(DataLoadError):
        load_flows(io.StringIO(""))


def test_sample_files_load():
    for name in ("portscan_sample.csv", "ddos_sample.csv", "benign_sample.csv"):
        flows, report = load_flows(config.SAMPLE_DIR / name)
        assert report.rows_kept == report.rows_read > 0
