"""Load CICIDS2017-style flow CSVs into one clean, consistent table.

Each row of the input is one network *flow* (a connection summary), not a
single packet. The loader:
  * strips the leading spaces CICIDS2017 puts in column names,
  * keeps only the columns the app needs and renames them,
  * parses the timestamps (see parse_timestamps for the quirks),
  * drops rows that cannot be used and reports how many it dropped.
"""
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

# CICIDS2017 column name -> internal name
COLUMN_MAP = {
    "Source IP": "src_ip",
    "Source Port": "src_port",
    "Destination IP": "dst_ip",
    "Destination Port": "dst_port",
    "Protocol": "protocol",
    "Timestamp": "timestamp_raw",
    "Flow Duration": "duration_us",
    "Total Fwd Packets": "fwd_packets",
    "Total Backward Packets": "bwd_packets",
    "Total Length of Fwd Packets": "fwd_bytes",
    "Total Length of Bwd Packets": "bwd_bytes",
    "SYN Flag Count": "syn_flags",
    "Label": "label",
}
REQUIRED = ["src_ip", "dst_ip", "dst_port", "timestamp_raw"]
NUMERIC = ["src_port", "dst_port", "protocol", "duration_us", "fwd_packets",
           "bwd_packets", "fwd_bytes", "bwd_bytes", "syn_flags"]
PROTOCOL_NAMES = {6: "TCP", 17: "UDP", 0: "HOPOPT"}

# CICIDS2017 was recorded 08:00-18:00 but most files use a 12-hour clock
# without AM/PM, so "1:00" means 13:00. Hours before this are treated as PM.
FIRST_WORKING_HOUR = 8


class DataLoadError(ValueError):
    """Raised when a file cannot be used at all (wrong format, empty...)."""


@dataclass
class LoadReport:
    source: str
    rows_read: int = 0
    rows_kept: int = 0
    dropped: dict[str, int] = field(default_factory=dict)
    assumptions: list[str] = field(default_factory=list)


def parse_timestamps(raw: pd.Series) -> pd.Series:
    """Parse '7/7/2017 3:05' and '03/07/2017 09:00:12' style values.

    Dates are day/month/year. Times without AM/PM before 08:00 are moved
    into the afternoon. Values that cannot be parsed become NaT.
    """
    text = raw.astype("string").str.strip()
    parsed = pd.to_datetime(text, format="%d/%m/%Y %H:%M", errors="coerce")
    with_seconds = pd.to_datetime(text, format="%d/%m/%Y %H:%M:%S", errors="coerce")
    parsed = parsed.fillna(with_seconds)
    afternoon = parsed.dt.hour < FIRST_WORKING_HOUR
    return parsed.where(~afternoon, parsed + pd.Timedelta(hours=12))


def load_flows(source, name: str | None = None) -> tuple[pd.DataFrame, LoadReport]:
    """Read a CSV path or file-like object and return (flows, report)."""
    report = LoadReport(source=name or str(getattr(source, "name", source)))
    try:
        df = pd.read_csv(source, encoding="cp1252", skipinitialspace=True,
                         low_memory=False)
    except pd.errors.EmptyDataError as exc:
        raise DataLoadError("The file is empty.") from exc

    df.columns = [str(c).strip() for c in df.columns]
    df = df[[c for c in COLUMN_MAP if c in df.columns]].rename(columns=COLUMN_MAP)
    missing = [c for c in REQUIRED if c not in df.columns]
    if missing:
        raise DataLoadError(f"Missing required columns: {', '.join(missing)}")
    report.rows_read = len(df)

    blank = df[REQUIRED].isna().all(axis=1)
    if blank.any():
        report.dropped["blank rows"] = int(blank.sum())
        df = df[~blank]

    for col in NUMERIC:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    df["timestamp"] = parse_timestamps(df["timestamp_raw"])
    report.assumptions.append(
        f"Times before {FIRST_WORKING_HOUR:02d}:00 were read as PM "
        "(the dataset uses a 12-hour clock without AM/PM)."
    )

    invalid = df["timestamp"].isna() | df["src_ip"].isna() | df["dst_ip"].isna() | df["dst_port"].isna()
    if invalid.any():
        report.dropped["invalid timestamp/IP/port"] = int(invalid.sum())
        df = df[~invalid]

    if "label" not in df.columns:
        df["label"] = pd.NA
    df["label"] = df["label"].astype("string").str.replace("\x96", "-", regex=False).str.replace("–", "-", regex=False)
    for col in ("src_ip", "dst_ip"):
        df[col] = df[col].astype("string").str.strip()
    df["dst_port"] = df["dst_port"].astype("int64")

    df = df.drop(columns=["timestamp_raw"]).sort_values("timestamp", kind="stable")
    df = df.reset_index(drop=True)
    report.rows_kept = len(df)
    return df, report


def list_datasets(*folders: Path) -> dict[str, Path]:
    """Return {display name: path} for every CSV in the given folders."""
    found: dict[str, Path] = {}
    for folder in folders:
        if folder and Path(folder).is_dir():
            for path in sorted(Path(folder).glob("*.csv")):
                found[f"{Path(folder).name}/{path.name}"] = path
    return found
