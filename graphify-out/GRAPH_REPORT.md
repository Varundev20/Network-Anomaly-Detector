# Graph Report - Network-Anomaly-Detector  (2026-10-25)

## Corpus Check
- cluster-only mode — file stats not available

## Summary
- 183 nodes · 425 edges · 7 communities (6 shown, 1 thin omitted)
- Extraction: 97% EXTRACTED · 3% INFERRED · 0% AMBIGUOUS · INFERRED: 13 edges (avg confidence: 0.92)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- Community 0
- Community 1
- Community 2
- Community 3
- Community 4
- Community 5
- Community 6

## God Nodes (most connected - your core abstractions)
1. `investigate()` - 22 edges
2. `detect()` - 22 edges
3. `load_flows()` - 18 edges
4. `connect()` - 15 edges
5. `Alert` - 13 edges
6. `validate_report()` - 12 edges
7. `make_flows()` - 11 edges
8. `save_analysis()` - 9 edges
9. `summarize_time_window()` - 9 edges
10. `DataLoadError` - 8 edges

## Surprising Connections (you probably didn't know these)
- `test_empty_file_raises()` --uses--> `DataLoadError`  [INFERRED]
  tests/test_data_loader.py → backend/data_loader.py
- `test_missing_columns_raise()` --uses--> `DataLoadError`  [INFERRED]
  tests/test_data_loader.py → backend/data_loader.py
- `stored_alert()` --calls--> `save_analysis()`  [EXTRACTED]
  tests/conftest.py → backend/storage.py
- `main()` --calls--> `investigate()`  [EXTRACTED]
  scripts/repeat_runs.py → agent/investigator.py
- `test_agent_loop_runs_requested_tools()` --calls--> `investigate()`  [EXTRACTED]
  tests/test_investigator.py → agent/investigator.py

## Import Cycles
- None detected.

## Communities (7 total, 1 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.08
Nodes (21): chat(), _clean(), fallback_report(), investigate(), run(), ModelUnavailable, _numbers_in(), ollama_status() (+13 more)

### Community 1 - "Community 1"
Cohesion: 0.12
Nodes (18): evaluate(), _in_alert(), Alert, connect(), flow_count(), flows_for_alert(), flows_in_range(), flows_per_window() (+10 more)

### Community 2 - "Community 2"
Cohesion: 0.13
Nodes (16): add_windows(), detect(), _merge_windows(), severity_label(), window_stats(), burst(), db(), make_flows() (+8 more)

### Community 3 - "Community 3"
Cohesion: 0.19
Nodes (11): DataLoadError, load_flows(), LoadReport, parse_timestamps(), test_afternoon_times_without_am_pm_are_read_as_pm(), test_column_names_with_spaces_and_bad_rows(), test_empty_file_raises(), test_en_dash_in_labels_is_normalised() (+3 more)

### Community 4 - "Community 4"
Cohesion: 0.18
Nodes (10): _alert_or_error(), count_distinct_ports(), get_alert_details(), ollama_tool_schemas(), run_tool(), summarize_time_window(), ToolError, test_only_the_selected_alert_can_be_queried() (+2 more)

### Community 5 - "Community 5"
Cohesion: 0.15
Nodes (3): main(), minute_key(), main()

## Knowledge Gaps
- **1 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `detect()` connect `Community 2` to `Community 1`, `Community 3`, `Community 5`, `Community 6`?**
  _High betweenness centrality (0.118) - this node is a cross-community bridge._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.08084163898117387 - nodes in this community are weakly interconnected._
- **Why does `investigate()` connect `Community 0` to `Community 1`, `Community 4`, `Community 5`?**
  _High betweenness centrality (0.103) - this node is a cross-community bridge._
- **Should `Community 1` be split into smaller, more focused modules?**
  _Cohesion score 0.12121212121212122 - nodes in this community are weakly interconnected._
- **Why does `load_flows()` connect `Community 3` to `Community 2`, `Community 5`, `Community 6`?**
  _High betweenness centrality (0.071) - this node is a cross-community bridge._
- **Should `Community 2` be split into smaller, more focused modules?**
  _Cohesion score 0.1310483870967742 - nodes in this community are weakly interconnected._
- **Should `Community 5` be split into smaller, more focused modules?**
  _Cohesion score 0.14619883040935672 - nodes in this community are weakly interconnected._