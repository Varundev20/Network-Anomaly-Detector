# Third-party components and licences

Node Sentinel's own code is MIT-licensed (see `LICENSE`). It depends on:

| Component | Use | Licence |
|---|---|---|
| Qwen3 4B / Qwen3 1.7B (Alibaba Qwen team) | Local open-weight language model | Apache-2.0 |
| Ollama | Local model runtime (localhost:11434) | MIT |
| Streamlit | Web dashboard | Apache-2.0 |
| pandas | CSV loading and aggregation | BSD-3-Clause |
| requests | HTTP calls to the local Ollama server | Apache-2.0 |
| pytest | Tests | MIT |
| Graphify | Codebase graph (required by the event) | See the Graphify project |

## Dataset

`data/sample_data/` contains short excerpts (selected minutes and columns, rows unchanged)
of the **CICIDS2017** intrusion detection evaluation dataset by the Canadian
Institute for Cybersecurity, University of New Brunswick. The dataset is used
with attribution for research and education. Please cite:

> Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, "Toward Generating
> a New Intrusion Detection Dataset and Intrusion Traffic Characterization",
> 4th International Conference on Information Systems Security and Privacy
> (ICISSP), Portugal, January 2018.
