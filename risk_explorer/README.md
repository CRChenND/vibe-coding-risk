# Risk Explorer

This folder contains a lightweight interactive website for exploring the project's code-risk results.

## What It Shows

- Overview metrics and key insights from the latest `analysis/output/code_risk_analysis`
- Distribution views for attribution, top CWE, emergence buckets, and temporal degradation
- An interactive findings browser with filters for `CWE`, `primary_cause`, `severity`, and block type
- Drill-down detail panels for concrete risky findings

## How To Refresh Data

From the repo root:

```bash
python3 analysis/scripts/build_risk_explorer_data.py
```

This writes:

```text
risk_explorer/data/site_data.json
```

## How To View Locally

From the repo root:

```bash
python3 -m http.server 8123
```

Then open:

```text
http://localhost:8123/risk_explorer/
```
