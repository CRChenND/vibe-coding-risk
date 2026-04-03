# Risk Annotator

This is a local manual review tool for the 1887-row risk dataset.

## Run

Serve the repo root with a static server, then open:

`http://localhost:8000/risk_annotator/`

For example:

```bash
python3 -m http.server 8000
```

## Data it loads

- `analysis/output/risk_dataset_export_1887/manifest.json`
- `analysis/output/risk_dataset_export_1887/source_files/*.json`

## Annotation fields

- `review_state`: `pass`, `needs_fix`, `reject`, `unsure`
- `cwe_correct`: `yes`, `no`, `unsure`
- `reason_correct`: `yes`, `no`, `unsure`
- `corrected_cwe`
- `corrected_reason`
- `notes`

Annotations are autosaved in browser `localStorage`.

## Export

Use the `Export JSON` or `Export CSV` buttons in the top bar.
