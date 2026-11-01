# Current project evidence

- `Portkey_Implementation_and_Feature_Mapping_Report.pdf`: seven-page implementation, traceability and verification report.
- `Portkey Presentation.pdf`: fourteen-slide presentation in the original 16:9 PDF format.
- `CODE_GUIDE.md`: custom source-file inventory and a presentation walkthrough separating our code from dependencies/generated files.
- `evidence.json`: final local verification index and explicit external-readiness flags.
- `initial-audit.md`: historical findings before this implementation pass.

Rebuild from repository root with Python containing the packages in `docs/requirements.txt`:

```bash
python scripts/buildDocs.py
```

The generator uses installed Noto Sans fonts and evidence in `benchmark-results/`. It copies final PDFs to the parent workspace `../docs` to replace the previous hand-in files. Current application screenshots are under `../outputs`. The saved PDFs have been rendered and visually checked. They are static PDFs, matching the original deliverable format; no editable PowerPoint file is claimed.
