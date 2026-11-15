# tools

Repo maintenance. These are not competition scripts and are never copied to a target host.

| Tool | What it does |
| --- | --- |
| `update-docs.sh` | Regenerates `roles/*/README.md` and `docs/STATUS.md` from `docs/catalog.csv` |
| `build.sh` (LB-03) | Pastes the library into each script and writes single-file scripts to `dist/` plus `MANIFEST.sha256`. Run it after changing anything in `roles/` or `lib/`; `--check` tells you if `dist/` is out of date |
