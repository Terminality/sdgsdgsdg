# Changes

One file per change, named `YYYY-MM-DD-short-name.md` (the date first, so `ls` sorts them by date; `ls -r` shows the newest first). History before 2026-11-20: [`../CHANGELOG.md`](../CHANGELOG.md).

Each file says:

- the title line: `# YYYY-MM-DD: what changed (library X.Y.Z when it changed)`
- one bullet per script touched: what changed, in plain words
- a `Tested:` bullet: the shells and awks, the built copies, and what was not tested

A new file never touches another change's lines, so two changes open at the same time do not conflict.
