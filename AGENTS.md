# Rules for changing this repo

For people and AI tools.

1. Read `docs/PLAN.md` and `docs/ENVIRONMENT.md` first.
2. Only build scripts in `docs/catalog.csv`. Want a new one? Ask first.
3. **Test your script before you upload it.** Add a test in `tests/`. Run `sh tests/run-tests.sh` and `sh tests/lint-ps2.sh`. Tests must not change the real system.
4. Never break a scored service or lock someone out. Follow the lockout rule in `docs/PLAN.md`.
5. Follow `docs/CONVENTIONS.md` (POSIX sh, PowerShell 2.0, dry run by default, no passwords in output).
6. Don't change scripts you weren't asked to change.
7. Open a merge request. Don't push to `main`. Say what you tested.
8. Keep docs short and plain.
