# Review fixes

A fresh-eyes review pass.

- **SV-45:** a shellcheck directive inside a `case` branch stopped shellcheck from reading the file. Moved onto its own line.
- **Revert timer (lib.ps1):** the scheduled task is now made from task XML. The old `/TR` command line broke on Windows PowerShell 5.1 when the run folder path had spaces (nested quotes). It also fires at the exact second now (no rounding to the minute, no after-midnight problem).
- **WN-43 / WN-42 (Server Core):** a Winlogon `Shell` that is not `explorer.exe` is left alone when the box has no `explorer.exe` (Server Core). Setting it back would leave the login with no shell.
- **WN-20:** with more than 5 accounts to change, it asks once: "Go through them one by one?" Enter gives every account a random password, instead of asking about 40 accounts on a DC.
