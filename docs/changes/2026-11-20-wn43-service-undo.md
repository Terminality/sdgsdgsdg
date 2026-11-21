# WN-43: service undo starts only what was running

The undo line for Spooler and Remote Registry always ended with `Start-Service`. A service that was stopped before WN-43 would be started by the undo. Now the undo starts it only if it was running, and an unknown start type falls back to Manual instead of an empty value.
