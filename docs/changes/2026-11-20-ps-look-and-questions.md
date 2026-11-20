# PowerShell library 0.7.0: the same look and questions as the Linux scripts

- New in lib/lib.ps1: Write-CcShow, Write-CcHeader, Write-CcLegend (colours,
  numbered headers, legend, output.txt); Read-CcChoice, Read-CcAsk,
  Read-CcText, Read-CcBox (questions, Enter = default, -Batch takes the
  defaults, the box guessed from the machine); Use-CcNumberedDir (NAME-N run
  folders, no CSV left); New-CcTable / Add-CcTableRow / Format-CcTable (.txt
  tables); Start-CcTimer / Complete-CcTimer (the revert timer, as a one-time
  scheduled task running as SYSTEM).
- Initialize-Cc reads -Batch and -NoColor.  Add-CcUndo also writes the run's
  own undo.txt.  Test hooks: BT_TEST_ANSWERS, BT_TEST_BOX_GUESS,
  BT_TEST_SCHTASKS.
- The PowerShell template uses all of it.  Old scripts keep working.
