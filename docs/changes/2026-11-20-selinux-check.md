# SELinux check (SH-05) and SELinux denials in SV-50

- SH-05 mac section: SELinux off now or at the next boot (config, kernel
  command line, GRUB), permissive domains (HIGH), policy modules added on the
  box, changed booleans and file labels.  Read only.
- SV-50: when SELinux is enforcing and a scored service is down, the latest
  denial for its program is named with the fix (restorecon), not "turn it off".
