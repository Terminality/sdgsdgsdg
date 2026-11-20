# One box list for every script, with a guess (library 0.7.0)

- `cc_box_ask` asks "Which box is this?" the same way in all 14 scripts that
  have `--box` (LX-21, 22, 25, 26, 31, 39; SV-20, 21, 30, 31, 40, 41, 42, 50).
  Every script now takes every box kind: splunk, webmail, ecomm, fileshare,
  gitea, web, other.
- It guesses the box from its files (nothing is changed):
  Splunk (/opt/splunk), webmail (Roundcube, or postfix plus dovecot), Gitea
  (app.ini or the gitea program), file share (a Samba share or an NFS
  export), web (nginx, Apache, lighttpd, Caddy).  It shows
  "This box looks like: gitea (/etc/gitea/app.ini)" and makes that the
  answer for Enter.  A plain web server does not replace a script's own
  default (ecomm in SV-20/21/42, webmail in SV-31/40/41).
- With --batch the guess is used, so LX-25 keeps a Gitea or file-share box's
  scored ports open without being told.
