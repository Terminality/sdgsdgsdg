# SV-45 Gitea hardening (new)

- New script for the Gitea box: install page (INSTALL_LOCK), sign-ups, git
  hooks, migrations and webhooks into the inside network, hooks planted in
  repositories, admin accounts, app.ini permissions.  Each fix asked (Enter =
  yes); Gitea restarted and the login page checked after, put back if it broke.
- lib.test.sh: the box test no longer uses `sed -i` (lint).
