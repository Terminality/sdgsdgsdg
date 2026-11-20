# One manual per role: Linux, network, applications

- docs/manual-linux.md, docs/manual-network.md, docs/manual-applications.md:
  before you start, the first 15 minutes (which script, when, what to look at),
  what to run after, "when this happens, run that", notes for this network,
  then a deep dive for every script of the role.
- The playbooks are written by hand in docs/playbooks/<role>.md; each deep dive
  is the script's section of docs/MANUAL.md.  tools/role-manuals.sh builds the
  three files; build.test fails when they are out of date.
- docs/MANUAL.md: command examples no longer pass an old p.csv protected list
  (protected.txt in the out folder is found by itself); every box question
  lists the seven box kinds.
