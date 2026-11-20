# The protected list and LX-20's password files are text, not CSV

- The protected list is `protected.txt` (one entry a line, split by spaces:
  `port 80/tcp scored web`).  An old `protected.csv`, or comma lines, still
  work.  config/protected.example.txt replaces the .csv example.  Shell and
  PowerShell libraries both.
- LX-20: `--passwords` takes `user password` lines (old `user,password`
  still works); the new passwords go to `passwords.txt` (columns, mode 600);
  no more `csv/accounts.csv` (accounts.txt has the same table).
