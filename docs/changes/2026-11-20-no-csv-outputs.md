# No CSV files in the results

- The library deletes the CSV working files at the end of every run
  (cc_finish, and cc_die): each one becomes a .txt table first unless the
  script wrote one, and the csv/ folder goes.  Same without a run folder.
  BT_TEST_KEEP_CSV=1 keeps them, for tests only.
- New cc_csv_table: CSV to a " | " table (the look SH-03 has).  SH-05 writes
  its section tables this way, so SH-04 still compares two SH-05 runs; it
  still reads older runs' csv/ too.  NW-20 already reads SH-03's ports.txt.
- SV-26: the ban history is bans.txt (a " | " table); an older bans.csv is
  turned into it once.
- Script headers and the manual no longer mention csv/ output.
