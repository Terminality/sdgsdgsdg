# SV-46 File share hardening (new)

- New script for the file-share box: Samba (SMB1, NTLMv1/lanman, lines that
  run programs, wide links, guest shares anyone can write, smb.conf mode) and
  NFS (no_root_squash, insecure).  Each fix asked; guest-write defaults to no.
  testparm, reload, port 445 and exportfs checked after, put back if broken.
