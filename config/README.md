# config

File formats the scripts read. Only the `*.example.*` files and `hosts.flokid.txt` (addresses from the team packet, no passwords) are committed; real host lists, protected lists and credential sheets are ignored by git and must stay out of the repository.

| File | Read by | Purpose |
| --- | --- | --- |
| `protected.example.txt` | Every script that changes things, through the libraries | Things no script may close, stop, block or change |
| `hosts.flokid.txt` | The same scripts | The Flókið boxes from the team packet, ready to copy to `hosts.txt`. Fill in the scored services and logins at 9 AM |
| `hosts.example.txt` | Network scan (SH-03) and every network device script (NW-01, NW-10, NW-12, NW-20, NW-21, NW-30); later fan-out and the run sheet | One line per machine the team defends: columns separated by spaces, `-` for an empty one. Copy it to `hosts.txt`. An older `hosts.csv` is still read |

The protected list format is final and is implemented in both libraries. The host list format is version 1 and may gain columns when the host list builder (AU-01) is written.
