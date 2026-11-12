# config

File formats the scripts read. Only the `*.example.csv` files are committed; real host lists, protected lists and credential sheets are ignored by git and must stay out of the repository.

| File | Read by | Purpose |
| --- | --- | --- |
| `protected.example.csv` | Every script that changes things, through the libraries | Things no script may close, stop, block or change |
| `hosts.example.csv` | Network scan (SH-03), config backup (NW-01), device passwords (NW-10); later fan-out and the run sheet | One row per machine the team defends |

The protected list format is final and is implemented in both libraries. The host list format is version 1 and may gain columns when the host list builder (AU-01) is written.
