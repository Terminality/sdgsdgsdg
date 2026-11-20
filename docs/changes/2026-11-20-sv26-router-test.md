# 2026-11-20: SV-26 is tested never to ban the router

- **SV-26** (no change to the script): a new test proves the default gateway (the router, `.2` on this network) is never banned, even when it is over the limit. With NAT every outside client can look like the router, so banning it would cut every scored service off. The run shows it as `NOT BANNED` with the reason, and nothing is sent to the firewall for it.
- Tested: sv26 under dash, bash, ksh93, mksh, yash and busybox sh; gawk, mawk and busybox awk; the built copy. The router comes from a stand-in `ip route` (`default via ...`) and a log of SSH failures from it.
