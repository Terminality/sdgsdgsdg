#!/bin/sh
# Tests for roles/linux/LX-46-safe-updates.sh.
# No real package is touched: stand-in apt-get, apt-mark, dpkg-query and ss
# come first on PATH and keep their "installed" versions, holds and
# listening ports in the test folder.  The package "breakme" closes a port
# when updated and opens it again when rolled back.  A fake /etc holds the
# package sources.  Checks: sources (an unknown one, one with no signature
# check), a held package, the grouping (security / kernel / other), the
# defaults, a dry run changes nothing, --apply updates, a broken service is
# rolled back, the questions on a terminal.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/linux/LX-46-safe-updates.sh"
export CCDC_SKIP_VERIFY=1
O="$T_TMP/out"; S="$T_TMP/stub"; ST="$T_TMP/state"; E="$T_TMP/etc"
mkdir -p "$S" "$ST" "$E/apt/sources.list.d" "$E/apt/apt.conf.d"
export STUB_STATE="$ST" CCDC_TEST_ETC="$E" CCDC_TEST_APTCACHE="$T_TMP/cache"

cat >"$S/apt-get" <<'EOF'
#!/bin/sh
# stand-in apt-get: installed in $STUB_STATE/inst ("pkg ver"), offered in avail ("pkg ver pocket")
D=$STUB_STATE; echo "apt-get $*" >>"$D/calls"
setv() { awk -v p="$1" -v v="$2" '$1 == p { $2 = v } { print }' "$D/inst" >"$D/inst.n"; cat "$D/inst.n" >"$D/inst"; }
case " $* " in
    *" update "*) exit 0 ;;
    *" -s "*) awk 'NR == FNR { i[$1] = $2; next } ($1 in i) && i[$1] != $2 { printf "Inst %s [%s] (%s Ubuntu:24.04/%s [amd64])\n", $1, i[$1], $2, $3 }' "$D/inst" "$D/avail"; exit 0 ;;
    *" download "*) for a; do case "$a" in *=*) case " ${STUB_NODL:-} " in *" ${a%%=*} "*) echo "E: Can't find a source to download version" >&2; exit 100 ;; esac; touch "$(printf '%s_%s_all.deb' "${a%%=*}" "$(printf '%s' "${a#*=}" | sed 's/:/%3a/')")" ;; esac; done; exit 0 ;;
    *" --only-upgrade "*)
        for a; do case "$a" in -*|install|Dpkg*) ;; *) v=$(awk -v p="$a" '$1 == p { print $2 }' "$D/avail"); [ -n "$v" ] && setv "$a" "$v"
            [ "$a" = openssh-server ] && { grep -v '^40000$' "$D/ports" >"$D/p.n"; cat "$D/p.n" >"$D/ports"; }
            [ "$a" = breakme ] && { grep -v '^8080$' "$D/ports" >"$D/p.n"; cat "$D/p.n" >"$D/ports"; } ;; esac; done; exit 0 ;;
    *" --allow-downgrades "*)
        for a; do case "$a" in ./*.deb) b=${a#./}; b=${b%_all.deb}; setv "${b%%_*}" "$(printf '%s' "${b#*_}" | sed 's/%3a/:/')"
            [ "${b%%_*}" = breakme ] && echo 8080 >>"$D/ports" ;; esac; done; exit 0 ;;
esac
exit 0
EOF
cat >"$S/dpkg-query" <<'EOF'
#!/bin/sh
cat "$STUB_STATE/inst"
EOF
cat >"$S/apt-mark" <<'EOF'
#!/bin/sh
D=$STUB_STATE
case "$1" in
    showhold) cat "$D/held" ;;
    unhold) grep -vx "$2" "$D/held" >"$D/h.n"; cat "$D/h.n" >"$D/held" ;;
    hold) echo "$2" >>"$D/held" ;;
esac
EOF
cat >"$S/ss" <<'EOF'
#!/bin/sh
while read -r p; do echo "LISTEN 0 128 0.0.0.0:$p 0.0.0.0:*"; done <"$STUB_STATE/ports"
EOF
chmod +x "$S"/*
PATH="$S:$PATH"; export PATH

reset() {
    printf 'openssh-server 1:9.6p1-3ubuntu13.4\nlibssl3t64 3.0.13-0ubuntu3.4\nbreakme 1.0\nlinux-image-generic 6.8.0.40\nvim 2:9.1.0016-1\nnewlib 0\n' >"$ST/inst"
    printf 'openssh-server 1:9.6p1-3ubuntu13.5 noble-security\nlibssl3t64 3.0.13-0ubuntu3.5 noble-security\nbreakme 1.1 noble-security\nlinux-image-generic 6.8.0.45 noble-security\nvim 2:9.1.0016-1ubuntu7 noble-updates\n' >"$ST/avail"
    printf 'sudo\n' >"$ST/held"; printf '22\n8080\n40000\n' >"$ST/ports"; : >"$ST/calls"
    mkdir -p "$E/apt/preferences.d" "$T_TMP/cache"; printf 'Package: openssl\nPin: version 3.0.2*\nPin-Priority: -1\n' >"$E/apt/preferences.d/hold-ssl"
    : >"$T_TMP/cache/breakme_1.0_all.deb"
    printf 'deb http://archive.ubuntu.com/ubuntu noble main\ndeb [trusted=yes] http://203.0.113.9/repo ./\n' >"$E/apt/sources.list"
}
run() { $SH "$C" --out "$O" --no-color --url http://127.0.0.1:1/ --no-restart --no-refresh --no-protected "$@"; }

t_start "options"
$SH "$C" --moon >/dev/null 2>&1; t_eq "$?" 2 "an unknown option exits 2"
out=$($SH "$C" --help 2>&1); t_has "$out" "--no-refresh" "--help"

t_start "sources, holds and the list"
reset
out=$(run --batch 2>&1)
t_has "$out" "[ok] http://archive.ubuntu.com/ubuntu" "the distribution's source is fine"
t_has "$out" "[!] no signature check: http://203.0.113.9/repo" "a source with no signature check is HIGH"
t_has "$out" "[*] not the distribution's: http://203.0.113.9/repo" "an unknown source is flagged"
t_has "$out" "[*] held (never updated): sudo" "a held package is shown"
t_has "$out" "a pin that blocks updates (Pin-Priority below 0) for openssl in /etc/apt/preferences.d/hold-ssl" "a blocking pin is shown"
t_has "$out" "3 of them security" "security updates are counted (kernel apart)"
t_has "$out" "[!] ssh: openssh-server" "grouped by service"
t_has "$out" "Security updates for ssh (1: openssh-server): what now? [U/s] u (default)" "security: default update"
t_has "$out" "Kernel updates" "the kernel is asked apart"
t_has "$out" "Non-security updates for system (1: vim): what now? [u/S] s (default)" "non-security: default skip"
t_has "$out" "[~] would update ssh (security): openssh-server" "the plan"
t_hasnt "$out" "would update kernel" "the kernel defaults to skip"
t_has "$out" "Dry run: nothing was changed" "dry run without --apply"
t_ok "a dry run installs nothing" grep -q 'openssh-server 1:9.6p1-3ubuntu13.4' "$ST/inst"
t_file "$(ls -d "$O"/updates-* | tail -n 1)/updates.txt" "updates.txt"
t_fail "no CSV files are left" sh -c "find '$O' -name '*.csv' | grep -q ."

if [ "$(id -u)" = 0 ]; then
    t_start "apply the defaults (--batch)"
    reset
    out=$(STUB_NODL=breakme run --batch --apply 2>&1)
    _rd=$(ls -d "$O"/updates-* | tail -n 1)
    t_hasnt "$out" "after the ssh (security) update" "a high (short-lived) port closing is not a broken service"
    t_ok "the old package came from apt's cache when the mirror has none" test -f "$_rd/old-packages/breakme_1.0_all.deb"
    t_ok "openssh is updated" grep -q 'openssh-server 1:9.6p1-3ubuntu13.5' "$ST/inst"
    t_ok "openssl is updated" grep -q 'libssl3t64 3.0.13-0ubuntu3.5' "$ST/inst"
    t_ok "the kernel is not" grep -q 'linux-image-generic 6.8.0.40' "$ST/inst"
    t_ok "the non-security one is not" grep -q 'vim 2:9.1.0016-1$' "$ST/inst"
    t_ok "your config files are kept" grep -q 'force-confold' "$ST/calls"
    t_ok "the old package is saved" test -f "$_rd/old-packages/openssh-server_1%3a9.6p1-3ubuntu13.4_all.deb"
    t_has "$out" "[!] after the system (security) update: port(s) 8080 no longer listening" "a closed port is seen"
    t_has "$out" "[+] rolled back; everything answers again" "and rolled back (default)"
    t_ok "breakme is back on the old version" grep -q 'breakme 1.0' "$ST/inst"
    t_ok "the held package stays held (default keep)" grep -qx sudo "$ST/held"
    t_file "$_rd/versions-before.txt" "versions-before.txt"

    t_start "the undo"
    awk -F'\t' '{ l[NR] = $4 } END { for (i = NR; i > 0; i--) print l[i] }' "$O"/undo-*.log >"$T_TMP/undo.sh"
    sh "$T_TMP/undo.sh" >/dev/null 2>&1
    t_ok "the undo puts openssh back" grep -q 'openssh-server 1:9.6p1-3ubuntu13.4' "$ST/inst"

    t_start "questions on a terminal"
    if command -v script >/dev/null 2>&1; then
        reset
        # sudo hold: r; ssh: s; openssl: Enter (u); system (breakme): u; kernel: Enter (s); vim: u;
        # apply: Enter; breakme broke: l (leave)
        printf 'r\ns\n\nu\n\nu\n\nl\n' >"$T_TMP/ans"
        tt=$(CCDC_NO_TTY=0 script -qc "$SH '$C' --out '$O' --no-color --url http://127.0.0.1:1/ --no-restart --no-refresh --no-protected --apply" /dev/null <"$T_TMP/ans" 2>&1)
        t_has "$tt" "[u] update them" "each group lists its answers"
        t_has "$tt" "[r] roll back the system update now" "a broken group lists its answers"
        t_fail "r: the hold is released" grep -qx sudo "$ST/held"
        t_ok "s: openssh is not updated" grep -q 'openssh-server 1:9.6p1-3ubuntu13.4' "$ST/inst"
        t_ok "Enter: openssl is updated" grep -q 'libssl3t64 3.0.13-0ubuntu3.5' "$ST/inst"
        t_ok "u: vim is updated" grep -q 'vim 2:9.1.0016-1ubuntu7' "$ST/inst"
        t_ok "l: breakme stays on the new version" grep -q 'breakme 1.1' "$ST/inst"
    fi
fi
t_done
