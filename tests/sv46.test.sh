#!/bin/sh
# Tests for roles/applications/SV-46-fileshare-hardening.sh.
# A fake root (--root) with an smb.conf (SMB1 allowed, lanman auth, a
# root preexec and a magic script, wide links, a guest share anyone can
# write, a guest read-only share, a user share with force user = root,
# writable by every user) and NFS exports (no_root_squash, insecure, one in
# /etc/exports.d).  Checks: each finding; a dry run changes nothing; --apply
# makes each change and keeps the rest; guest-write is asked with default no;
# a second run is clean; the undo puts every file back; the questions on a
# terminal.  Nothing outside the fake root is touched.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/applications/SV-46-fileshare-hardening.sh"
export BT_SKIP_VERIFY=1
O="$T_TMP/out"; F="$T_TMP/root"; SC="$F/etc/samba/smb.conf"

mkroot() {
    rm -rf "$F"
    mkdir -p "$F/etc/samba" "$F/etc/exports.d" "$F/srv/public" "$F/srv/drop" "$F/srv/staff"
    cat >"$SC" <<'EOF'
[global]
   workgroup = KOLLA
   server min protocol = NT1
   lanman auth = yes
   map to guest = Bad User
   # root preexec = /old/comment
   root preexec = /usr/local/bin/.sync.sh %u

[public]
   path = /srv/public
   guest ok = yes
   read only = yes

[drop]
   path = /srv/drop
   public = yes
   writable = yes
   wide links = yes
   magic script = run.sh

[staff]
   path = /srv/staff
   valid users = @staff
   read only = no
   force user = root
EOF
    chmod 666 "$SC"; chmod 777 "$F/srv/drop"
    printf '# /etc/exports\n/srv/staff  10.100.1.0/24(rw,sync,no_root_squash,no_subtree_check)\n/srv/public *(ro,insecure)\n# /old *(rw,no_root_squash)\n' >"$F/etc/exports"
    printf '/srv/drop 192.168.220.0/24(rw,insecure,sync)\n' >"$F/etc/exports.d/drop.exports"
}
run() { $SH "$C" --root "$F" --out "$O" --no-color "$@"; }
snap() { (cd "$F" && find . -exec ls -lnd {} + | awk '{ print $1, $3, $4, $NF }' | sort; find . -type f -exec cat {} +) | cksum; }
sec() { awk -v s="$1" '/^[ \t]*\[/ { c = $0; gsub(/[][ \t]/, "", c); next } c == s && !/^[ \t]*#/ { print }' "$SC"; }

t_start "options"
$SH "$C" --only everything >/dev/null 2>&1; t_eq "$?" 2 "an unknown fix exits 2"
out=$($SH "$C" --help 2>&1); t_has "$out" "root-squash" "--help"
mkdir -p "$T_TMP/empty"
out=$($SH "$C" --root "$T_TMP/empty" --out "$O" --no-color --batch 2>&1); t_eq "$?" 0 "no share: exits 0"
t_has "$out" "No file share here" "and says so"

t_start "find"
mkroot; before=$(snap)
out=$(run --batch 2>&1)
t_has "$out" "==========[ 1/3  Samba (/etc/samba/smb.conf) ]==========" "the look: numbered headers"
t_has "$out" "[!] SMB1 is allowed (server min protocol = NT1)" "SMB1 is HIGH"
t_has "$out" "[!] lanman auth = yes" "lanman auth is HIGH"
t_has "$out" "[!] [global] root preexec = /usr/local/bin/.sync.sh %u (line 7): runs a program as root" "root preexec is HIGH"
t_has "$out" "[!] [drop] magic script = run.sh (line 19): runs a program as root" "magic script is HIGH"
t_hasnt "$out" "/old/comment" "a commented line is left out"
t_has "$out" "[*] symbolic links may point out of the share: drop: wide links" "wide links is MED"
t_has "$out" "[*] [public] /srv/public: read-only, guests allowed - anyone can read it" "a guest read-only share is MED"
t_has "$out" "[!] [drop] /srv/drop: read-write, guests allowed - ANYONE can write here" "a guest writable share is HIGH (public = writable = yes)"
t_has "$out" "[staff] /srv/staff: read-write, users: @staff" "a user share is listed"
t_has "$out" "[*] [staff] force user = root" "force user = root is MED"
t_has "$out" "[*] [drop] the folder /srv/drop can be written by every user" "a world-writable share folder is MED"
t_has "$out" "[!] /etc/samba/smb.conf can be changed by every user" "a world-writable smb.conf is HIGH"
t_has "$out" "==========[ 2/3  NFS (/etc/exports /etc/exports.d/drop.exports) ]==========" "both export files are read"
t_has "$out" "[!] /srv/staff -> 10.100.1.0/24: no_root_squash" "no_root_squash is HIGH"
t_has "$out" "[*] /srv/public -> everyone: insecure" "insecure is MED"
t_has "$out" "[*] /srv/drop -> 192.168.220.0/24: insecure" "and in exports.d"
t_hasnt "$out" "/old" "a commented export is left out"
t_has "$out" "[?] [guest-write] guest ok = no on drop" "guest-write is asked"
t_has "$out" "[y/N] n (default)" "with default no"
t_has "$out" "Dry run: nothing was changed" "dry run without --apply"
t_eq "$(snap)" "$before" "a dry run changes nothing"
t_fail "no CSV files are left" sh -c "find '$O' -name '*.csv' | grep -q ."

t_start "apply"
_u0=$(cat "$O"/undo-*.log 2>/dev/null | grep -c .)
out=$(run --batch --no-protected --apply --no-timer 2>&1)
t_has "$(sec global)" "server min protocol = SMB2_02" "SMB2 at least"
t_eq "$(grep -c 'server min protocol' "$SC")" 1 "written once"
t_has "$(sec global)" "ntlm auth = ntlmv2-only" "ntlm auth = ntlmv2-only"
t_has "$(sec global)" "lanman auth = no" "lanman auth = no"
t_has "$(cat "$SC")" "# BT SV-46 off:    root preexec = /usr/local/bin/.sync.sh %u" "root preexec is turned off"
t_has "$(cat "$SC")" "# BT SV-46 off:    magic script = run.sh" "magic script is turned off"
t_has "$(sec drop)" "wide links = no" "wide links = no in its share"
t_has "$(sec drop)" "writable = yes" "guest-write (default no) left the share as is"
t_has "$(sec drop)" "public = yes" "and its guests"
t_has "$(sec global)" "workgroup = KOLLA" "other settings are kept"
t_eq "$(ls -l "$SC" | cut -c8-10)" "r--" "smb.conf is not writable by others"
t_has "$(cat "$F/etc/exports")" "(rw,sync,root_squash,no_subtree_check)" "no_root_squash -> root_squash"
t_has "$(cat "$F/etc/exports")" "/srv/public *(ro)" "insecure dropped"
t_has "$(cat "$F/etc/exports")" "# /old *(rw,no_root_squash)" "a commented export is not touched"
t_has "$(cat "$F/etc/exports.d/drop.exports")" "(rw,sync)" "exports.d too"
out=$(run --batch 2>&1)
t_has "$out" "[ok] SMB1 is off" "a second run: SMB1 off"
t_has "$out" "[ok] no lines that run programs" "no programs"
t_has "$out" "[ok] no no_root_squash or insecure exports" "exports clean"
cat "$O"/undo-*.log | awk -F'\t' -v n="$_u0" 'NR > n { l[NR] = $4 } END { for (i = NR; i > n; i--) print l[i] }' >"$T_TMP/undo.sh"
sh "$T_TMP/undo.sh" >/dev/null 2>&1
t_eq "$(snap)" "$before" "undo puts every file back"

t_start "guest-write when asked for"
mkroot
out=$(run --batch --no-protected --apply --no-timer --only guest-write 2>&1)
t_has "$(sec drop)" "guest ok = no" "guest ok = no"
t_hasnt "$(sec drop)" "public = yes" "and its alias public is replaced"
t_has "$(sec public)" "guest ok = yes" "a read-only guest share is left"

t_start "only NFS, no Samba"
mkroot; rm -f "$SC"
out=$(run --batch 2>&1)
t_hasnt "$out" "Samba" "no Samba section"
t_has "$out" "no_root_squash" "NFS still checked"

t_start "questions on a terminal"
if command -v script >/dev/null 2>&1; then
    mkroot
    # smb1-off y, ntlmv1-off n, exec-lines y, wide-links n, guest-write y, conf-perms n, root-squash n, nfs-insecure y; apply Enter
    printf 'y\nn\ny\nn\ny\nn\nn\ny\n\n' >"$T_TMP/ans"
    tt=$(BT_NO_TTY=0 script -qc "$SH '$C' --root '$F' --out '$O' --no-color --no-protected --apply --no-timer" /dev/null <"$T_TMP/ans" 2>&1)
    t_has "$tt" "[y] yes, do it" "each fix lists its answers"
    t_has "$(sec global)" "server min protocol = SMB2_02" "y: SMB1 off"
    t_has "$(sec global)" "lanman auth = yes" "n: lanman stays"
    t_has "$(sec drop)" "guest ok = no" "y: guest write off"
    t_has "$(cat "$F/etc/exports")" "no_root_squash" "n: no_root_squash stays"
    t_has "$(cat "$F/etc/exports")" "/srv/public *(ro)" "y: insecure dropped"
fi
t_done
