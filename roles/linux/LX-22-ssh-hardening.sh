#!/bin/sh
# =============================================================================
# ID:       LX-22
# NAME:     SSH hardening and key cleanup
# ROLE:     Linux  (wave 2, first 15 minutes)
# KIND:     changes - dry run unless --apply
# VERSION:  1.1.0
#
# PURPOSE
#   A changed password does not stop a red team that planted an SSH key.  This:
#     1. lists every authorized key of every account (also service accounts
#        like www-data, a favourite hiding place) with its fingerprint and
#        options; with --allow-keys it removes every key not on the team's
#        list (removed lines are kept as evidence in the quarantine folder)
#     2. puts a marked block of settings at the TOP of sshd_config, where they
#        win (sshd uses the first value it reads): no empty passwords, root
#        by key only (or not at all), no rhosts/host-based logins, no
#        user-set environment, no X11 or agent forwarding, few auth tries
#     3. tests the new config with "sshd -t" BEFORE installing it, reloads
#        sshd (open sessions stay up), checks sshd still listens, and puts
#        the old config back by itself if it does not
#     4. quarantines ~/.ssh/rc and /etc/ssh/sshrc (commands run at every
#        login - a backdoor spot) and reports the rest to check by hand:
#        Match blocks that loosen settings, AuthorizedKeysCommand, extra
#        sshd processes, keys with forced commands, ~/.ssh/environment
#   Password logins are NOT turned off: scoring engines usually log in with
#   passwords.
#
# USAGE
#   sudo sh LX-22-ssh-hardening.sh                              dry run
#   sudo sh LX-22-ssh-hardening.sh --apply                      settings + rc files; keys only listed
#   sudo sh LX-22-ssh-hardening.sh --apply --allow-keys team.pub   also remove unknown keys
#
# OPTIONS
#   --allow-keys FILE   the team's public keys (authorized_keys format) or
#                       fingerprints (SHA256:...), one per line.  Every other
#                       key is removed from every account
#   --remove-all-keys   remove every authorized key (no allow list)
#   --no-root-login     PermitRootLogin no (default: prohibit-password,
#                       which still allows root with a key).  The default is
#                       NOT applied - root login is left as it is, and the
#                       summary says so - when root has a password but no
#                       SSH key that stays (root could then no longer log in
#                       at all), or when root is on the protected list
#   --root-key-only     PermitRootLogin prohibit-password even then
#   --keep-root-login   leave PermitRootLogin as it is
#   --no-forwarding     also turn off TCP forwarding, tunnels and gateway
#                       ports (stops pivoting; check nothing scored uses them)
#   --allow-users LIST  AllowUsers: ONLY these accounts may log in by SSH
#                       (space or comma separated).  Protected accounts are
#                       added automatically.  Easy to lock yourself out with
#   --banner FILE       show this file before login (Banner)
#   --no-reload         install the config but do not reload sshd
#   --root DIR          treat DIR as / for passwd, homes and sshd_config
#                       (tests; sshd is not reloaded)
#   --help              this text plus the common options
#
# OUTPUTS  (under --out, in LX-22_<host>_<UTC time>/)
#   summary.txt    settings changed, keys found and removed, things to check
#   keys.csv       user,file,type,fingerprint,comment,options,action
#   settings.csv   setting,before,after,status
#
# WHAT IT CHANGES  (only with --apply)
#   /etc/ssh/sshd_config (marked block at the top; backed up first),
#   authorized_keys files (rewritten without the removed keys; backed up
#   first; removed lines saved in quarantine), ~/.ssh/rc and /etc/ssh/sshrc
#   (moved to quarantine), and reloads sshd.  Every change has an undo line.
#
# DEPENDS ON
#   sshd (to test and reload), ssh-keygen (fingerprints; without it keys are
#   compared by their text only), awk, systemctl/service/kill for the reload.
#   CCDC_SSHD may name a stand-in sshd (the tests use one).
#
# TESTED ON
#   Ubuntu 24.04 with OpenSSH 9.6 under dash, bash, busybox sh, ksh93, mksh
#   and yash (fake root and stand-in sshd), and live: after --apply the
#   allowed key still logs in and the planted key is refused.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Keep a second root session open while applying, as with any SSH change.
#   - Settings inside Match blocks apply on top of the global ones for
#     matching logins; they are reported, not changed.
#   - Keys in LDAP or an AuthorizedKeysCommand are not in files; the command
#     is reported.
#   - Accounts on the protected list keep their keys.
#
# DEBUGGING
#   --debug shows each key file read and each key's fingerprint.
#   The candidate config and sshd -t output are in the log.
# =============================================================================

# >>> CCDC-LIB
# Development copy: find lib/lib.sh by walking up from this file.  The build
# step (tools/build.sh, LB-03) replaces this whole block with the library
# itself, so the built script is a single standalone file.
_cc_d=$(cd "$(dirname "$0")" && pwd)
while [ "$_cc_d" != "/" ] && [ ! -f "$_cc_d/lib/lib.sh" ]; do _cc_d=$(dirname "$_cc_d"); done
[ -f "$_cc_d/lib/lib.sh" ] || { echo "cannot find lib/lib.sh above $0" >&2; exit 3; }
. "$_cc_d/lib/lib.sh"
# <<< CCDC-LIB

usage() {
    cat <<'USAGE'
LX-22 SSH hardening and key cleanup
  sudo sh LX-22-ssh-hardening.sh [--apply] [options]

  --allow-keys FILE   team public keys / fingerprints; every other key is removed
  --remove-all-keys   remove every authorized key
  --no-root-login     PermitRootLogin no (default: prohibit-password, unless
                      root has no SSH key or is on the protected list)
  --root-key-only     PermitRootLogin prohibit-password even if root has no key
  --keep-root-login   leave PermitRootLogin alone
  --no-forwarding     also block TCP forwarding and tunnels
  --allow-users LIST  only these accounts may log in by SSH (careful)
  --banner FILE       pre-login banner
  --no-reload         install the config without reloading sshd
  --root DIR          treat DIR as / (tests)
  --help              show this text

USAGE
    cc_usage_common
}

ALLOWKEYS=""; RMALL=0; ROOTSET=0; ROOTMODE=prohibit-password; NOFWD=0; ALLOWUSERS=""; BANNER=""; NORELOAD=0; R=""
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --allow-keys)      [ $# -ge 2 ] || cc_die 2 "--allow-keys needs a file"; [ -r "$2" ] || cc_die 2 "--allow-keys: cannot read $2"; ALLOWKEYS=$2; shift 2 ;;
        --remove-all-keys) RMALL=1; shift ;;
        --no-root-login)   ROOTMODE=no; ROOTSET=1; shift ;;
        --root-key-only)   ROOTMODE=prohibit-password; ROOTSET=1; shift ;;
        --keep-root-login) ROOTMODE=""; ROOTSET=1; shift ;;
        --no-forwarding)   NOFWD=1; shift ;;
        --allow-users)     [ $# -ge 2 ] || cc_die 2 "--allow-users needs a list"; ALLOWUSERS=$(printf '%s' "$2" | tr ',' ' '); shift 2 ;;
        --banner)          [ $# -ge 2 ] || cc_die 2 "--banner needs a file"; [ -r "$2" ] || cc_die 2 "--banner: cannot read $2"; BANNER=$(cc_abspath "$2"); shift 2 ;;
        --no-reload)       NORELOAD=1; shift ;;
        --root)            [ $# -ge 2 ] || cc_die 2 "--root needs a folder"; [ -d "$2" ] || cc_die 2 "--root: not a folder: $2"
                           R=$(cd "$2" && pwd); [ "$R" = / ] && R=""; shift 2 ;;
        --help|-h)         usage; exit 0 ;;
        *)                 cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
[ -n "$ALLOWKEYS" ] && [ "$RMALL" = 1 ] && cc_die 2 "use --allow-keys or --remove-all-keys, not both"

cc_init "LX-22" "SSH hardening and key cleanup" changes
cc_detect_os
[ -z "$R" ] && [ "$CC_APPLY" = 1 ] && cc_require_root
cc_use_run_dir
W="$CC_RUN_DIR/.work"
mkdir -p "$W" || cc_die 3 "cannot create $W"
KCSV=$(cc_csv_new keys "user,file,type,fingerprint,comment,options,action")
SCSV=$(cc_csv_new settings "setting,before,after,status")
CONF="$R/etc/ssh/sshd_config"
SSHD=${CCDC_SSHD:-$(cc_which sshd)} || SSHD=""
KEYGEN=$(cc_which ssh-keygen) || KEYGEN=""
[ -n "$KEYGEN" ] || cc_warn "ssh-keygen not found: keys are compared by their text, fingerprints are not shown"
: >"$W/report"
report() { printf '%s\n' "$*" >>"$W/report"; }
result() { if [ "$CC_APPLY" != 1 ]; then echo "would change"; elif [ "$1" -eq 0 ]; then echo changed; else echo failed; fi; }

# ---- Key parsing --------------------------------------------------------------
# AWK_KEY: parse(line) splits an authorized_keys line into
#   K_opts (options before the key, which may hold quoted spaces), K_type,
#   K_blob (the base64 key) and K_comment.  Returns 0 if no key type found.
AWK_KEY='
function iskeytype(t) { return t ~ /^(ssh-(rsa|dss|ed25519)|ecdsa-sha2-nistp[0-9]+|sk-[a-z0-9-]+@openssh\.com|ssh-[a-z0-9-]+-cert-v01@openssh\.com)$/ }  # awk, not shell: posix-ok
function parse(line,   rest, i, c, q, n, f) {  # awk, not shell: posix-ok
    K_opts = ""; K_type = ""; K_blob = ""; K_comment = ""
    sub(/^[ \t]+/, "", line)
    if (line == "" || line ~ /^#/) return 0
    n = split(line, f, /[ \t]+/)
    if (iskeytype(f[1])) { K_type = f[1]; K_blob = f[2]; rest = line; sub(/^[^ \t]+[ \t]+[^ \t]+[ \t]*/, "", rest); K_comment = rest; return 1 }
    # Options first: read up to the first blank outside double quotes.
    q = 0
    for (i = 1; i <= length(line); i++) {
        c = substr(line, i, 1)
        if (c == "\"") q = !q
        else if ((c == " " || c == "\t") && !q) break
    }
    K_opts = substr(line, 1, i - 1); rest = substr(line, i); sub(/^[ \t]+/, "", rest)
    n = split(rest, f, /[ \t]+/)
    if (!iskeytype(f[1])) return 0
    K_type = f[1]; K_blob = f[2]; sub(/^[^ \t]+[ \t]+[^ \t]+[ \t]*/, "", rest); K_comment = rest
    return 1
}'

# fingerprint TYPE BLOB -> SHA256:... (or nothing without ssh-keygen)
fingerprint() {
    [ -n "$KEYGEN" ] || return 0
    printf '%s %s\n' "$1" "$2" >"$W/fp.pub"
    "$KEYGEN" -l -f "$W/fp.pub" 2>/dev/null | awk '{ print $2 }'
}

# The team's allowed keys: one "blob" or "SHA256:..." per line in $W/allowed.
: >"$W/allowed"
if [ -n "$ALLOWKEYS" ]; then
    awk "$AWK_KEY"'{ l = $0; sub(/^[ \t]+/, "", l); if (l ~ /^SHA256:/) { split(l, a, /[ \t]/); print "F " a[1]; next }
                     if (parse(l)) print "K " K_type " " K_blob }' "$ALLOWKEYS" >"$W/allow.raw"
    while read -r _k _t _b; do
        if [ "$_k" = F ]; then printf '%s\n' "$_t" >>"$W/allowed"
        else printf '%s\n' "$_b" >>"$W/allowed"; _fp=$(fingerprint "$_t" "$_b"); [ -n "$_fp" ] && printf '%s\n' "$_fp" >>"$W/allowed"; fi
    done <"$W/allow.raw"
    [ -s "$W/allowed" ] || cc_die 2 "--allow-keys: no keys or fingerprints found in $ALLOWKEYS"
    cc_info "team keys on the allow list: $(grep -c '^SHA256:' "$W/allowed")"
fi
KEYMODE=list
[ -n "$ALLOWKEYS" ] && KEYMODE=allow
[ "$RMALL" = 1 ] && KEYMODE=all

# ---- Where keys live ---------------------------------------------------------
# AuthorizedKeysFile from the effective config (sshd -T), else the defaults.
AKF=""
if [ -z "$R" ] && [ -n "$SSHD" ]; then
    AKF=$("$SSHD" -T 2>/dev/null | awk '$1 == "authorizedkeysfile" { $1 = ""; sub(/^ /, ""); print }')
fi
[ -n "$AKF" ] || AKF=$(awk 'tolower($1) == "authorizedkeysfile" && !m { $1 = ""; sub(/^ /, ""); print; exit } tolower($1) == "match" { m = 1 }' "$CONF" 2>/dev/null)
[ -n "$AKF" ] || AKF=".ssh/authorized_keys .ssh/authorized_keys2"
cc_debug "AuthorizedKeysFile: $AKF"

# ---- 1. Keys ------------------------------------------------------------------
_nkeys=0; _nrem=0; _nfiles=0; _rootkeys=0
awk -F: '$6 != "" { print $1 ":" $6 }' "$R/etc/passwd" >"$W/users"
: >"$W/seen"
while IFS=: read -r _u _h; do
    for _pat in $AKF; do
        # %h home, %u user, %% a percent sign; relative paths start at the home.
        _f=$(printf '%s' "$_pat" | sed "s|%h|$_h|g; s|%u|$_u|g; s|%%|%|g")
        case "$_f" in /*) ;; *) _f="$_h/$_f" ;; esac
        _pf="$R$_f"
        [ -e "$_pf" ] || [ -h "$_pf" ] || continue
        grep -qxF "$_pf" "$W/seen" && continue
        printf '%s\n' "$_pf" >>"$W/seen"
        if [ -h "$_pf" ]; then report "$_f ($_u) is a symbolic link to $(ls -l "$_pf" | sed 's/.*-> //'): check it by hand"; continue; fi
        [ -r "$_pf" ] || { report "$_f ($_u) cannot be read (run as root)"; continue; }
        _nfiles=$((_nfiles + 1))
        # One line per entry: line number|type|blob|comment|options
        awk "$AWK_KEY"'{ if (parse($0)) print NR "|" K_type "|" K_blob "|" K_comment "|" K_opts }' "$_pf" >"$W/k"
        : >"$W/drop"
        _protected=0
        cc_is_protected account "$_u" && [ "$CC_FORCE_SCORED" != 1 ] && _protected=1
        while IFS='|' read -r _ln _t _b _c _o; do
            _nkeys=$((_nkeys + 1))
            _fp=$(fingerprint "$_t" "$_b")
            _act=kept
            case "$KEYMODE" in
                list)  _act="listed" ;;
                all)   _act=remove ;;
                allow) if grep -qxF "$_b" "$W/allowed" || { [ -n "$_fp" ] && grep -qxF "$_fp" "$W/allowed"; }; then _act="kept (on the team list)"; else _act=remove; fi ;;
            esac
            if [ "$_act" = remove ] && [ "$_protected" = 1 ]; then
                _act="kept (protected account)"; CC_N_REFUSED=$((CC_N_REFUSED + 1))
                cc_log REFUSED "key $_fp in $_f: account $_u is on the protected list - kept"
            fi
            [ "$_act" = remove ] && { printf '%s\n' "$_ln" >>"$W/drop"; _nrem=$((_nrem + 1)); }
            # Keys root keeps decide below whether key-only root login is safe.
            [ "$_u" = root ] && [ "$_act" != remove ] && _rootkeys=$((_rootkeys + 1))
            case "$_o" in *command=*|*environment=*) report "$_f ($_u): key ${_fp:-$_c} has options [$_o] - a forced command or environment can be a backdoor" ;; esac
            [ "$_act" = remove ] && [ "$CC_APPLY" != 1 ] && _act="would remove"
            [ "$_act" = remove ] && _act=removed
            cc_csv_row "$KCSV" "$_u" "$_f" "$_t" "$_fp" "$_c" "$_o" "$_act"
            cc_debug "key: $_u $_f ${_fp:-?} $_act"
        done <"$W/k"
        [ -s "$W/drop" ] || continue
        # Rewrite the file without the dropped lines (by line number, so
        # comments and kept keys stay exactly as they were).
        awk 'NR == FNR { d[$1] = 1; next } !(FNR in d)' "$W/drop" "$_pf" >"$W/kept"
        awk 'NR == FNR { d[$1] = 1; next } (FNR in d)' "$W/drop" "$_pf" >"$W/removed"
        if ! cc_guard path "$_f"; then continue; fi
        cc_backup_file "$_pf" || continue
        if [ "$CC_APPLY" = 1 ]; then
            # Evidence: the removed lines, kept outside the account's reach.
            (umask 077; mkdir -p "$(dirname "$CC_QUAR_DIR$_f")" && cp "$W/removed" "$CC_QUAR_DIR$_f.removed")
        fi
        # cp onto the existing file keeps its owner and mode.  A file locked
        # with chattr +i makes this fail: the log says so.
        cc_run "remove $(grep -c . "$W/drop") key(s) from $_f ($_u)" cp "$W/kept" "$_pf" ||
            report "$_f: could not rewrite it (immutable? try: lsattr $_f; chattr -i $_f)"
    done
done <"$W/users"

# ---- 2. rc files and environment files -----------------------------------------
_nrc=0
for _f in /etc/ssh/sshrc $(awk -F: '$6 != "" { print $6 "/.ssh/rc" }' "$R/etc/passwd" | sort -u); do
    [ -e "$R$_f" ] || continue
    _nrc=$((_nrc + 1))
    cc_quarantine "$R$_f"
    _rc=$?
    if [ "$_rc" -eq 4 ]; then report "$_f runs at every SSH login; it is protected, so it was left in place"
    else cc_csv_row "$SCSV" "$_f" present quarantined "$(result "$_rc")"; fi
done
awk -F: '$6 != "" { print $1 ":" $6 }' "$R/etc/passwd" | while IFS=: read -r _u _h; do
    [ -s "$R$_h/.ssh/environment" ] && printf '%s\n' "$_h/.ssh/environment ($_u) sets environment variables at login; harmless once PermitUserEnvironment is no, but read it"
done >>"$W/report"

# ---- 3. sshd_config ------------------------------------------------------------
_cfg_status="not changed"
if [ ! -f "$CONF" ]; then
    report "no $CONF: SSH server not installed or configured elsewhere"
    _cfg_status="no sshd_config"
else
    # Things only a person can judge.
    awk 'tolower($1) == "match" { m = $0; next }
         m != "" && tolower($1) ~ /^(permitrootlogin|passwordauthentication|permitemptypasswords|authorizedkeysfile|authorizedkeyscommand|forcecommand|permituserenvironment)$/ {
             print "sshd_config Match block [" m "] sets: " $0 }
         m == "" && tolower($1) ~ /^(authorizedkeyscommand|authorizedprincipalscommand|trustedusercakeys)$/ {
             print "sshd_config sets " $0 " - keys can come from outside the key files; check it is the team'"'"'s" }' "$CONF" >>"$W/report"
    if [ -z "$R" ]; then
        ps -eo user=,args= 2>/dev/null | awk '$2 ~ /sshd$/ && ($0 ~ / -f / || $0 ~ / -p /) { $1 = ""; print "extra sshd process running:" $0 }' >>"$W/report"
    fi
    # Root login: never take away root's only way in, or a scored login.
    if [ -n "$ROOTMODE" ] && cc_is_protected account root && [ "$CC_FORCE_SCORED" != 1 ]; then
        ROOTMODE=""
        report "root is on the protected list: PermitRootLogin was left as it is"
    elif [ -n "$ROOTMODE" ] && [ "$ROOTSET" = 0 ] && [ "$_rootkeys" -eq 0 ]; then
        # No readable shadow file counts as "has a password": when unsure, do
        # not lock root out.
        _rpw=$(awk -F: '$1 == "root" { print ($2 == "" || $2 ~ /^[!*]/) ? "no" : "yes" }' "$R/etc/shadow" 2>/dev/null)
        if [ "$_rpw" != no ]; then
            ROOTMODE=""
            report "root has a password but no SSH key that stays, so root password login was LEFT ON (turning it off would lock root out of SSH). Give root a team key or check another admin account can log in and use sudo, then run again with --no-root-login or --root-key-only"
        fi
    fi
    # The block to put at the top.  Each setting is also recorded with the
    # value the current config gives (first occurrence outside Match).
    {
        printf '# >>> CCDC LX-22 (sshd uses the first value it reads, so this block wins)\n'
        [ -n "$ROOTMODE" ] && printf 'PermitRootLogin %s\n' "$ROOTMODE"
        printf 'PermitEmptyPasswords no\nHostbasedAuthentication no\nIgnoreRhosts yes\nPermitUserEnvironment no\n'
        printf 'X11Forwarding no\nAllowAgentForwarding no\nMaxAuthTries 4\nLoginGraceTime 30\n'
        if [ "$NOFWD" = 1 ]; then printf 'AllowTcpForwarding no\nPermitTunnel no\nGatewayPorts no\n'; fi
        if [ -n "$ALLOWUSERS" ]; then
            # Protected accounts are added so scoring keeps working.
            _au=$ALLOWUSERS
            if [ -n "$CC_PROTECTED" ]; then
                for _p in $(awk -F',' 'tolower($1) ~ /account/ { gsub(/[ "\r]/, "", $2); print $2 }' "$CC_PROTECTED"); do
                    case " $_au " in *" $_p "*) ;; *) _au="$_au $_p" ;; esac
                done
            fi
            printf 'AllowUsers %s\n' "$_au"
        fi
        [ -n "$BANNER" ] && printf 'Banner %s\n' "$BANNER"
        printf '# <<< CCDC LX-22\n'  # text, not a here-string: posix-ok
    } >"$W/block"
    # Candidate: our block, then the current file without any older block.
    awk '/^# >>> CCDC LX-22/ { skip = 1 } !skip { print } /^# <<< CCDC LX-22/ { skip = 0 }' "$CONF" >"$W/rest"  # awk regex, not a heredoc: posix-ok
    cat "$W/block" "$W/rest" >"$W/sshd_config.new"
    awk '/^# >>> CCDC LX-22/ || /^# <<< CCDC LX-22/ || /^#/ || NF == 0 { next } { print tolower($1) "|" $0 }' "$W/block" >"$W/want"  # posix-ok
    while IFS='|' read -r _k _line; do
        _before=$(awk -v k="$_k" '/^# >>> CCDC LX-22/ { s = 1 } /^# <<< CCDC LX-22/ { s = 0; next } s { next }  # posix-ok
                   tolower($1) == "match" { exit } tolower($1) == k { $1 = ""; sub(/^ /, ""); print; exit }' "$CONF")
        _after=${_line#* }
        if [ "$_before" = "$_after" ]; then _st="already ok"; else _st=$([ "$CC_APPLY" = 1 ] && echo changed || echo "would change"); fi
        cc_csv_row "$SCSV" "${_line%% *}" "${_before:-(default)}" "$_after" "$_st"
    done <"$W/want"
    if cmp -s "$W/sshd_config.new" "$CONF"; then
        _cfg_status="already in place"
    elif [ -z "$SSHD" ]; then
        report "sshd not found, so the new config cannot be tested: sshd_config NOT changed"
        _cfg_status="not changed (cannot test without sshd)"
    elif ! cc_guard path /etc/ssh/sshd_config; then
        _cfg_status="not changed (protected)"
    else
        # Test BEFORE installing.  A config sshd rejects never goes live.
        if ! "$SSHD" -t -f "$W/sshd_config.new" >"$W/sshd_t" 2>&1; then
            cat "$W/sshd_t" >>"$CC_LOG"
            cc_err "sshd rejected the new config, so it was NOT installed: $(head -n 1 "$W/sshd_t")"
            CC_N_FAIL=$((CC_N_FAIL + 1))
            _cfg_status="FAILED: sshd -t rejected it (see the log)"
        elif cc_backup_file "$CONF"; then
            cc_run "install hardened sshd_config (block at the top)" cp "$W/sshd_config.new" "$CONF"
            _rc=$?
            if [ "$_rc" -ne 0 ]; then _cfg_status="FAILED to install"
            elif [ "$CC_APPLY" != 1 ]; then _cfg_status="would install (passed sshd -t)"
            else _cfg_status="installed (passed sshd -t)"; fi
        fi
    fi
fi

# ---- 4. Reload sshd and make sure it still answers --------------------------
# listening_ports -> the ports sshd listens on now (from ss, else netstat).
sshd_listening() {
    if cc_have ss; then ss -ltnp 2>/dev/null | grep -q '"sshd"'
    else netstat -ltnp 2>/dev/null | grep -q '/sshd'; fi
}
sshd_reload() {
    if [ "$CC_INIT" = systemd ]; then systemctl reload ssh 2>/dev/null || systemctl reload sshd
    elif cc_have rc-service; then rc-service sshd reload
    else
        for _pidf in /run/sshd.pid /var/run/sshd.pid; do
            [ -r "$_pidf" ] && { kill -HUP "$(cat "$_pidf")"; return $?; }
        done
        return 1
    fi
}
_reload="not needed"
case "$_cfg_status" in installed*)
    if [ -n "$R" ] || [ "$NORELOAD" = 1 ]; then
        _reload="skipped (--no-reload or --root): run 'sshd -t' and reload sshd yourself"
    elif ! sshd_listening; then
        _reload="sshd is not running; the new config applies when it starts"
    else
        cc_run "reload sshd (open sessions stay up)" sshd_reload
        sleep 2
        if sshd_listening; then
            _reload="reloaded; sshd still listening"
        else
            # Never leave the box without SSH: put the old config back.
            cc_err "sshd is NOT listening after the reload - putting the old config back"
            cp "$CC_LAST_BACKUP" "$CONF" 2>>"$CC_LOG"
            sshd_reload >>"$CC_LOG" 2>&1 || "$SSHD" >>"$CC_LOG" 2>&1
            CC_N_FAIL=$((CC_N_FAIL + 1))
            _reload="FAILED: sshd stopped listening; old config restored$(sshd_listening && echo ', sshd is back' || echo ', START SSHD BY HAND')"
        fi
    fi ;;
esac

# Effective values after the change, when sshd can tell us.
if [ -z "$R" ] && [ -n "$SSHD" ] && [ "$CC_APPLY" = 1 ]; then
    "$SSHD" -T 2>/dev/null | awk '$1 ~ /^(permitrootlogin|permitemptypasswords|passwordauthentication|pubkeyauthentication|x11forwarding|maxauthtries|allowtcpforwarding)$/' >"$W/effective"
fi

# ---- Summary ------------------------------------------------------------------
{
    printf 'LX-22 SSH hardening and key cleanup | host %s | %s | %s\n\n' "$CC_HOST" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$([ "$CC_APPLY" = 1 ] && echo APPLIED || echo 'DRY RUN - nothing changed')"
    printf 'sshd_config: %s\n' "$_cfg_status"
    printf 'sshd:        %s\n' "$_reload"
    awk "$CC_AWK_CSV"'NR > 1 { csvsplit($0, f); if (f[1] ~ /^\//) next; printf "  %-24s %-18s -> %-18s %s\n", f[1], f[2], f[3], f[4] }' "$SCSV"
    if [ -s "$W/effective" ]; then printf '  now in effect (sshd -T): %s\n' "$(tr '\n' ';' <"$W/effective" | sed 's/;/; /g')"; fi
    printf '\nKeys: %d in %d files; ' "$_nkeys" "$_nfiles"
    case "$KEYMODE" in
        list)  printf 'listed only (give --allow-keys to remove unknown keys)\n' ;;
        *)     printf '%d %s\n' "$_nrem" "$([ "$CC_APPLY" = 1 ] && echo removed || echo 'would be removed')" ;;
    esac
    awk "$CC_AWK_CSV"'NR > 1 { csvsplit($0, f); printf "  %-12s %-34s %-12s %-50s %s\n", f[1], f[2], f[3], (f[4] != "" ? f[4] : "?"), f[7] }' "$KCSV" | head -n 40
    [ "$_nrc" -gt 0 ] && printf '\nLogin rc files: %d %s\n' "$_nrc" "$([ "$CC_APPLY" = 1 ] && echo 'moved to quarantine' || echo 'would be moved to quarantine')"
    if [ -s "$W/report" ]; then
        printf '\nCheck by hand:\n'
        awk '{ l = "  " $0; if (length(l) > 220) l = substr(l, 1, 217) "..."; print l }' "$W/report"
    fi
    printf '\n'
    [ "$CC_APPLY" = 1 ] || printf 'Dry run: nothing changed.  Run again with --apply (keep a second root session open).\n'
    printf 'Password logins were left as they were (scoring engines use them).\n'
    printf 'All results: %s\n' "$CC_RUN_DIR"
} >"$CC_RUN_DIR/summary.txt"
cat "$CC_RUN_DIR/summary.txt"
rm -rf "$W"
cc_finish
