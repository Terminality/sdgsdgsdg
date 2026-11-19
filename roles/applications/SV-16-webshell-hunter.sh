#!/bin/sh
# =============================================================================
# ID:       SV-16
# NAME:     Web shell hunter
# ROLE:     Applications  (wave 2, then any time the store goes down again)
# KIND:     changes - dry run unless --apply (it only ever quarantines)
# VERSION:  1.0.0
#
# PURPOSE
#   Red team keeps coming back to a PHP site through a web shell: a small
#   file that runs their commands from a browser.  SV-15 finds files that
#   changed since its backup - but a shell planted BEFORE the backup is in
#   the backup too.  This looks at the files themselves:
#
#     HIGH  request data run as code  (system($_GET..), eval($_POST..),
#           assert($_REQUEST..), $_GET['f']($_GET['a']), backticks with $_GET)
#           eval of decoded text       (eval(base64_decode(..)), gzinflate,
#           str_rot13 ...); preg_replace with /e; known shell names (c99, r57,
#           WSO, b374k, weevely, p0wny, FilesMan ...)
#           PHP in an upload folder; PHP code inside an image or text file
#           .htaccess that makes other files run as PHP, or auto_prepend_file
#           a WordPress core file that differs from wordpress.org, or a file
#           in wp-admin / wp-includes that WordPress does not ship
#     MED   functions that run programs (shell_exec, passthru, proc_open,
#           popen, pcntl_exec); long encoded blobs; hex-escaped strings
#     LOW   changed in the last --hours hours; owned by the web server
#           account in a code folder; a hidden .something.php
#   A file is HIGH when any HIGH reason matches, MED when any MED reason
#   does, LOW otherwise; the list is sorted by score (HIGH 5, MED 2, LOW 1
#   per reason).  The matching line is shown, so a real shell is easy to tell from
#   a plugin.  Then each file is asked about: [q]uarantine (moved out of the
#   site; the undo puts it back) or [k]eep.  After quarantining, the site
#   must still load (--url), or the files go back.
#
#   --watch N checks every N seconds for new or changed PHP files and scans
#   them at once; with --auto-quarantine --apply a HIGH file is moved out
#   immediately (and put back if the site stops loading).
#
#   QUESTIONS (Enter takes the default in capitals; a flag answers each):
#     each file: [q]uarantine [k]eep [a]ll the rest default
#                    (default q for HIGH, k for MED)      --batch
#     apply?                                              --apply
#
# USAGE
#   sudo sh SV-16-webshell-hunter.sh                          scan, dry run
#   sudo sh SV-16-webshell-hunter.sh --protected p.csv --apply
#   sudo sh SV-16-webshell-hunter.sh --protected p.csv --apply --batch --url http://127.0.0.1/shop/
#   sudo sh SV-16-webshell-hunter.sh --protected p.csv --watch 60 --auto-quarantine --apply
#
# OPTIONS
#   --apply              quarantine (without it, dry run only)
#   --webroot DIR        scan this folder too (repeatable; default /var/www,
#                        /srv/www, /srv/http, /usr/share/nginx/html,
#                        /usr/share/roundcube, /var/lib/roundcube)
#   --hours N            "changed lately" means the last N hours (default 24)
#   --show-low           also list LOW files
#   --url URL            page to check after quarantining (repeatable;
#                        default http://127.0.0.1/)
#   --wp-checksums FILE  WordPress checksums saved from
#                        api.wordpress.org/core/checksums/1.0/?version=X&locale=en_US
#                        (used when wordpress.org cannot be reached)
#   --no-online          never try wordpress.org
#   --watch SECONDS      keep checking for new or changed PHP files
#   --auto-quarantine    with --watch and --apply: move HIGH files out at once
#   --watch-count N      with --watch: stop after N rounds (tests)
#   --timer SECONDS      revert countdown (default 120); --no-timer
#   --no-color           no colours
#   --help               this text plus the common options
#
# OUTPUTS  (under --out, in webshells-N/)
#   output.txt, findings.txt (every file found, its score and reasons),
#   summary.txt, run.txt, revert.sh, watch.txt (with --watch)
#
# DEPENDS ON
#   find, awk, grep, xargs; md5sum and curl for the WordPress check.
#
# TESTED ON
#   Ubuntu 24.04 with a WordPress-style site and planted shells (one-liners,
#   base64/eval, a dynamic call, PHP in uploads, PHP inside a .jpg, an
#   .htaccess handler, a changed core file, an extra core file), under dash,
#   bash, busybox sh, ksh93, mksh and yash with gawk, mawk and busybox awk.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - A clever shell can avoid every pattern.  The LOW hints (changed
#     lately, owned by the web server) are there for that: read them.
#   - Big plugins (backup, file manager, page builders) use exec functions:
#     MED for them is normal; look at the line before you quarantine.
#   - Shells in the database (a plugin option holding PHP) are not seen.
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
SV-16 Web shell hunter - find the PHP files red team uses to get back in
  sudo sh SV-16-webshell-hunter.sh                       scan, dry run
  sudo sh SV-16-webshell-hunter.sh --protected p.csv --apply
  sudo sh SV-16-webshell-hunter.sh --protected p.csv --watch 60 --auto-quarantine --apply

  --apply              quarantine (without it, dry run only)
  --webroot DIR        scan this folder too (repeatable)
  --hours N            "changed lately" = the last N hours (default 24)
  --show-low           also list LOW files
  --url URL            page to check after quarantining (repeatable)
  --wp-checksums FILE  WordPress checksums JSON (when wordpress.org is unreachable)
  --no-online          never try wordpress.org
  --watch SECONDS      keep checking for new or changed PHP files
  --auto-quarantine    with --watch and --apply: move HIGH files out at once
  --watch-count N      with --watch: stop after N rounds
  --timer SECONDS      revert countdown (default 120); --no-timer
  --no-color           no colours
  --help               show this text
USAGE
    cc_usage_common
}

NL='
'
EXTRA=""; HOURS=24; SHOWLOW=0; URLS=""; WPSUM=""; ONLINE=1; WATCH=""; AUTOQ=0; WCOUNT=0; TIMER=120; NOTIMER=0; COLOR=1
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --apply)           CC_APPLY=1; shift ;;
        --webroot)         [ $# -ge 2 ] || cc_die 2 "--webroot needs a folder"; [ -d "$2" ] || cc_die 2 "--webroot: not a folder: $2"; EXTRA="$EXTRA$(cc_abspath "$2")$NL"; shift 2 ;;
        --hours)           [ $# -ge 2 ] || cc_die 2 "--hours needs a number"; HOURS=$2; shift 2 ;;
        --show-low)        SHOWLOW=1; shift ;;
        --url)             [ $# -ge 2 ] || cc_die 2 "--url needs an address"; URLS="$URLS $2"; shift 2 ;;
        --wp-checksums)    [ $# -ge 2 ] || cc_die 2 "--wp-checksums needs a file"; [ -r "$2" ] || cc_die 2 "--wp-checksums: cannot read $2"; WPSUM=$(cc_abspath "$2"); shift 2 ;;
        --no-online)       ONLINE=0; shift ;;
        --watch)           [ $# -ge 2 ] || cc_die 2 "--watch needs seconds"; WATCH=$2; shift 2 ;;
        --auto-quarantine) AUTOQ=1; shift ;;
        --watch-count)     [ $# -ge 2 ] || cc_die 2 "--watch-count needs a number"; WCOUNT=$2; shift 2 ;;
        --timer)           [ $# -ge 2 ] || cc_die 2 "--timer needs seconds"; TIMER=$2; shift 2 ;;
        --no-timer)        NOTIMER=1; shift ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)         usage; exit 0 ;;
        *)                 cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
for _n in "$HOURS" "$TIMER" "$WATCH" "$WCOUNT"; do case "$_n" in *[!0-9]*) cc_die 2 "--hours, --timer, --watch and --watch-count need whole numbers" ;; esac; done
[ -z "$WATCH" ] || [ "$WATCH" -ge 5 ] || cc_die 2 "--watch must be at least 5 seconds"
[ "$AUTOQ" = 1 ] && [ -z "$WATCH" ] && cc_die 2 "--auto-quarantine needs --watch"

cc_init "SV-16" "Web shell hunter" changes
cc_detect_os
# shellcheck disable=SC2034  # read by cc_color_init
[ "$COLOR" = 1 ] || CC_NOCOLOR=1
cc_color_init
cc_use_numbered_dir webshells
rmdir "$CC_RUN_DIR/raw" 2>/dev/null
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF
W="$CC_RUN_DIR/.work"; mkdir -p "$W"
CC_CSV_DIR="$W/csv"; mkdir -p "$CC_CSV_DIR"
TAB=$(printf '\t')
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }

cc_show "$C_CYN" "SV-16 Web shell hunter | host $CC_HOST | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_RED}[!] HIGH${C_OFF}  ${C_YEL}[*] MED${C_OFF}  ${C_GRY}[-] LOW${C_OFF}   ${C_YEL}[~] would quarantine${C_OFF}   ${C_GRN}[+] quarantined${C_OFF}   ${C_RED}[x] failed${C_OFF}"

# ---- What to scan --------------------------------------------------------------------------
{
    for _d in /var/www /srv/www /srv/http /usr/share/nginx/html /usr/share/roundcube /var/lib/roundcube; do [ -d "$_d" ] && printf '%s\n' "$_d"; done
    printf '%s' "$EXTRA"
} | grep . | sort -u >"$W/roots"
[ -s "$W/roots" ] || { cc_show "$C_GRY" "No web folders here (give --webroot DIR)."; rm -rf "$W"; cc_finish; exit 0; }
WEBUSER=""; for _u in www-data apache nginx http wwwrun; do grep -q "^$_u:" /etc/passwd 2>/dev/null && { WEBUSER=$_u; break; }; done
WEBUID=$(awk -F: -v u="$WEBUSER" '$1 == u { print $3 }' /etc/passwd 2>/dev/null)
# xargs -0 keeps names with spaces whole; without it, one awk per file.
X0=0; [ "$(printf 'a b\0' | xargs -0 printf '%s' 2>/dev/null)" = "a b" ] && X0=1

# list_files ROOTS-FILE [NEWER-THAN] -> $W/php (code), $W/img (images/text), $W/hta
list_files() {
    : >"$W/php"; : >"$W/img"; : >"$W/hta"
    while IFS= read -r _d; do
        find "$_d" -xdev \( -name node_modules -o -name .git \) -prune -o -type f -size -5000k ${2:+-newer "$2"} -print 2>/dev/null
    done <"$1" | awk -v p="$W/php" -v i="$W/img" -v h="$W/hta" '
        { f = tolower($0); n = f; sub(/.*\//, "", n) }
        n == ".htaccess" || n == ".user.ini" { print >h; next }
        n ~ /\.(php[0-9]?|phtml|pht|phar|inc|module)$/ { print >p; next }
        n ~ /\.(jpe?g|png|gif|ico|bmp|svg|webp|txt|css|log)$/ { print >i }'
}
# The rules: one awk over many files.  Prints FILE<TAB>LEVEL<TAB>WHY<TAB>LINE<TAB>TEXT
cat >"$W/rules.awk" <<'AWK'
function hit(lv, why) {   # awk, not shell: posix-ok
    if ((FILENAME, why) in seen) return
    seen[FILENAME, why] = 1
    t = $0; gsub(/[\t\r]/, " ", t); sub(/^ +/, "", t)
    printf "%s\t%s\t%s\t%d\t%s\n", FILENAME, lv, why, FNR, substr(t, 1, 140)
}
{
    l = tolower($0)
    if (FILENAME ~ /\.htaccess$|\.user\.ini$/) {
        if (l ~ /(addtype|addhandler|sethandler|forcetype)[ \t].*(php|phtml)/ && l !~ /\.(php[0-9]?|phtml)([ \t"]|$)/) hit("HIGH", "makes other files run as PHP")
        if (l ~ /auto_(prepend|append)_file/) hit("HIGH", "runs a file before/after every page (auto_prepend_file)")
        next
    }
    if (IMG) { if (l ~ /<\?php|<\?=|<script language="php"/) hit("HIGH", "PHP code inside a non-PHP file"); next }
    if (l ~ /(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|assert|eval|create_function)[ \t]*\([ \t]*@?(stripslashes[ \t]*\([ \t]*|base64_decode[ \t]*\([ \t]*|trim[ \t]*\([ \t]*)?\$_(get|post|request|cookie|server|files)/) hit("HIGH", "runs request data as code or a command")
    if (l ~ /eval[ \t]*\([ \t]*@?(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|hex2bin|rawurldecode|urldecode|convert_uudecode)/) hit("HIGH", "eval of hidden (encoded) code")
    if (l ~ /\$_(get|post|request|cookie)[ \t]*\[[^]]*\][ \t]*\(/) hit("HIGH", "calls a function named in the request")
    if (l ~ /`[^`]*\$_(get|post|request|cookie)/) hit("HIGH", "runs request data in backticks")
    if (l ~ /preg_replace[ \t]*\([ \t]*["'][^"']*\/[a-z]*e[a-z]*["'][ \t]*,/) hit("HIGH", "preg_replace with /e (runs code)")
    if (l ~ /(c99shell|r57shell|wso shell|b374k|weevely|filesman|indoxploit|alfa ?shell|p0wny|phpspy|webshell|shell_exec\(\$_)/) hit("HIGH", "known web shell name or code")
    if (l ~ /(^|[^a-z_])(shell_exec|passthru|proc_open|popen|pcntl_exec)[ \t]*\(/) hit("MED", "runs programs (" substr(l, match(l, /(shell_exec|passthru|proc_open|popen|pcntl_exec)/), RLENGTH) ")")
    if (l ~ /(gzinflate|gzuncompress|str_rot13|convert_uudecode)[ \t]*\(/) hit("MED", "decodes hidden text")
    if (l ~ /(\\x[0-9a-f][0-9a-f]){8}/ || l ~ /\\x[0-9a-f][0-9a-f]\\x[0-9a-f][0-9a-f]\\x[0-9a-f][0-9a-f]\\x[0-9a-f][0-9a-f]\\x[0-9a-f][0-9a-f]\\x[0-9a-f][0-9a-f]/) hit("MED", "hex-escaped strings")
    if (length($0) > 400 && l ~ /base64_decode/) {
        s = $0
        while (match(s, /[A-Za-z0-9+\/=]+/)) { if (RLENGTH > 300) { hit("MED", "a long base64 blob"); break }; s = substr(s, RSTART + RLENGTH) }
    }
}
AWK
scan() {   # scan LIST-FILE IMG(0/1) -> appends hits to $W/hits
    [ -s "$1" ] || return 0
    if [ "$X0" = 1 ]; then tr '\n' '\0' <"$1" | xargs -0 awk -v IMG="$2" -f "$W/rules.awk" 2>/dev/null >>"$W/hits"
    else while IFS= read -r _f; do awk -v IMG="$2" -f "$W/rules.awk" "$_f" 2>/dev/null; done <"$1" >>"$W/hits"; fi
}
# Rules from where a file is, who owns it, when it changed.
place_rules() {   # place_rules PHP-LIST -> appends to $W/hits
    : >"$W/recent"; : >"$W/wown"
    while IFS= read -r _d; do
        [ "$HOURS" -gt 0 ] && find "$_d" -xdev -type f -mmin "-$((HOURS * 60))" 2>/dev/null >>"$W/recent"
        [ -n "$WEBUID" ] && find "$_d" -xdev -type f -user "$WEBUID" 2>/dev/null >>"$W/wown"
    done <"$W/roots"
    awk -F'\t' -v h="$HOURS" -v wu="$WEBUSER" -v rc="$W/recent" -v wo="$W/wown" -v up="$W/upcand" -v rf="$W/roots" '
        BEGIN { while ((getline l < rc) > 0) r[l] = 1; while ((getline l < wo) > 0) o[l] = 1; nr = 0; while ((getline l < rf) > 0) rt[++nr] = l }
        { f = $0; n = f; sub(/.*\//, "", n)
          # The folder names are only looked at inside the web root.
          rel = f; for (i = 1; i <= nr; i++) if (index(f, rt[i] "/") == 1 && length(rt[i]) < length(f)) { x = substr(f, length(rt[i]) + 1); if (length(x) < length(rel)) rel = x }
          if (rel ~ /\/(uploads|upload|images|image|files|media|sites\/default\/files)\//) print "HIGH\t" f > up
          else if (rel ~ /\/(tmp|temp|cache)\//) print "MED\t" f > up
          if (n ~ /^\./) printf "%s\tLOW\ta hidden file name\t0\t-\n", f
          if (f in r) printf "%s\tLOW\tchanged in the last %s hours\t0\t-\n", f, h
          if (f in o) printf "%s\tLOW\towned by the web server account (%s)\t0\t-\n", f, wu }' "$1" >>"$W/hits"
    # PHP in an upload folder - except WordPress's empty "Silence is golden" index.php.
    [ -f "$W/upcand" ] && while IFS="$TAB" read -r _lv _f; do
        if [ "$(wc -c <"$_f")" -lt 120 ] && grep -qi 'silence is golden' "$_f"; then continue; fi
        if [ "$_lv" = HIGH ]; then printf '%s\tHIGH\tPHP in an upload / image folder\t0\t-\n' "$_f" >>"$W/hits"
        else printf '%s\tMED\tPHP in a cache / temp folder\t0\t-\n' "$_f" >>"$W/hits"; fi
    done <"$W/upcand"
    rm -f "$W/upcand"
}

# ---- WordPress core against wordpress.org --------------------------------------------------
# $W/clean: core files that match (their MED/LOW hits are dropped).
wp_check() {
    : >"$W/clean"
    cc_have md5sum || return 0
    while IFS= read -r _d; do find "$_d" -maxdepth 4 -type f -path '*/wp-includes/version.php' 2>/dev/null; done <"$W/roots" | sort -u >"$W/wpv"
    while IFS= read -r _v; do
        _root=${_v%/wp-includes/version.php}
        _ver=$(sed -n "s/^\$wp_version *= *'\([^']*\)'.*/\1/p" "$_v")
        [ -n "$_ver" ] || continue
        _js="$W/wp-$_ver.json"
        if [ -n "$WPSUM" ]; then cp "$WPSUM" "$_js"
        elif [ "$ONLINE" = 1 ] && cc_have curl; then curl -s -m 15 -o "$_js" "https://api.wordpress.org/core/checksums/1.0/?version=$_ver&locale=en_US" 2>/dev/null; fi
        # {"checksums":{"wp-admin/about.php":"md5",...}} -> "md5  path"
        tr '{},' '\n\n\n' <"$_js" 2>/dev/null | sed -n 's/^"\([^"]*\)":"\([0-9a-f]\{32\}\)"$/\2  \1/p' >"$W/wpsum"
        if [ ! -s "$W/wpsum" ]; then
            cc_show "$C_GRY" "  WordPress $_ver in $_root: not checked against wordpress.org (cannot reach it; save the checksums and give --wp-checksums FILE)"
            continue
        fi
        (cd "$_root" && md5sum -c "$W/wpsum" 2>/dev/null) | awk -v r="$_root/" '/: OK$/ { sub(/: OK$/, ""); print r $0 > "/dev/stdout"; next } /: FAILED$/ { sub(/: FAILED$/, ""); print r $0 > "/dev/stderr" }' >>"$W/clean" 2>"$W/wpbad"
        while IFS= read -r _f; do case "$_f" in */wp-config-sample.php|*/readme.html|*/license.txt) continue ;; esac
            printf '%s\tHIGH\ta WordPress core file that differs from wordpress.org %s\t0\t-\n' "$_f" "$_ver" >>"$W/hits"; done <"$W/wpbad"
        awk '{ print $2 }' "$W/wpsum" | sort >"$W/wpknown"
        find "$_root/wp-admin" "$_root/wp-includes" -type f 2>/dev/null | sed "s|^$_root/||" | sort | comm -13 "$W/wpknown" - | while IFS= read -r _x; do
            printf '%s/%s\tHIGH\ta file in wp-admin/wp-includes that WordPress %s does not ship\t0\t-\n' "$_root" "$_x" "$_ver"; done >>"$W/hits"
        cc_show "$C_GRN" "  WordPress $_ver in $_root: $(grep -c . "$W/clean") core files match wordpress.org, $(grep -c . "$W/wpbad") differ"
    done <"$W/wpv"
}

# ---- Score -------------------------------------------------------------------------------
# $W/files: "SCORE<TAB>LEVEL<TAB>FILE" sorted; reasons stay in $W/hits.
score() {
    [ -s "$W/hits" ] || { : >"$W/files"; return; }
    awk -F'\t' -v c="$W/clean" 'BEGIN { while ((getline l < c) > 0) ok[l] = 1 }
        { if (($1 in ok) && $2 != "HIGH") next; s[$1] += ($2 == "HIGH" ? 5 : ($2 == "MED" ? 2 : 1))
          if ($2 == "HIGH") hi[$1] = 1; else if ($2 == "MED") me[$1] = 1 }
        END { for (f in s) { lv = ((f in hi) ? "HIGH" : ((f in me) ? "MED" : "LOW")); printf "%d\t%s\t%s\n", s[f], lv, f } }' "$W/hits" | sort -t"$TAB" -k1,1nr -k3 >"$W/files"
}
show_file() {   # show_file LEVEL FILE
    case "$1" in HIGH) _c=$C_RED; _m='[!]' ;; MED) _c=$C_YEL; _m='[*]' ;; *) _c=$C_GRY; _m='[-]' ;; esac
    cc_show "$_c" "  $_m $1  $2  ($(ls -l "$2" 2>/dev/null | awk '{ print $3 ":" $4 ", " $6 " " $7 " " $8 }'))"
    awk -F'\t' -v f="$2" '$1 == f { if ($4 > 0) printf "        - %s (line %d): %s\n", $3, $4, $5; else printf "        - %s\n", $3 }' "$W/hits" | while IFS= read -r _l; do cc_show "$C_GRY" "$_l"; done
}
# Site check (as SV-21).
page() {
    _s=""
    if cc_have curl; then _s=$(curl -s -m 10 -o "$W/page" -w '%{http_code}' "$1" 2>/dev/null)
    elif cc_have wget; then _s=$(wget -q -S -O "$W/page" -T 10 "$1" 2>&1 | awk '/HTTP\// { c = $2 } END { print c }'); fi
    _pe=0; grep -qiE 'Fatal error|Failed opening required|failed to open stream|No such file or directory in' "$W/page" 2>/dev/null && _pe=1
    printf '%s %s' "${_s:-000}" "$_pe"
}
[ -n "$URLS" ] || URLS="http://127.0.0.1/"
site_before() { : >"$W/site0"; for _u in $URLS; do printf '%s %s\n' "$_u" "$(page "$_u")" >>"$W/site0"; done; }
# site_worse -> true if a page that worked stopped working.  PHP caches
#   compiled files (opcache, rechecked every 2 s by default), so a moved file
#   can keep "working" for a few seconds: look at 3 s and again at 6 s.
site_worse() {
    : >"$W/worse"
    for _t in 3 3; do
        sleep "$_t"
        while read -r _u _s0 _e0; do
            _pg=$(page "$_u"); _s1=${_pg% *}; _e1=${_pg#* }
            _w0=0; case "$_s0" in [23]??) _w0=1 ;; esac; _w1=0; case "$_s1" in [23]??) _w1=1 ;; esac
            { [ "$_w0" = 1 ] && [ "$_w1" = 0 ]; } || { [ "$_e1" = 1 ] && [ "$_e0" = 0 ]; } && printf '%s %s -> %s\n' "$_u" "$_s0" "$_s1" >>"$W/worse"
        done <"$W/site0"
        [ -s "$W/worse" ] && return 0
    done
    return 1
}
put_back() {   # put_back UNDO-LINE-COUNT -> replay this run's undo lines
    awk -F'\t' -v n="${1:-0}" 'NR > n { l[NR] = $4 } END { for (i = NR; i > n; i--) print l[i] }' "$CC_UNDO" >"$W/undo-now"
    while IFS= read -r _cmd; do sh -c "$_cmd" >>"$CC_LOG" 2>&1 || cc_show "$C_RED" "  [x] could not undo: $_cmd"; done <"$W/undo-now"
}

# ---- Watch mode --------------------------------------------------------------------------
if [ -n "$WATCH" ]; then
    WF="$CC_RUN_DIR/watch.txt"
    cc_show "$C_CYN" "Watching $(tr '\n' ' ' <"$W/roots")every $WATCH s for new or changed PHP files$([ "$AUTOQ" = 1 ] && [ "$CC_APPLY" = 1 ] && echo ', moving HIGH ones out'). Ctrl-C to stop."
    [ "$AUTOQ" = 1 ] && [ "$CC_APPLY" != 1 ] && cc_show "$C_YEL" "  [*] --auto-quarantine without --apply: only reporting."
    touch "$W/last"; _round=0; : >"$W/clean"
    trap 'cc_show "" "Stopped. Log: $WF"; rm -rf "$W"; cc_finish; exit 0' INT TERM
    while :; do
        _round=$((_round + 1)); sleep "$WATCH"
        touch "$W/now"
        list_files "$W/roots" "$W/last"
        mv "$W/now" "$W/last"
        : >"$W/hits"; scan "$W/php" 0; scan "$W/img" 1; scan "$W/hta" 0
        # Every new or changed PHP file is at least reported.
        while IFS= read -r _f; do printf '%s\tLOW\tnew or changed while watching\t0\t-\n' "$_f" >>"$W/hits"; done <"$W/php"
        HOURS=0; place_rules "$W/php"; score
        while IFS="$TAB" read -r _s _lv _f; do
            [ "$_lv" = LOW ] && [ "$SHOWLOW" = 0 ] && { cc_show "$C_GRY" "$(date +%H:%M:%S) [-] new/changed: $_f"; printf '%s LOW %s\n' "$(date '+%F %T')" "$_f" >>"$WF"; continue; }
            cc_show "" "$(date +%H:%M:%S)"; show_file "$_lv" "$_f"
            printf '%s %s %s\n' "$(date '+%F %T')" "$_lv" "$_f" >>"$WF"
            if [ "$_lv" = HIGH ] && [ "$AUTOQ" = 1 ] && [ "$CC_APPLY" = 1 ]; then
                site_before; _u0=$(grep -c . "$CC_UNDO" 2>/dev/null)
                if cc_guard file "$_f" && cc_quarantine "$_f" >>"$CC_LOG" 2>&1; then
                    if site_worse; then put_back "$_u0"; cc_show "$C_RED" "        [x] the site broke without it: put back"
                    else cc_show "$C_GRN" "        [+] quarantined"; printf '%s quarantined %s\n' "$(date '+%F %T')" "$_f" >>"$WF"; fi
                fi
            fi
        done <"$W/files"
        [ "$WCOUNT" -gt 0 ] && [ "$_round" -ge "$WCOUNT" ] && break
    done
    trap - INT TERM
    rm -rf "$W"; cc_finish; exit 0
fi

# ---- Scan --------------------------------------------------------------------------------
header "1/4  scan"
list_files "$W/roots"
cc_show "" "  $(grep -c . "$W/php") PHP files, $(grep -c . "$W/img") images/text files, $(grep -c . "$W/hta") .htaccess files in: $(tr '\n' ' ' <"$W/roots")"
: >"$W/hits"
scan "$W/php" 0; scan "$W/img" 1; scan "$W/hta" 0
place_rules "$W/php"
wp_check
score

header "2/4  findings"
NH=$(grep -c "${TAB}HIGH${TAB}" "$W/files"); NM=$(grep -c "${TAB}MED${TAB}" "$W/files"); NL0=$(grep -c "${TAB}LOW${TAB}" "$W/files")
while IFS="$TAB" read -r _s _lv _f; do
    [ "$_lv" = LOW ] && [ "$SHOWLOW" = 0 ] && continue
    show_file "$_lv" "$_f"
done <"$W/files"
[ "$NH$NM" = 00 ] && cc_show "$C_GRN" "  [ok] no HIGH or MED files"
[ "$NL0" -gt 0 ] && [ "$SHOWLOW" = 0 ] && cc_show "$C_GRY" "  ($NL0 LOW file(s) - changed lately, owned by the web server, hidden names - in findings.txt; --show-low lists them)"
{
    printf 'SV-16 findings | host %s | %s\n\n' "$CC_HOST" "$(date '+%F %T')"
    while IFS="$TAB" read -r _s _lv _f; do
        printf '%-4s %2d  %s\n' "$_lv" "$_s" "$_f"
        awk -F'\t' -v f="$_f" '$1 == f { if ($4 > 0) printf "           - %s (line %d): %s\n", $3, $4, $5; else printf "           - %s\n", $3 }' "$W/hits"
    done <"$W/files"
} >"$CC_RUN_DIR/findings.txt"

# ---- Questions ---------------------------------------------------------------------------
header "3/4  questions (Enter = the default in capitals)"
: >"$W/chosen"
awk -F'\t' '$2 != "LOW"' "$W/files" >"$W/ask"
if [ -s "$W/ask" ]; then
    _all=0
    while IFS="$TAB" read -r _s _lv _f; do
        _d=k; [ "$_lv" = HIGH ] && _d=q
        if [ "$_all" = 1 ]; then [ "$_d" = q ] && printf '%s\n' "$_f" >>"$W/chosen"; continue; fi
        cc_choose "$_lv: $_f?" "$_d" "q=quarantine it (moved out of the site; the undo puts it back)" "k=keep it" "a=all the rest: take their defaults (HIGH out, MED kept)"
        case "$CC_CHOICE" in
            q) printf '%s\n' "$_f" >>"$W/chosen" ;;
            a) _all=1; [ "$_d" = q ] && printf '%s\n' "$_f" >>"$W/chosen" ;;
        esac
    done <"$W/ask"
fi
NCH=$(grep -c . "$W/chosen")

# ---- Apply -------------------------------------------------------------------------------
header "4/4  quarantine"
NOK=0; NBAD=0; APPLIED=0; TIMER_ON=0; BROKE=0
if [ "$NCH" -eq 0 ]; then cc_show "$C_GRN" "  [ok] Nothing to quarantine."
elif [ "$CC_APPLY" != 1 ] || ! cc_is_root; then
    cc_is_root || cc_show "$C_YEL" "  [!] not root: showing the plan only"
    while IFS= read -r _f; do cc_show "$C_YEL" "  [~] quarantine $_f"; done <"$W/chosen"
    cc_show "$C_GRY" "  Dry run: nothing was changed. Run again with --apply."
    # shellcheck disable=SC2034  # read by cc_finish
    CC_N_WOULD=$NCH
elif cc_ask "Quarantine these $NCH file(s)?" Y "yes, move them out of the site (a revert timer puts them back unless you confirm from a NEW session)" "no, leave them"; then
    APPLIED=1
    site_before
    U0=$(grep -c . "$CC_UNDO" 2>/dev/null)
    if [ "$NOTIMER" != 1 ]; then cc_timer_start "$TIMER"; TIMER_ON=1
        cc_show "$C_YEL" "  [*] Revert timer started: the files come back in $((TIMER / 60)):$(printf '%02d' $((TIMER % 60))) unless you keep it at the end."; fi
    while IFS= read -r _f; do
        if ! cc_guard file "$_f"; then cc_show "$C_YEL" "  [-] $_f: protected, kept"; continue; fi
        if cc_quarantine "$_f" >>"$CC_LOG" 2>&1; then cc_show "$C_GRN" "  [+] quarantined $_f"; NOK=$((NOK + 1))
        else cc_show "$C_RED" "  [x] could not quarantine $_f"; NBAD=$((NBAD + 1)); fi
    done <"$W/chosen"
    if site_worse; then
        BROKE=1
        while IFS= read -r _l; do cc_show "$C_RED" "  [x] worse now: $_l"; done <"$W/worse"
        cc_show "$C_RED" "  The site needs one of these files: putting them all back, then trying them one at a time ..."
        put_back "$U0"; NOK=0; sleep 3
        # One at a time: a file the site needs goes back and is reported.
        : >"$W/needed"
        while IFS= read -r _f; do
            cc_is_protected file "$_f" && continue
            _u1=$(grep -c . "$CC_UNDO" 2>/dev/null)
            cc_quarantine "$_f" >>"$CC_LOG" 2>&1 || continue
            if site_worse; then put_back "$_u1"; sleep 3; printf '%s\n' "$_f" >>"$W/needed"; cc_show "$C_RED" "  [x] the site needs $_f: put back - it is still a HIGH file: read it and clean it by hand"
            else NOK=$((NOK + 1)); cc_show "$C_GRN" "  [+] quarantined $_f (the site still loads)"; fi
        done <"$W/chosen"
        [ -s "$W/needed" ] || BROKE=0
    else
        while read -r _u _s0 _e0; do cc_show "$C_GRN" "  [+] $_u still answers ($(page "$_u" | cut -d' ' -f1))"; done <"$W/site0"
    fi
else cc_show "$C_GRY" "  Not quarantined."; fi
# shellcheck disable=SC2034  # read by cc_finish
CC_N_DONE=$NOK
# shellcheck disable=SC2034  # read by cc_finish
CC_N_FAIL=$NBAD

# ---- Summary ----------------------------------------------------------------------------
{
    printf '==========[ summary ]==========\n'
    printf 'SV-16 Web shell hunter | host %s | %s\n' "$CC_HOST" "$([ "$APPLIED" = 1 ] && { [ "$BROKE" = 1 ] && echo 'QUARANTINED (some put back: the site needs them)' || echo QUARANTINED; } || echo 'DRY RUN - nothing changed')"
    printf 'Files: %d HIGH, %d MED, %d LOW   (findings.txt has every one with its reasons)\n' "$NH" "$NM" "$NL0"
    awk -F'\t' '$2 != "LOW" { printf "  %-4s %s\n", $2, $3 }' "$W/files" | head -n 40
    [ "$APPLIED" = 1 ] && printf 'Quarantined: %d   Failed: %d\n' "$NOK" "$NBAD"
    [ -s "$W/needed" ] && { printf 'The site needs these, so they were put back - clean them by hand (remove the bad lines, keep the rest):\n'; sed 's/^/  /' "$W/needed"; }
    [ "$APPLIED" = 1 ] && [ -f "$CC_RUN_DIR/revert.sh" ] && printf 'Undo this run: sh %s/revert.sh --force\n' "$CC_RUN_DIR"
    printf '\nNext: SV-15 --backup once the site is clean; SV-16 --watch 60 to catch the next one; SV-21 upload-nophp stops PHP running in uploads.\n'
} >"$CC_RUN_DIR/summary.txt"
cc_show "" ""
while IFS= read -r _l; do
    case "$_l" in ==*|SV-16*) cc_show "$C_CYN" "$_l" ;; *'PUT BACK'*|'  HIGH'*) cc_show "$C_RED" "$_l" ;; '  MED'*) cc_show "$C_YEL" "$_l" ;; *) cc_show "" "$_l" ;; esac
done <"$CC_RUN_DIR/summary.txt"
rm -rf "$W"
if [ "$TIMER_ON" = 1 ]; then header "KEEP OR REVERT"; cc_show "$C_YEL" "[*] Before you answer: load the store and click through it."; cc_timer_finish || true; fi
cc_finish
