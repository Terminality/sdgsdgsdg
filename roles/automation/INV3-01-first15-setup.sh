#!/bin/sh
# =============================================================================
# ID:       INV3-01
# NAME:     Invitational 3 first-15 setup
# ROLE:     Automation  (wave 1)
# KIND:     readonly - writes only to the chosen output folder
#
# PURPOSE
#   Builds the Invitational 3 team inventory, NAT map, protected list, service
#   matrix and change log. Prints the safe first-15 order and validation steps.
#   It can launch SH-03 read-only discovery.
#
# USAGE
#   sh INV3-01-first15-setup.sh --team 7 --out ~/ccdc-control
#   sh INV3-01-first15-setup.sh --team 7 --scan --kit /opt/ccdc/dist --out ~/ccdc-control
#
# INPUTS
#   --team N       team number used in the external 10.100.1XX.Y NAT address
#   --kit DIR      dist/ directory; defaults to the directory above this file
#   --scan         run SH-03 against 192.168.220.0/24 after writing the files
#
# OUTPUTS
#   inv3-control-N/hosts.csv             internal inventory for kit scripts
#   inv3-control-N/nat-map.csv           internal-to-external address map
#   inv3-control-N/protected.csv         starter list; add Quotient data first
#   inv3-control-N/service-matrix.csv    functional validation tracker
#   inv3-control-N/hardening-status.csv  one row per host; no credentials
#   inv3-control-N/change-log.csv        team change record
#   inv3-control-N/first15.txt           role order and per-host commands
#
# WHAT IT CHANGES
#   Nothing on competition systems. It writes planning files under --out.
#   --scan only calls the read-only SH-03 network scan.
#
# DEPENDS ON
#   POSIX sh and the shared library. SH-03 is optional and used only with
#   --scan. The packet inventory is embedded so the dist file stands alone.
#
# TESTED ON
#   not yet tested on a real competition jump box
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   Exact scored services and scoring accounts are withheld until competition
#   day. The generated protected list is incomplete until Quotient and live
#   discovery are recorded. Credential rotation is outside this controller.
# =============================================================================

# >>> CCDC-LIB
_cc_d=$(cd "$(dirname "$0")" && pwd)
while [ "$_cc_d" != "/" ] && [ ! -f "$_cc_d/lib/lib.sh" ]; do _cc_d=$(dirname "$_cc_d"); done
[ -f "$_cc_d/lib/lib.sh" ] || { echo "cannot find lib/lib.sh above $0" >&2; exit 3; }
. "$_cc_d/lib/lib.sh"
# <<< CCDC-LIB

usage() {
    cat <<'USAGE'
INV3-01 Invitational 3 first-15 setup
  sh INV3-01-first15-setup.sh --team N [options]

Options:
  --team N       team number, 1 through 99 (required)
  --kit DIR      path to dist/ (default: parent of this script's role folder)
  --scan         launch the read-only SH-03 scan after setup
  --help         show this text

Fill protected.csv from Quotient before any firewall, account or service
change. Credential rotation is handled by the team's separate process.

USAGE
    cc_usage_common
}

TEAM=""
KIT=""
DO_SCAN=0
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --team) [ $# -ge 2 ] || cc_die 2 "--team needs a number"; TEAM=$2; shift 2 ;;
        --kit) [ $# -ge 2 ] || cc_die 2 "--kit needs a directory"; KIT=$2; shift 2 ;;
        --scan) DO_SCAN=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done

case "$TEAM" in ''|*[!0-9]*) cc_die 2 "--team must be a number from 1 through 99" ;; esac
[ "$TEAM" -ge 1 ] 2>/dev/null && [ "$TEAM" -le 99 ] 2>/dev/null || cc_die 2 "--team must be from 1 through 99"

cc_init "INV3-01" "Invitational 3 first-15 setup" readonly
cc_use_numbered_dir "inv3-control"

if [ -z "$KIT" ]; then
    _au_here=$(cd "$(dirname "$0")" && pwd)
    KIT=$(dirname "$_au_here")
fi

# Keep the address formula visible. Team 7 becomes 10.100.107.Y; team 13
# becomes 10.100.113.Y. The internal address is always 192.168.220.Y.
NAT_PREFIX="10.100.1$(printf '%02d' "$TEAM")"

HOSTS="$CC_RUN_DIR/hosts.csv"
NAT="$CC_RUN_DIR/nat-map.csv"
PROTECTED="$CC_RUN_DIR/protected.csv"
SERVICES="$CC_RUN_DIR/service-matrix.csv"
HARDENING="$CC_RUN_DIR/hardening-status.csv"
CHANGES="$CC_RUN_DIR/change-log.csv"
GUIDE="$CC_RUN_DIR/first15.txt"

cat >"$HOSTS" <<EOF
host,ip,os,role,connect,port,user,scored_services,notes
vigra,192.168.220.2,openwrt,router,ssh,22,admin,,Router; record NAT firewall routes and WAN management before changes
kolla,192.168.220.30,alpine,fileshare,ssh,22,root,,Discover SMB NFS FTP and authenticated share workflows
borgar,192.168.220.10,windows,Windows Server 2022 food ordering,winrm,5985,Administrator,,Discover application database IIS and service-account dependencies
gufu,192.168.220.100,rocky,Gitea,ssh,22,root,,Back up app.ini repositories and database before changes
vattar,192.168.220.79,windows,Windows Server 2019 Active Directory,winrm,5985,Administrator,,Run AD enum and protect DNS Kerberos LDAP SMB RPC and scoring identities
haf,192.168.220.67,lubuntu,Wabbit,ssh,22,root,,Unknown application; inventory process ports data and business workflow
kvigindis,192.168.220.44,ubuntu,Furniture Help Site,ssh,22,root,,Discover web application database and authentication dependencies
skerja,192.168.220.97,alpine,Employee and Customer Tickets,ssh,22,root,,Discover ticket application database and authentication dependencies
thorska,192.168.220.231,fedora,Home Manager,ssh,22,root,,Discover application database and authentication dependencies
djupi,192.168.220.222,mint,Point of Sale,ssh,22,root,,Discover POS database payment and authentication dependencies
EOF

cat >"$NAT" <<EOF
host,internal_ip,external_ip,last_octet,purpose
vigra,192.168.220.2,$NAT_PREFIX.2,2,OpenWRT router
kolla,192.168.220.30,$NAT_PREFIX.30,30,Fileshare
borgar,192.168.220.10,$NAT_PREFIX.10,10,Food ordering
gufu,192.168.220.100,$NAT_PREFIX.100,100,Gitea
vattar,192.168.220.79,$NAT_PREFIX.79,79,Active Directory
haf,192.168.220.67,$NAT_PREFIX.67,67,Wabbit
kvigindis,192.168.220.44,$NAT_PREFIX.44,44,Furniture help
skerja,192.168.220.97,$NAT_PREFIX.97,97,Tickets
thorska,192.168.220.231,$NAT_PREFIX.231,231,Home manager
djupi,192.168.220.222,$NAT_PREFIX.222,222,Point of sale
EOF

cat >"$PROTECTED" <<'EOF'
type,value,note
host,192.168.220.2,OpenWRT router and gateway - never block or bulk change
port,22/tcp,SSH until another tested access path exists
port,53,DNS when discovered or scored - TCP and UDP
port,80/tcp,HTTP when discovered or scored
port,88,Kerberos on Active Directory - TCP and UDP
port,123/udp,time synchronization dependency when present
port,135/tcp,Windows RPC endpoint mapper
port,139/tcp,NetBIOS when used by file sharing or AD
port,389,LDAP - TCP and UDP
port,443/tcp,HTTPS when discovered or scored
port,445/tcp,SMB and Active Directory dependency
port,464,Kerberos password changes - TCP and UDP
port,636/tcp,LDAPS when configured
port,2049,NFS when the fileshare uses it - TCP and UDP
port,3268/tcp,Active Directory global catalog
port,3269/tcp,secure global catalog when configured
port,3389/tcp,RDP or manual interactive check when present
port,5985/tcp,WinRM used for team access or scoring
port,5986/tcp,WinRM TLS used for team access or scoring
service,NTDS,Active Directory Domain Services
service,DNS,Active Directory DNS
service,Netlogon,domain authentication
service,KDC,Kerberos authentication
account,ccdc-automation,team automation account if created
path,C:\Windows\SYSVOL,Group Policy and logon scripts
EOF

cat >"$SERVICES" <<'EOF'
host,internal_ip,external_ip,service,protocol_port,scoring_account,owner,dependency,local_test,remote_test,business_test,quotient_status,orange_status,last_checked_utc,notes
vigra,192.168.220.2,,router,,,,,,,,unknown,unknown,,Record scoring source WAN rules routes NAT and management
kolla,192.168.220.30,,fileshare,,,,,,,,unknown,unknown,,Identify protocol and authenticated read-write workflow
borgar,192.168.220.10,,food-ordering,,,,,,,,unknown,unknown,,Place a test order without changing production data
gufu,192.168.220.100,,gitea,,,,,,,,unknown,unknown,,Login browse repository and perform approved read operation
vattar,192.168.220.79,,active-directory,,,,,,,,unknown,unknown,,Test DNS domain authentication LDAP and required shares
haf,192.168.220.67,,wabbit,,,,,,,,unknown,unknown,,Determine the actual application workflow
kvigindis,192.168.220.44,,help-site,,,,,,,,unknown,unknown,,Load and authenticate if required
skerja,192.168.220.97,,ticketing,,,,,,,,unknown,unknown,,Create view and update a test ticket if permitted
thorska,192.168.220.231,,home-manager,,,,,,,,unknown,unknown,,Perform the application workflow shown by Quotient
djupi,192.168.220.222,,point-of-sale,,,,,,,,unknown,unknown,,Perform a safe test transaction workflow
EOF

cat >"$HARDENING" <<'EOF'
host,owner,inventory_complete,backup_off_host,monitoring_started,protected_list_current,safe_fixes_dry_run,safe_fixes_applied,persistence_reviewed,firewall_plan_reviewed,fresh_session_tested,business_tested,quotient_checked,status,notes
vigra,,no,no,no,no,n/a,n/a,no,no,no,no,no,discovery,Router uses separate OpenWRT procedure; no generic host hardening
kolla,,no,no,no,no,no,no,no,no,no,no,no,discovery,Preserve authenticated fileshare workflow and ACLs
borgar,,no,no,no,no,no,no,no,no,no,no,no,discovery,Preserve food-ordering application and database dependencies
gufu,,no,no,no,no,no,no,no,no,no,no,no,discovery,Preserve Gitea repositories app.ini database and SSH Git if used
vattar,,no,no,no,no,no,no,no,no,no,no,no,discovery,Preserve complete AD DNS Kerberos LDAP SMB RPC dependencies
haf,,no,no,no,no,no,no,no,no,no,no,no,discovery,Identify Wabbit before service or firewall hardening
kvigindis,,no,no,no,no,no,no,no,no,no,no,no,discovery,Preserve help-site web app database and uploads
skerja,,no,no,no,no,no,no,no,no,no,no,no,discovery,Preserve ticket database attachments sessions and notifications
thorska,,no,no,no,no,no,no,no,no,no,no,no,discovery,Preserve Home Manager and SELinux firewalld context
djupi,,no,no,no,no,no,no,no,no,no,no,no,discovery,Preserve POS UI database integrations and transaction data
EOF

cat >"$CHANGES" <<'EOF'
utc,requester,owner,host,service,action,exact_command,protected_version,precheck,postcheck,quotient_or_orange,rollback,status,notes
EOF

cat >"$GUIDE" <<EOF
INVITATIONAL 3 - FIRST 15 MINUTES
=================================

Team: $TEAM
Internal network: 192.168.220.0/24
External NAT prefix: $NAT_PREFIX.Y
Scoring: about 8-12 services checked every 2-4 minutes; SLA after 5 failures.

0:00-0:03 - captain and automation
  1. Open SSO, Quotient, ticket portal and private Discord text/voice.
  2. Put one person in the private voice channel for Orange Team.
  3. Fill service-matrix.csv from Quotient. Exact live data overrides this file.
  4. Add scoring IPs, accounts, ports, services and paths to protected.csv.
  5. Assign one owner per host. Do not let two people change one host.

0:03-0:08 - read-only inventory in parallel
  Network: SH-03 against 192.168.220.0/24; record both NAT perspectives.
  Router: back up /etc/config, routes, firewall and NAT before any change.
  Windows: SH-06; add WN-04 on vattar.
  Linux: SH-05 everywhere; add SV-01 on application/database hosts.

0:08-0:12 - backups, account plan and monitoring
  Windows: WN-35, then WN-44.
  Linux: LX-31; SV-14 where a database exists; then LX-40 and LX-41.
  Copy backups/evidence off each host. A local-only backup is not complete.
  Build the protected account list from Quotient and service dependencies.
  Dry-run LX-20/WN-20/NW-10; do not rotate an unknown service/scorer account.

0:12-0:15 - controlled account changes, validate and prioritize
  1. Rotate only approved interactive accounts, one host/device at a time.
  2. Test a new SSH/RDP/console login before keeping each password change.
  3. Do not rotate service, task, app-pool, database, scorer or unknown accounts.
  4. Test each listed business workflow, not only its listening port.
  5. Stop and revert immediately if access, a service or scoring fails.

Credential rotation is handled by the team's separate procedure (opt-in) in
INV3-FIRST15-ROLE-CARDS.md. INV3-01 itself does not generate, change, store,
transmit or track passwords.

Use hardening-status.csv to gate each host. Inventory, off-host backup,
monitoring, current protected list and a business test come before safe fixes.
Firewall planning and fresh-session validation are last.

VALIDATION AFTER EVERY CHANGE
=============================
  on-host test -> internal remote test -> mapped external test when permitted
  -> real business workflow -> Quotient for at least two cycles
  Because the SLA is five consecutive failures, do not wait five failures to
  roll back a team change. Roll back on the first new failure you caused.

Do not use AI to author or rewrite inject submissions. The packet requires
human-authored PDFs named like inject04_team13.pdf with cited external sources.
EOF

# Add calculated external addresses without relying on non-POSIX CSV tools.
_au_tmp="$CC_RUN_DIR/services.tmp"
awk -F, -v p="$NAT_PREFIX" 'BEGIN { OFS="," } NR==1 { print; next } { split($2,a,"."); $3=p "." a[4]; print }' "$SERVICES" >"$_au_tmp" && mv "$_au_tmp" "$SERVICES"

cc_info "team $TEAM workspace: $CC_RUN_DIR"
cc_info "internal network: 192.168.220.0/24"
cc_info "external NAT prefix: $NAT_PREFIX.Y"
cc_info "fill protected.csv and service-matrix.csv from Quotient before changes"
cc_info "track each host's hardening gate in hardening-status.csv"
cc_info "credential rotation is outside INV3-01 and remains with the team process"

if [ "$DO_SCAN" -eq 1 ]; then
    SCAN="$KIT/network/SH-03-network-scan.sh"
    [ -r "$SCAN" ] || cc_die 3 "cannot read SH-03 at $SCAN (use --kit DIR)"
    cc_info "launching read-only Invitational 3 discovery"
    sh "$SCAN" --target 192.168.220.0/24 --hosts "$HOSTS" --profile wrccdc --out "$CC_RUN_DIR/discovery"
    _au_rc=$?
    [ "$_au_rc" -eq 0 ] || cc_warn "SH-03 returned $_au_rc; review discovery before any change"
fi

cc_info "read $GUIDE"
cc_finish
