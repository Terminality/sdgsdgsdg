# Invitational 3 server guide

Use this after AU-01 creates the team workspace. It is based on the packet's
host table; live discovery and Quotient override every assumption here.

Do not begin by patching, stopping services or closing ports. First identify
the process, configuration, data, authentication and upstream/downstream
dependencies behind each business service.

## Common first steps

For every host, record these in `service-matrix.csv` and `change-log.csv`:

1. Owner, internal address and mapped external address.
2. Access method and a second tested session.
3. OS/version, running services, listeners and active connections.
4. Application process, executable, account, configuration, data and logs.
5. Database, DNS, AD, file-share and other host dependencies.
6. Quotient check name, account, port and latest result.
7. A real business-function test and its last known-good time.
8. Restorable backup location off the host.

Linux first look:

```sh
cat /etc/os-release
id
ip -br address 2>/dev/null || ip address
ip route
ss -lntup 2>/dev/null || netstat -lntup
ps auxf 2>/dev/null || ps -ef
systemctl --failed 2>/dev/null || rc-status -a 2>/dev/null
```

Then run the standalone read-only inventory and backup:

```sh
sudo sh SH-05-linux-enum.sh --out /root/ccdc-out --profile full
sudo sh LX-31-backup.sh --out /root/ccdc-out --copy-to APPROVED_OFF_HOST_PATH
```

On application hosts, also run:

```sh
sudo sh SV-01-web-db-enum.sh --out /root/ccdc-out
```

Windows first look, from elevated PowerShell:

```powershell
hostname
whoami /all
Get-WmiObject Win32_OperatingSystem | Select Caption,Version,LastBootUpTime
Get-WmiObject Win32_Service | Where State -eq 'Running' | Select Name,StartName,PathName
netstat -ano
tasklist /svc
```

Then run SH-06 and WN-35. Add WN-04 on the domain controller.

## vigra - OpenWRT router - 192.168.220.2

### What it does

The packet identifies vigra as the OpenWRT router. It controls the path between
the team/VPN side and `192.168.220.0/24`, including the `10.100.1XX.Y` one-to-one
NAT. A mistake can take every service down, and a reset costs 100 points.

### First actions

```sh
ubus call system board
ip -br address
ip route
uci export > /tmp/vigra-uci.txt
uci show network
uci show firewall
uci show dhcp
nft list ruleset 2>/dev/null || fw3 print 2>/dev/null
logread | tail -n 200
sysupgrade -b /tmp/vigra-prechange.tar.gz
```

Copy the UCI export and sysupgrade archive off-device before changing anything.
Record WAN/LAN zones, forwarding, redirects, NAT, management rules, routes,
DNS/DHCP and the scoring source addresses. Keep two management sessions.

### Validate

- Router management from a new session.
- Internal reachability to every known host.
- External mapped reachability where permitted.
- DNS and every currently passing Quotient service for two cycles.

### Stop conditions

Do not reload the firewall when the scoring source, NAT mapping, recovery path
or backup is unknown. Do not replace the whole ruleset to fix one rule.

### Official resources

- [OpenWRT backup and restore](https://openwrt.org/docs/guide-user/troubleshooting/backup_restore)
- [OpenWRT firewall configuration](https://openwrt.org/docs/guide-user/firewall/firewall_configuration)
- [OpenWRT UCI system](https://openwrt.org/docs/guide-user/base-system/uci)

## kolla - Alpine Linux fileshare - 192.168.220.30

### What it does

The packet calls kolla a fileshare but does not identify SMB, NFS, FTP or the
business workflow. Authenticated shares are likely candidates for manual
scoring, so discover the actual protocol before hardening it.

### First actions

```sh
rc-status -a
rc-update show -v
ss -lntup 2>/dev/null || netstat -lntup
mount
df -h
testparm -s 2>/dev/null
smbstatus 2>/dev/null
exportfs -v 2>/dev/null
showmount -e localhost 2>/dev/null
```

Locate `/etc/samba/smb.conf`, `/etc/exports`, FTP configuration, share paths,
filesystem permissions, ACLs, owners, authentication sources and active users.
Back up configuration and share metadata before changing access controls.

### Validate

From another host, authenticate as an approved test user, list the share, read
a known file and perform an approved create/update/delete cycle. Confirm the
same workflow Orange Team is expected to use.

### Official resources

- [Alpine Linux handbook](https://docs.alpinelinux.org/)
- [Alpine OpenRC service management](https://docs.alpinelinux.org/user-handbook/0.1a/Working/openrc.html)
- [Samba documentation](https://www.samba.org/samba/docs/)
- [Linux NFS administration](https://docs.kernel.org/admin-guide/nfs/index.html)

## borgar - Windows Server 2022 food ordering - 192.168.220.10

### What it does

Borgar hosts the food-ordering service. The packet does not identify IIS, its
application runtime or database, so treat all of those as discovery targets.

### First actions

Run SH-06 and WN-35, then record:

```powershell
Get-WindowsFeature | Where Installed
Get-Website -ErrorAction SilentlyContinue
Get-WebAppPoolState -Name * -ErrorAction SilentlyContinue
Get-WmiObject Win32_Service | Select Name,State,StartName,PathName
schtasks /query /fo LIST /v
netstat -ano
```

Map listener PID to process, service account, web/app configuration, database
connection, scheduled jobs, data directories and logs. Preserve IIS config,
application files and the database before changing any dependency.

### Validate

Load the customer interface from another system, authenticate if required,
view the menu, place an approved test order and confirm it reaches the expected
backend without generating duplicate or destructive production data.

### Official resources

- [Microsoft IIS documentation](https://learn.microsoft.com/iis/)
- [Windows Server troubleshooting documentation](https://learn.microsoft.com/troubleshoot/windows-server/)
- [PowerShell documentation](https://learn.microsoft.com/powershell/)

## gufu - Rocky Linux Gitea - 192.168.220.100

### What it does

Gufu provides the Git service. Gitea can depend on SQLite, MySQL, PostgreSQL or
MSSQL plus repository storage, LFS, SSH, a reverse proxy and systemd.

### First actions

```sh
systemctl status gitea --no-pager
systemctl cat gitea
journalctl -u gitea -n 200 --no-pager
ps auxf | grep '[g]itea'
ss -lntup
find /etc /var/lib /home -name app.ini -o -name gitea 2>/dev/null
```

Record the Gitea binary/version, service user, `app.ini`, work/custom paths,
repository root, attachments/LFS, database type, SSH integration, proxy and
logs. Check free space before creating a dump. Do not run a repair option from
`gitea doctor` during initial triage.

### Back up and validate

Use LX-31/SV-14 and the application-aware Gitea dump after identifying its
paths and database. Test web login, repository browsing and an approved clone
or read operation. Validate SSH Git only if Quotient or the business uses it.

### Official resources

- [Gitea administration command line and dump](https://docs.gitea.com/administration/command-line/)
- [Gitea configuration cheat sheet](https://docs.gitea.com/administration/config-cheat-sheet/)
- [Rocky Linux documentation](https://docs.rockylinux.org/)

## vattar - Windows Server 2019 Active Directory - 192.168.220.79

### What it does

Vattar provides identity and likely DNS, Kerberos, LDAP, Group Policy and
SYSVOL. Other applications may authenticate against it even when AD is not a
separate scored line.

### First actions

Run SH-06, WN-04 and WN-35 before policy or account changes. Then capture:

```powershell
dcdiag /v
dcdiag /test:DNS /v
repadmin /replsummary
repadmin /showrepl
ipconfig /all
net share
sc query DNS
sc query NTDS
sc query Netlogon
```

Record domain/forest names, FSMO roles, DNS zones/forwarders, DC DNS client
settings, privileged groups, GPOs, SYSVOL scripts, trusts, service identities
and recent security/directory/DNS events.

### Validate

From another host, resolve the domain/DC records, authenticate an approved test
user, access a required share and exercise an application that depends on AD.
An open LDAP port is not proof that domain authentication works.

### Stop conditions

Do not change DNS client settings, GPOs, service identities, SPNs, delegation,
Kerberos settings or AD-integrated zones without a backup and dependency owner.

### Official resources

- [Microsoft dcdiag reference](https://learn.microsoft.com/windows-server/administration/windows-commands/dcdiag)
- [Verify DNS for AD replication](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/troubleshoot/verify-dns-functionality-to-support-directory-replication)
- [Windows Server DNS troubleshooting](https://learn.microsoft.com/troubleshoot/windows-server/networking/troubleshoot-dns-guidance)
- [Active Directory PowerShell module](https://learn.microsoft.com/powershell/module/activedirectory/)

## haf - Lubuntu 22 Wabbit - 192.168.220.67

### What it does

The packet names the service “Wabbit” but does not define the product. Do not
assume it is RabbitMQ or another similarly named application. Identify it from
the actual process, unit, package, listener, page title and configuration.

### First actions

```sh
systemctl --failed
systemctl list-units --type=service --state=running
ss -lntup
ps auxf
journalctl -p warning..alert --since '-30 minutes' --no-pager
dpkg-query -W 2>/dev/null | less
```

Run SH-05 and SV-01. For each application process record its executable,
package owner (`dpkg -S PATH`), unit, account, working directory, environment,
config, data, logs, database and callers. Once positively identified, use that
project's official documentation.

### Validate

Use the exact Quotient or Orange Team workflow. Save a screenshot/request and
expected response so another teammate can repeat it after each change.

### Official resources

- [Ubuntu Server documentation](https://ubuntu.com/server/docs/)
- [systemctl reference](https://www.freedesktop.org/software/systemd/man/latest/systemctl)
- [journalctl reference](https://www.freedesktop.org/software/systemd/man/latest/journalctl)

## kvigindis - Ubuntu 24.04 furniture help site - 192.168.220.44

### What it does

Kvigindis hosts the public furniture-help application. Expect a web server,
application runtime, content, authentication and possibly a remote database.

### First actions

Run SH-05, SV-01 and LX-31. Then inspect:

```sh
systemctl status nginx apache2 --no-pager 2>/dev/null
nginx -T 2>/dev/null
apache2ctl -S 2>/dev/null
ss -lntup
find /var/www /srv -maxdepth 3 -type f -name '.env' -o -name 'config*' 2>/dev/null
journalctl -u nginx -u apache2 --since '-30 minutes' --no-pager
```

Identify virtual host, web root, reverse proxy, application unit/container,
database, uploads, secrets file, TLS material, access/error logs and writable
paths. Preserve legitimate customer content before quarantining a suspicious
file.

### Validate

Load the correct hostname through the intended path, follow a help workflow,
authenticate if required, and confirm dynamic/database-backed content works.

### Official resources

- [Ubuntu web-server overview](https://ubuntu.com/server/docs/about-web-servers/)
- [NGINX administration guide](https://docs.nginx.com/nginx/admin-guide/)
- [Apache HTTP Server documentation](https://httpd.apache.org/docs/)

## skerja - Alpine employee/customer tickets - 192.168.220.97

### What it does

Skerja is the ticket application. It likely combines web, application and
database layers; the actual product is withheld.

### First actions

```sh
rc-status -a
rc-update show -v
ss -lntup 2>/dev/null || netstat -lntup
ps auxf
find /etc /var/www /srv /opt -maxdepth 3 -type f \( -name '*.conf' -o -name '.env' -o -name 'config*' \) 2>/dev/null
```

Run SH-05, SV-01, LX-31 and SV-14 if a database is discovered. Record web
server, application process, database, mail/notification dependency, file
attachments, session storage, users, logs and OpenRC scripts.

### Validate

Using an approved test identity, log in, create a ticket, view it, update it
and confirm its persistence. If email is part of the workflow, validate that
dependency separately.

### Official resources

- [Alpine Linux handbook](https://docs.alpinelinux.org/)
- [Alpine OpenRC service management](https://docs.alpinelinux.org/user-handbook/0.1a/Working/openrc.html)

After identifying the ticket product, use only its official administration
and backup documentation rather than applying generic web fixes blindly.

## thorska - Fedora 44 home manager - 192.168.220.231

### What it does

Thorska hosts the Home Manager application. Its product, runtime and database
are unknown until discovery.

### First actions

```sh
systemctl --failed
systemctl list-units --type=service --state=running
ss -lntup
ps auxf
firewall-cmd --list-all 2>/dev/null
getenforce 2>/dev/null
journalctl -p warning..alert --since '-30 minutes' --no-pager
rpm -qa --last | head -n 50
```

Run SH-05, SV-01 and LX-31. Identify application unit/container, reverse proxy,
database, config, data, logs, SELinux context and firewall service. Do not turn
off SELinux or firewalld simply to make an unexplained error disappear.

### Validate

Use the Home Manager workflow shown in Quotient: authenticate, read expected
data and make only an approved reversible test update.

### Official resources

- [Fedora system-administration documentation](https://docs.fedoraproject.org/en-US/fedora/latest/system-administrators-guide/)
- [Fedora firewalld documentation](https://docs.fedoraproject.org/en-US/quick-docs/firewalld/)
- [systemd manuals](https://www.freedesktop.org/software/systemd/man/latest/)

## djupi - Linux Mint 22.3 point of sale - 192.168.220.222

### What it does

Djupi hosts the point-of-sale application. It may rely on a local/remote
database, web service, AD, printers or other business integrations. Availability
and data integrity matter more than whether a single port is open.

### First actions

```sh
systemctl --failed
systemctl list-units --type=service --state=running
ss -lntup
ps auxf
journalctl -p warning..alert --since '-30 minutes' --no-pager
find /opt /srv /var/www -maxdepth 3 -type f \( -name '*.conf' -o -name '.env' -o -name 'config*' \) 2>/dev/null
```

Run SH-05, SV-01 and LX-31. Record the application process, autostart method,
user, display/session dependency, database, data files, integrations and logs.
Coordinate with Orange Team before manipulating customer or transaction data.

### Validate

Perform the exact approved POS workflow, including login, item lookup and a
reversible test transaction if permitted. Confirm the record reaches the
correct backend and the UI remains usable.

### Official resources

- [Linux Mint documentation](https://linuxmint.com/documentation.php)
- [Ubuntu Server documentation](https://ubuntu.com/server/docs/)
- [systemctl reference](https://www.freedesktop.org/software/systemd/man/latest/systemctl)

## When the product is unknown

Use evidence, not the hostname:

1. Map port to PID and executable.
2. Read the service unit/OpenRC script and process command line.
3. Identify the owning package without installing anything.
4. Locate config, environment, working directory, data and logs.
5. Inspect the HTTP title/headers or protocol banner from an approved source.
6. Search the binary's built-in `--help`, local man pages and package files.
7. Once identified, use the product's official version-matched documentation.

Do not install diagnostic packages during competition unless rules and the host
owner explicitly allow it. Preserve raw evidence before cleanup or repair.
