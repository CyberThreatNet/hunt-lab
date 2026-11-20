# Linux auditd and shell hunt notes

These are questions and commands for operators, not a vendor schema. Facts and paths are from Kaspersky ICS CERT, 5 November 2026. Untested against a live hypervisor. MIT licence.

## What to look for

1. A file at `/etc/cron.hourly/pgcache` or `/etc/cron.hourly/1vmware-timesync`.
2. The published MD5 values, especially `346b04985ec6c5d107ba0ddf32fe7691` (pgcache) and `cb2908ef4cc042bfe856c84e9b61a2f9` (GSocket downloader).
3. Cron or curl activity involving `nofrillsdns.com`, including:
   - `lo1yaizaeghaevarooD1ahtaichootae.nofrillsdns.com`
   - `lo1yaizaeghaevarood1ahtaichootaz.nofrillsdns.com`
   - `vmware-timecheck-api.nofrillsdns.com`
4. A DNS answer of `127.0.0.1` for those names, which Kaspersky says is how the attackers parked the command-and-control record when the server was off.
5. A fetch of `hxxps://gsocket[.]io/y` (defanged), or a bash line that runs that installer.
6. A change to `/usr/bin/nxnode-login`, or a file at `/dev/shm/pulse-shm-3088612174`.
7. Root shells on a vCenter appliance that do not match a vCenter user session or an SSH login at the same time, especially a Java or Tomcat process spawning `bash`, `sh`, `nc`, `curl` or `wget`.

## Example auditd watches

These watches are starting points. They will also fire on legitimate package updates and administrator work.

```
-w /etc/cron.hourly -p wa -k bo_team_cron
-w /usr/bin/nxnode-login -p wa -k bo_team_nxnode
-w /dev/shm -p wa -k bo_team_shm
```

Search the audit log for those keys, and for `curl` or `wget` process arguments that contain `nofrillsdns` or `gsocket[.]io` (remove the brackets when you search).

## Example shell checks (read only)

```
ls -la /etc/cron.hourly/
md5sum /etc/cron.hourly/pgcache /etc/cron.hourly/1vmware-timesync 2>/dev/null
getent hosts lo1yaizaeghaevarooD1ahtaichootae.nofrillsdns.com vmware-timecheck-api.nofrillsdns.com
# A result of 127.0.0.1 is a parked-record lead, not proof of a live beacon.
test -e /dev/shm/pulse-shm-3088612174 && ls -la /dev/shm/pulse-shm-3088612174
```

Do not download or run GSocket, and do not use the published connection key, except in an isolated lab that you already control.
