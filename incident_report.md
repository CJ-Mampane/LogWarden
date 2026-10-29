# LogWarden INCIDENT REPORT

**Scan Date:** 2026-10-29 13:28:49

**Log File:** `mock_server_log.txt`

**Lines Read:** 160 (87 security events)

## SUMMARY

| Severity | Findings |
|---|---|
| Critical | 0 |
| High | 5 |
| Medium | 2 |
| Low | 0 |

## 1. Brute force attack (LW-1)

* **Severity:** high
* **MITRE ATT&CK:** T1110.001 Password Guessing
* **Time:** 2026-06-03 01:26:00 to 01:27:11
* **IP:** `203.0.113.45`
* **Accounts:** `admin`

30 failed logins from 203.0.113.45 within 5 minutes (30 failed logins in total).

Evidence from the log:

```text
line 3: Jun  3 01:26:00 lab-server sshd[15725]: Failed password for invalid user admin from 203.0.113.45 port 33965 ssh2
line 5: Jun  3 01:26:01 lab-server sshd[39555]: Failed password for invalid user admin from 203.0.113.45 port 41078 ssh2
line 7: Jun  3 01:26:03 lab-server sshd[1471]: Failed password for invalid user admin from 203.0.113.45 port 49282 ssh2
line 9: Jun  3 01:26:04 lab-server sshd[4858]: Failed password for invalid user admin from 203.0.113.45 port 53194 ssh2
line 11: Jun  3 01:26:06 lab-server sshd[3058]: Failed password for invalid user admin from 203.0.113.45 port 32208 ssh2
... and 25 more lines
```

## 2. Password spraying (LW-2)

* **Severity:** high
* **MITRE ATT&CK:** T1110.003 Password Spraying
* **Time:** 2026-06-03 02:40:00 to 02:49:41
* **IP:** `198.51.100.23`
* **Accounts:** `admin`, `ftpuser`, `guest`, `oracle`, `pi`, `postgres`, `test`, `ubuntu`

198.51.100.23 tried 8 different usernames within 10 minutes.

Evidence from the log:

```text
line 72: Jun  3 02:40:00 lab-server sshd[5490]: Failed password for invalid user admin from 198.51.100.23 port 57896 ssh2
line 74: Jun  3 02:41:24 lab-server sshd[57480]: Failed password for invalid user test from 198.51.100.23 port 32226 ssh2
line 76: Jun  3 02:42:45 lab-server sshd[62708]: Failed password for invalid user oracle from 198.51.100.23 port 43230 ssh2
line 78: Jun  3 02:44:09 lab-server sshd[39962]: Failed password for invalid user ubuntu from 198.51.100.23 port 38067 ssh2
line 80: Jun  3 02:45:29 lab-server sshd[28474]: Failed password for invalid user postgres from 198.51.100.23 port 50295 ssh2
... and 3 more lines
```

## 3. Login after many failed attempts (LW-3)

* **Severity:** high
* **MITRE ATT&CK:** T1078 Valid Accounts
* **Time:** 2026-06-03 04:12:05 to 04:12:19
* **IP:** `203.0.113.99`
* **Accounts:** `research_user`

research_user logged in from 203.0.113.99 after 7 failed attempts from the same IP. The password may have been guessed, check with the account owner.

Evidence from the log:

```text
line 98: Jun  3 04:12:05 lab-server sshd[36234]: Failed password for research_user from 203.0.113.99 port 32400 ssh2
line 99: Jun  3 04:12:07 lab-server sshd[18380]: Failed password for research_user from 203.0.113.99 port 46576 ssh2
line 100: Jun  3 04:12:09 lab-server sshd[58728]: Failed password for research_user from 203.0.113.99 port 41436 ssh2
line 101: Jun  3 04:12:10 lab-server sshd[17009]: Failed password for research_user from 203.0.113.99 port 58811 ssh2
line 102: Jun  3 04:12:19 lab-server sshd[19676]: Accepted password for research_user from 203.0.113.99 port 51515 ssh2
```

## 4. Risky command run with sudo (LW-6)

* **Severity:** high
* **MITRE ATT&CK:** T1548.003 Sudo and Sudo Caching
* **Time:** 2026-06-03 04:14:19 to 04:16:19
* **Accounts:** `research_user`

research_user ran 3 risky command(s) as root: /usr/bin/cat /etc/shadow; /usr/sbin/useradd -m -s /bin/bash backup-svc; /usr/bin/chmod 4755 /tmp/.helper

Evidence from the log:

```text
line 103: Jun  3 04:14:19 lab-server sudo:  research_user : TTY=pts/1 ; PWD=/home/research_user ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow
line 104: Jun  3 04:15:19 lab-server sudo:  research_user : TTY=pts/1 ; PWD=/home/research_user ; USER=root ; COMMAND=/usr/sbin/useradd -m -s /bin/bash backup-svc
line 105: Jun  3 04:16:19 lab-server sudo:  research_user : TTY=pts/1 ; PWD=/home/research_user ; USER=root ; COMMAND=/usr/bin/chmod 4755 /tmp/.helper
```

## 5. Direct root login (LW-4)

* **Severity:** high
* **MITRE ATT&CK:** T1078.003 Local Accounts
* **Time:** 2026-06-03 07:44:00 to 07:44:00
* **IP:** `192.0.2.200`
* **Accounts:** `root`

root logged in directly from 192.0.2.200 using password. It is safer to set PermitRootLogin to no.

Evidence from the log:

```text
line 144: Jun  3 07:44:00 lab-server sshd[41086]: Accepted password for root from 192.0.2.200 port 40022 ssh2
```

## 6. Brute force attack (LW-1)

* **Severity:** medium
* **MITRE ATT&CK:** T1110.001 Password Guessing
* **Time:** 2026-06-03 04:12:00 to 04:12:10
* **IP:** `203.0.113.99`
* **Accounts:** `research_user`

7 failed logins from 203.0.113.99 within 5 minutes (7 failed logins in total).

Evidence from the log:

```text
line 95: Jun  3 04:12:00 lab-server sshd[45019]: Failed password for research_user from 203.0.113.99 port 34288 ssh2
line 96: Jun  3 04:12:03 lab-server sshd[21720]: Failed password for research_user from 203.0.113.99 port 44982 ssh2
line 97: Jun  3 04:12:04 lab-server sshd[31034]: Failed password for research_user from 203.0.113.99 port 30305 ssh2
line 98: Jun  3 04:12:05 lab-server sshd[36234]: Failed password for research_user from 203.0.113.99 port 32400 ssh2
line 99: Jun  3 04:12:07 lab-server sshd[18380]: Failed password for research_user from 203.0.113.99 port 46576 ssh2
... and 2 more lines
```

## 7. Failed attempts to become root (LW-5)

* **Severity:** medium
* **MITRE ATT&CK:** T1548.003 Sudo and Sudo Caching
* **Time:** 2026-06-03 06:03:00 to 06:03:30
* **Accounts:** `student01`

student01 typed the wrong password 3 times using su within 10 minutes while trying to become root.

Evidence from the log:

```text
line 121: Jun  3 06:03:00 lab-server su[11338]: pam_unix(su:auth): authentication failure; logname=student01 uid=1001 euid=0 tty=/dev/pts/2 ruser=student01 rhost=  user=root
line 123: Jun  3 06:03:15 lab-server su[55640]: pam_unix(su:auth): authentication failure; logname=student01 uid=1001 euid=0 tty=/dev/pts/2 ruser=student01 rhost=  user=root
line 125: Jun  3 06:03:30 lab-server su[47107]: pam_unix(su:auth): authentication failure; logname=student01 uid=1001 euid=0 tty=/dev/pts/2 ruser=student01 rhost=  user=root
```

## WHAT TO DO NEXT

1. Check each high or critical finding with the owner of the account.
2. Block IPs that are confirmed as attackers, for example with fail2ban or a firewall.
3. Change the password of any account listed under LW-3.
4. Turn off password login and root login for SSH where possible.

Each finding comes from a fixed rule and can be checked against the evidence lines. A finding means something looks suspicious, not that an attack definitely happened.
