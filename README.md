# LogWarden: Automated SOC Log Analyzer

![Tests](https://github.com/CJ-Mampane/LogWarden/actions/workflows/tests.yml/badge.svg)

## Project Overview

In a modern Security Operations Centre (SOC), analysts deal with large volumes of daily log data that are difficult to review manually. LogWarden is a Python-based tool I built to automate basic log triage.

It reads Linux authentication logs (`/var/log/auth.log`), finds suspicious activity such as brute-force attacks, password spraying and attempts to become root, and writes an incident report. Every finding shows the exact log lines that caused it and is linked to a MITRE ATT&CK technique.

## Key skills demonstrated

- Security Operations: log parsing, threat detection, incident reporting, MITRE ATT&CK mapping
- Python: regular expressions, dates and time windows, dictionaries, command-line arguments
- Testing: 18 automated tests with pytest, run on GitHub Actions every time I push
- Simulation: generating realistic Linux logs with planted attacks to test the detections

## How it works

The project has two scripts.

**1. Generator (`log_generator.py`)**
Creates `mock_server_log.txt`, a fake Linux auth log with normal activity (people logging in, the odd password typo, routine sudo commands) and five planted attacks. It uses a fixed seed, so it makes the same file every time.

**2. Analyzer (`log_warden.py`)**
Reads the log line by line, picks out the security events (failed logins, successful logins, su and sudo use) and runs six checks on them:

| Check | What it looks for | Default limit | MITRE ATT&CK |
|---|---|---|---|
| LW-1 | Brute force | 5 or more failed logins from one IP within 5 minutes | T1110.001 |
| LW-2 | Password spraying | 4 or more different usernames from one IP within 10 minutes | T1110.003 |
| LW-3 | Login after failed attempts | A login that worked from an IP with 3 or more failures in the last hour | T1078 |
| LW-4 | Direct root login | Anyone logging in over SSH as root | T1078.003 |
| LW-5 | Failed attempts to become root | 3 or more wrong passwords for su or sudo by one user within 10 minutes | T1548.003 |
| LW-6 | Risky sudo commands | Things like reading `/etc/shadow`, adding users or opening a root shell | T1548.003 |

The limits are at the top of `log_warden.py` and are easy to change.

The results are written to `incident_report.md`, with the most serious findings first.

## How to Run Locally

1. Clone the repository:
   ```bash
   git clone https://github.com/CJ-Mampane/LogWarden.git
   cd LogWarden
   ```
2. Create a new mock log (optional, one is already included):
   ```bash
   python log_generator.py
   ```
3. Run the scan:
   ```bash
   python log_warden.py
   ```
4. Open `incident_report.md`.

To scan a different file: `python log_warden.py path/to/auth.log`

To run the tests: `pip install pytest` and then `pytest`

LogWarden only needs Python 3.10 or newer. It does not use any other libraries.

## Example result

On the included mock log, LogWarden finds all five planted attacks and nothing in the normal activity:

| Severity | Check | What it found |
|---|---|---|
| High | LW-1 | 30 failed logins for `admin` from `203.0.113.45` in about one minute |
| High | LW-2 | `198.51.100.23` slowly tried 8 usernames (admin, oracle, pi and others) |
| High | LW-3 | `research_user` logged in from `203.0.113.99` after 7 failed attempts |
| High | LW-6 | `research_user` then read `/etc/shadow`, added a user and set a SUID bit |
| High | LW-4 | Someone logged in directly as root |
| Medium | LW-1 | The 7 failed attempts before the LW-3 login |
| Medium | LW-5 | `student01` typed the wrong password 3 times trying to `su` to root |

## Project history

- **Version 1 (June 2026):** a simple script that counted failed logins per IP and flagged `su root` attempts in a made-up log format.
- **Version 2 (October 2026):** reads real Linux auth logs, uses time windows instead of total counts (5 typos over a week is not an attack, 5 failures in a minute is), adds four new checks, shows evidence for every finding, and has automated tests. The su root check from version 1 is now LW-5 and uses the real Linux log format.

## Things I learned

- SSH writes two lines for one attempt with a fake username (`Invalid user admin` and `Failed password for invalid user admin`). Counting both would double the numbers, so LogWarden only counts the second one. The same happens with failed su and sudo attempts.
- Real attackers often go slowly on purpose. The password spraying attack in the mock log tries one username every 80 seconds, which is too slow for the brute force check but is caught by LW-2.

## Limitations

- The limits are rules of thumb. A busy server needs different numbers than a small one.
- It only checks SSH, su and sudo lines for now.
- It scans a saved log file, it does not watch the server live.
- Older log lines have no year, so LogWarden uses the current year unless you pass `--year`.
- A report with no findings does not prove the server is safe.

## Next steps

- Add machine learning (Isolation Forest) to spot unusual login behaviour that the fixed rules miss, and show those results separately from the rule findings
- Measure how well the rules and the machine learning each do on labelled data

## Ethics

Only scan logs from systems you own or have permission to check. Real logs contain usernames and IP addresses, which are personal information under POPIA, so they should never be uploaded to GitHub. The mock log only uses IPs that are reserved for examples.
