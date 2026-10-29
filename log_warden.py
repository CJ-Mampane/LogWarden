import argparse
import re
from datetime import datetime, timedelta

# Limits used by the detection rules. Change these to make LogWarden stricter or looser.
BRUTE_FORCE_LIMIT = 5          # failed logins from one IP...
BRUTE_FORCE_WINDOW = 300       # ...within this many seconds (5 minutes)
SPRAY_USER_LIMIT = 4           # different usernames tried from one IP...
SPRAY_WINDOW = 600             # ...within this many seconds (10 minutes)
LOGIN_AFTER_FAILS_LIMIT = 3    # failed logins before a login that worked...
LOGIN_AFTER_FAILS_WINDOW = 3600  # ...within this many seconds (1 hour)
ROOT_FAIL_LIMIT = 3            # wrong passwords for su or sudo by one user...
ROOT_FAIL_WINDOW = 600         # ...within this many seconds (10 minutes)

# Commands that are risky when someone runs them as root with sudo
RISKY_COMMANDS = [
    "/etc/shadow", "/etc/sudoers", "visudo", "useradd", "usermod", "passwd",
    "chmod 777", "chmod 4755", "chmod u+s", "chmod +s", "crontab", "authorized_keys",
]
ROOT_SHELLS = ["/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh"]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Every line in auth.log starts with a date, the server name and the program name.
# Older systems write "Jun  3 01:11:00", newer Ubuntu writes "2026-06-03T01:11:00.123456+02:00".
OLD_STYLE_LINE = re.compile(
    r"^(\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (\S+) ([\w\-()]+)(?:\[\d+\])?: (.*)$"
)
NEW_STYLE_LINE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\S* (\S+) ([\w\-()]+)(?:\[\d+\])?: (.*)$"
)


def read_date(date_text, year):
    if date_text[0].isdigit():
        return datetime.strptime(date_text, "%Y-%m-%dT%H:%M:%S")
    # The older style has no year so we add one. split and join removes the
    # extra space in dates like "Jun  3".
    return datetime.strptime(f"{year} {' '.join(date_text.split())}", "%Y %b %d %H:%M:%S")


def read_line(line, line_no, year):
    # Turns one log line into an event (a dictionary), or returns None if the
    # line is not something LogWarden looks at.
    match = OLD_STYLE_LINE.match(line) or NEW_STYLE_LINE.match(line)
    if not match:
        return None
    date_text, host, program, message = match.groups()

    event = {"time": read_date(date_text, year), "line_no": line_no, "text": line,
             "user": None, "ip": None, "method": None, "command": None}

    if program == "sshd":
        failed = re.match(r"Failed (\S+) for (invalid user )?(\S+) from (\S+)", message)
        if failed:
            event["type"] = "invalid_user" if failed.group(2) else "failed_login"
            event["method"], event["user"], event["ip"] = failed.group(1, 3, 4)
            return event

        accepted = re.match(r"Accepted (\S+) for (\S+) from (\S+)", message)
        if accepted:
            event["type"] = "login"
            event["method"], event["user"], event["ip"] = accepted.groups()
            return event

        # SSH also writes "Invalid user admin from ..." just before the
        # "Failed password for invalid user admin" line. It is the same attempt,
        # so we skip it to avoid counting it twice.
        return None

    if program in ("su", "sudo"):
        # A wrong password when someone tries to become root with su or sudo
        wrong_password = re.search(r"pam_unix\((su|sudo):auth\): authentication failure;.*ruser=(\S*)",
                                   message)
        if wrong_password:
            event["type"] = "root_password_fail"
            event["method"] = wrong_password.group(1)
            event["user"] = wrong_password.group(2) or None
            return event

        # A command someone ran with sudo. We skip the "3 incorrect password attempts"
        # summary line because each attempt already has its own pam_unix line above.
        command = re.match(r"\s*(\S+) : TTY=.*; COMMAND=(.*)$", message)
        if command and "incorrect password" not in message:
            event["type"] = "sudo_command"
            event["user"], event["command"] = command.group(1), command.group(2).strip()
            return event

    return None


def read_log(path, year=None):
    year = year or datetime.now().year
    events = []
    total_lines = 0
    with open(path, "r", encoding="utf-8", errors="replace") as file:
        for line_no, line in enumerate(file, start=1):
            line = line.strip()
            if not line:
                continue
            total_lines += 1
            event = read_line(line, line_no, year)
            if event:
                events.append(event)
    return events, total_lines


def group_by(events, key, types):
    # Puts events of the given types into groups, for example all failed logins per IP
    groups = {}
    for event in events:
        if event["type"] in types and event[key]:
            groups.setdefault(event[key], []).append(event)
    for group in groups.values():
        group.sort(key=lambda e: e["time"])
    return groups


def busiest_window(events, seconds):
    # Finds the busiest stretch of time, for example the most failed logins that
    # happened within any 5 minutes. Returns the events in that stretch.
    best = []
    start = 0
    for end in range(len(events)):
        while events[end]["time"] - events[start]["time"] > timedelta(seconds=seconds):
            start += 1
        if end - start + 1 > len(best):
            best = events[start:end + 1]
    return best


def make_finding(rule, title, severity, mitre, details, evidence, ip=None, users=None):
    return {"rule": rule, "title": title, "severity": severity, "mitre": mitre,
            "details": details, "ip": ip, "users": users or [], "evidence": evidence,
            "first": evidence[0]["time"], "last": evidence[-1]["time"]}


def check_brute_force(events):
    # LW-1: many failed logins from one IP in a short time
    findings = []
    for ip, fails in group_by(events, "ip", ["failed_login", "invalid_user"]).items():
        burst = busiest_window(fails, BRUTE_FORCE_WINDOW)
        if len(burst) < BRUTE_FORCE_LIMIT:
            continue
        severity = "high" if len(burst) >= BRUTE_FORCE_LIMIT * 4 else "medium"
        users = sorted({e["user"] for e in fails if e["user"]})
        details = (f"{len(burst)} failed logins from {ip} within {BRUTE_FORCE_WINDOW // 60} "
                   f"minutes ({len(fails)} failed logins in total).")
        findings.append(make_finding("LW-1", "Brute force attack", severity,
                                     "T1110.001 Password Guessing", details, burst, ip, users))
    return findings


def check_password_spraying(events):
    # LW-2: one IP trying many different usernames, like admin, test and ubuntu
    findings = []
    for ip, fails in group_by(events, "ip", ["failed_login", "invalid_user"]).items():
        best_users, best_events = set(), []
        start = 0
        for end in range(len(fails)):
            while fails[end]["time"] - fails[start]["time"] > timedelta(seconds=SPRAY_WINDOW):
                start += 1
            window = fails[start:end + 1]
            users = {e["user"] for e in window if e["user"]}
            if len(users) > len(best_users):
                best_users, best_events = users, window
        if len(best_users) < SPRAY_USER_LIMIT:
            continue
        severity = "high" if len(best_users) >= SPRAY_USER_LIMIT * 2 else "medium"
        details = f"{ip} tried {len(best_users)} different usernames within {SPRAY_WINDOW // 60} minutes."
        findings.append(make_finding("LW-2", "Password spraying", severity,
                                     "T1110.003 Password Spraying", details, best_events,
                                     ip, sorted(best_users)))
    return findings


def check_login_after_fails(events):
    # LW-3: a login that worked from an IP that had just failed several times.
    # This can mean the attacker guessed the password.
    findings = []
    fails_by_ip = group_by(events, "ip", ["failed_login", "invalid_user"])
    for login in [e for e in events if e["type"] == "login"]:
        earlier = [f for f in fails_by_ip.get(login["ip"], [])
                   if timedelta(0) <= login["time"] - f["time"] <= timedelta(seconds=LOGIN_AFTER_FAILS_WINDOW)]
        if len(earlier) < LOGIN_AFTER_FAILS_LIMIT:
            continue
        severity = "critical" if login["user"] == "root" else "high"
        details = (f"{login['user']} logged in from {login['ip']} after {len(earlier)} failed "
                   f"attempts from the same IP. The password may have been guessed, "
                   f"check with the account owner.")
        findings.append(make_finding("LW-3", "Login after many failed attempts", severity,
                                     "T1078 Valid Accounts", details, earlier[-4:] + [login],
                                     login["ip"], [login["user"]]))
    return findings


def check_root_login(events):
    # LW-4: someone logged in directly as root. Most servers should not allow this.
    findings = []
    for login in events:
        if login["type"] == "login" and login["user"] == "root":
            details = (f"root logged in directly from {login['ip']} using {login['method']}. "
                       f"It is safer to set PermitRootLogin to no.")
            findings.append(make_finding("LW-4", "Direct root login", "high",
                                         "T1078.003 Local Accounts", details, [login],
                                         login["ip"], ["root"]))
    return findings


def check_root_password_fails(events):
    # LW-5: a user typing the wrong password several times when trying to become
    # root with su or sudo. This was the "su root" check in the first version.
    findings = []
    for user, fails in group_by(events, "user", ["root_password_fail"]).items():
        burst = busiest_window(fails, ROOT_FAIL_WINDOW)
        if len(burst) < ROOT_FAIL_LIMIT:
            continue
        tools = " and ".join(sorted({e["method"] for e in burst}))
        details = (f"{user} typed the wrong password {len(burst)} times using {tools} "
                   f"within {ROOT_FAIL_WINDOW // 60} minutes while trying to become root.")
        findings.append(make_finding("LW-5", "Failed attempts to become root", "medium",
                                     "T1548.003 Sudo and Sudo Caching", details, burst,
                                     users=[user]))
    return findings


def is_risky(command):
    return command in ROOT_SHELLS or any(word in command for word in RISKY_COMMANDS)


def check_risky_sudo(events):
    # LW-6: risky commands run as root, like reading /etc/shadow or adding a new user
    findings = []
    for user, commands in group_by(events, "user", ["sudo_command"]).items():
        risky = [e for e in commands if is_risky(e["command"])]
        if not risky:
            continue
        details = f"{user} ran {len(risky)} risky command(s) as root: " + \
                  "; ".join(e["command"] for e in risky[:3])
        findings.append(make_finding("LW-6", "Risky command run with sudo", "high",
                                     "T1548.003 Sudo and Sudo Caching", details, risky,
                                     users=[user]))
    return findings


def run_checks(events):
    findings = []
    for check in [check_brute_force, check_password_spraying, check_login_after_fails,
                  check_root_login, check_root_password_fails, check_risky_sudo]:
        findings += check(events)
    # Most serious first, then oldest first
    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["first"]))
    return findings


def write_report(findings, log_path, total_lines, events, report_path):
    counts = {level: 0 for level in SEVERITY_ORDER}
    for finding in findings:
        counts[finding["severity"]] += 1

    lines = [
        "# LogWarden INCIDENT REPORT",
        "",
        f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        f"**Log File:** `{log_path}`",
        "",
        f"**Lines Read:** {total_lines} ({len(events)} security events)",
        "",
        "## SUMMARY",
        "",
        "| Severity | Findings |",
        "|---|---|",
    ]
    for level in SEVERITY_ORDER:
        lines.append(f"| {level.title()} | {counts[level]} |")
    lines.append("")

    if not findings:
        lines += ["No suspicious activity found. This does not prove the server is safe, "
                  "only that none of the checks matched.", ""]

    for number, f in enumerate(findings, start=1):
        lines += [
            f"## {number}. {f['title']} ({f['rule']})",
            "",
            f"* **Severity:** {f['severity']}",
            f"* **MITRE ATT&CK:** {f['mitre']}",
            f"* **Time:** {f['first']:%Y-%m-%d %H:%M:%S} to {f['last']:%H:%M:%S}",
        ]
        if f["ip"]:
            lines.append(f"* **IP:** `{f['ip']}`")
        if f["users"]:
            lines.append("* **Accounts:** " + ", ".join(f"`{u}`" for u in f["users"]))
        lines += ["", f["details"], "", "Evidence from the log:", "", "```text"]
        lines += [f"line {e['line_no']}: {e['text']}" for e in f["evidence"][:5]]
        if len(f["evidence"]) > 5:
            lines.append(f"... and {len(f['evidence']) - 5} more lines")
        lines += ["```", ""]

    lines += [
        "## WHAT TO DO NEXT",
        "",
        "1. Check each high or critical finding with the owner of the account.",
        "2. Block IPs that are confirmed as attackers, for example with fail2ban or a firewall.",
        "3. Change the password of any account listed under LW-3.",
        "4. Turn off password login and root login for SSH where possible.",
        "",
        "Each finding comes from a fixed rule and can be checked against the evidence lines. "
        "A finding means something looks suspicious, not that an attack definitely happened.",
        "",
    ]
    with open(report_path, "w", encoding="utf-8") as report:
        report.write("\n".join(lines))


def analyze_logs(log_path, report_path="incident_report.md", year=None):
    print("Initializing LogWarden security scan...")
    try:
        events, total_lines = read_log(log_path, year)
    except FileNotFoundError:
        print(f"Error: Could not find the log file at '{log_path}'. Please check the path.")
        return None

    findings = run_checks(events)

    print(f"\nRead {total_lines} lines and found {len(events)} security events.")
    if findings:
        for f in findings:
            print(f"{f['severity'].upper()}: {f['title']} ({f['rule']}) {f['ip'] or ', '.join(f['users'])}")
    else:
        print("No suspicious activity found.")

    write_report(findings, log_path, total_lines, events, report_path)
    print(f"\nIncident report saved to '{report_path}'.")
    return findings


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LogWarden: find suspicious activity in Linux auth logs.")
    parser.add_argument("log_file", nargs="?", default="mock_server_log.txt",
                        help="the log file to scan (default: mock_server_log.txt)")
    parser.add_argument("-o", "--output", default="incident_report.md",
                        help="where to save the report (default: incident_report.md)")
    parser.add_argument("--year", type=int,
                        help="year to use for log dates that have no year (default: this year)")
    args = parser.parse_args()
    analyze_logs(args.log_file, args.output, args.year)
