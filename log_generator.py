import random
from datetime import datetime, timedelta

# Creates a mock Linux auth.log with normal activity and five planted attacks,
# so LogWarden can be tested without touching a real server.
#
# All IPs come from ranges that are reserved for examples (192.0.2.x, 198.51.100.x
# and 203.0.113.x), so none of them belong to a real computer.

SERVER = "lab-server"
USERS = ["cathrene", "student01", "research_user", "faculty_admin"]
OFFICE_IPS = ["192.0.2.10", "192.0.2.11", "192.0.2.12"]
ROUTINE_COMMANDS = ["/usr/bin/apt update", "/usr/bin/systemctl status nginx",
                    "/usr/bin/tail /var/log/syslog"]

log_lines = []


def add_line(time, program, message):
    # Writes the time the same way Linux does, for example "Jun  3 01:11:00"
    stamp = f"{time:%b} {time.day:>2} {time:%H:%M:%S}"
    if program == "sudo":
        log_lines.append((time, f"{stamp} {SERVER} sudo: {message}"))
    else:
        log_lines.append((time, f"{stamp} {SERVER} {program}[{random.randint(1000, 65000)}]: {message}"))


def normal_activity(start, hours):
    # People logging in with SSH keys, the odd password typo, and normal sudo use
    for _ in range(hours * 3):
        time = start + timedelta(seconds=random.randint(0, hours * 3600))
        user = random.choice(USERS)
        ip = random.choice(OFFICE_IPS)
        port = random.randint(40000, 60000)

        if random.random() < 0.15:
            # someone typed their password wrong once before logging in
            add_line(time, "sshd", f"Failed password for {user} from {ip} port {port} ssh2")
            time += timedelta(seconds=random.randint(4, 12))

        add_line(time, "sshd", f"Accepted publickey for {user} from {ip} port {port} ssh2")
        add_line(time, "sshd", f"pam_unix(sshd:session): session opened for user {user}(uid=1000) by (uid=0)")

        if random.random() < 0.3:
            add_line(time + timedelta(seconds=40), "sudo",
                     f" {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; "
                     f"COMMAND={random.choice(ROUTINE_COMMANDS)}")

    # scheduled jobs that run every hour
    for hour in range(hours):
        add_line(start + timedelta(hours=hour, minutes=17), "CRON",
                 "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)")


def brute_force(time, ip, user, attempts, invalid=False):
    who = f"invalid user {user}" if invalid else user
    for _ in range(attempts):
        port = random.randint(30000, 60000)
        if invalid:
            add_line(time, "sshd", f"Invalid user {user} from {ip} port {port}")
        add_line(time, "sshd", f"Failed password for {who} from {ip} port {port} ssh2")
        time += timedelta(seconds=random.randint(1, 4))
    return time


def password_spray(time, ip, usernames):
    # Attackers try one password on many usernames and go slowly to avoid being blocked
    for user in usernames:
        port = random.randint(30000, 60000)
        add_line(time, "sshd", f"Invalid user {user} from {ip} port {port}")
        add_line(time, "sshd", f"Failed password for invalid user {user} from {ip} port {port} ssh2")
        time += timedelta(seconds=random.randint(80, 85))


def create_logs(file_name, seed=42):
    random.seed(seed)  # the same seed always gives the same log file
    log_lines.clear()
    start = datetime(2026, 6, 3, 1, 0, 0)

    normal_activity(start, hours=8)

    # Attack 1: brute force on a username that doesn't exist
    brute_force(start + timedelta(minutes=26), "203.0.113.45", "admin", 30, invalid=True)

    # Attack 2: password spraying with common usernames
    password_spray(start + timedelta(hours=1, minutes=40), "198.51.100.23",
                   ["admin", "test", "oracle", "ubuntu", "postgres", "guest", "pi", "ftpuser"])

    # Attack 3: brute force that works, followed by risky sudo commands
    time = brute_force(start + timedelta(hours=3, minutes=12), "203.0.113.99", "research_user", 7)
    time += timedelta(seconds=6)
    add_line(time, "sshd", "Accepted password for research_user from 203.0.113.99 port 51515 ssh2")
    for minutes, command in [(2, "/usr/bin/cat /etc/shadow"),
                             (3, "/usr/sbin/useradd -m -s /bin/bash backup-svc"),
                             (4, "/usr/bin/chmod 4755 /tmp/.helper")]:
        add_line(time + timedelta(minutes=minutes), "sudo",
                 f" research_user : TTY=pts/1 ; PWD=/home/research_user ; USER=root ; COMMAND={command}")

    # Attack 4: a user trying to become root with su and the wrong password
    time = start + timedelta(hours=5, minutes=3)
    for attempt in range(3):
        attempt_time = time + timedelta(seconds=15 * attempt)
        add_line(attempt_time, "su",
                 "pam_unix(su:auth): authentication failure; logname=student01 uid=1001 "
                 "euid=0 tty=/dev/pts/2 ruser=student01 rhost=  user=root")
        add_line(attempt_time, "su", "FAILED SU (to root) student01 on pts/2")

    # Attack 5: someone logging in directly as root
    add_line(start + timedelta(hours=6, minutes=44), "sshd",
             "Accepted password for root from 192.0.2.200 port 40022 ssh2")

    log_lines.sort(key=lambda item: item[0])
    with open(file_name, "w", encoding="utf-8", newline="\n") as file:
        for _, line in log_lines:
            file.write(line + "\n")

    print(f"Generated {len(log_lines)} log lines in '{file_name}'")


if __name__ == "__main__":
    create_logs("mock_server_log.txt")
