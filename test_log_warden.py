# Tests for LogWarden. Run them with: pytest

from datetime import datetime

import log_generator
from log_warden import analyze_logs, read_line, run_checks


def make_events(lines):
    events = []
    for number, line in enumerate(lines, start=1):
        event = read_line(line, number, 2026)
        if event:
            events.append(event)
    return events


def failed(second, ip="203.0.113.5", user="root"):
    # A fake failed login, the given number of seconds after 10:00
    minutes, seconds = divmod(second, 60)
    return f"Jun  3 10:{minutes:02d}:{seconds:02d} srv sshd[1]: Failed password for {user} from {ip} port 4000 ssh2"


def login(second, ip="203.0.113.5", user="root"):
    minutes, seconds = divmod(second, 60)
    return f"Jun  3 10:{minutes:02d}:{seconds:02d} srv sshd[1]: Accepted password for {user} from {ip} port 4000 ssh2"


def sudo(user, command):
    return f"Jun  3 13:00:00 srv sudo: {user} : TTY=pts/1 ; PWD=/home/{user} ; USER=root ; COMMAND={command}"


def rules_found(lines):
    return sorted(f["rule"] for f in run_checks(make_events(lines)))


# Reading log lines

def test_reads_failed_login():
    event = read_line(failed(0), 1, 2026)
    assert event["type"] == "failed_login"
    assert event["user"] == "root"
    assert event["ip"] == "203.0.113.5"
    assert event["time"] == datetime(2026, 6, 3, 10, 0, 0)


def test_reads_new_ubuntu_date_style():
    line = ("2026-06-03T10:05:00.123456+02:00 srv sshd[42]: Failed password for root "
            "from 203.0.113.45 port 4000 ssh2")
    assert read_line(line, 1, 2026)["time"] == datetime(2026, 6, 3, 10, 5, 0)


def test_invalid_user_line_is_not_counted_twice():
    assert read_line("Jun  3 10:00:00 srv sshd[1]: Invalid user admin from 1.2.3.4 port 22", 1, 2026) is None


def test_reads_sudo_command():
    event = read_line(sudo("eve", "/usr/bin/cat /etc/shadow"), 1, 2026)
    assert event["type"] == "sudo_command"
    assert event["command"] == "/usr/bin/cat /etc/shadow"


def test_ignores_lines_that_are_not_logs():
    assert read_line("hello world", 1, 2026) is None


# LW-1 brute force

def test_brute_force_found():
    assert rules_found([failed(s * 10) for s in range(5)]) == ["LW-1"]


def test_four_fails_is_not_brute_force():
    assert rules_found([failed(s) for s in range(4)]) == []


def test_fails_spread_out_over_time_are_not_brute_force():
    # 5 failures, one every 5 minutes
    assert rules_found([failed(s * 300) for s in range(5)]) == []


# LW-2 password spraying

def test_password_spraying_found():
    lines = [failed(s * 90, user=name) for s, name in enumerate(["admin", "test", "oracle", "pi"])]
    assert rules_found(lines) == ["LW-2"]


# LW-3 login after failed attempts

def test_login_after_fails_found():
    lines = [failed(s, user="deploy") for s in range(3)] + [login(10, user="deploy")]
    assert rules_found(lines) == ["LW-3"]


def test_one_typo_then_login_is_normal():
    assert rules_found([failed(0, user="cathrene"), login(5, user="cathrene")]) == []


def test_login_from_a_different_ip_is_normal():
    lines = [failed(s, user="deploy") for s in range(3)] + [login(10, ip="192.0.2.10", user="deploy")]
    assert rules_found(lines) == []


# LW-4 root login

def test_root_login_found():
    assert rules_found([login(0)]) == ["LW-4"]


# LW-5 failed attempts to become root

def test_failed_su_to_root_found_and_not_counted_twice():
    lines = []
    for s in range(3):
        lines.append(f"Jun  3 10:00:0{s} srv su[9]: pam_unix(su:auth): authentication failure; "
                     f"logname=student01 uid=1001 euid=0 tty=/dev/pts/2 ruser=student01 rhost=  user=root")
        lines.append(f"Jun  3 10:00:0{s} srv su[9]: FAILED SU (to root) student01 on pts/2")
    findings = run_checks(make_events(lines))
    assert [f["rule"] for f in findings] == ["LW-5"]
    assert len(findings[0]["evidence"]) == 3


# LW-6 risky sudo commands

def test_risky_sudo_found():
    assert rules_found([sudo("eve", "/usr/sbin/useradd backdoor")]) == ["LW-6"]


def test_normal_sudo_is_ignored():
    assert rules_found([sudo("bob", "/usr/bin/apt update"), sudo("bob", "/usr/bin/chmod 644 file")]) == []


# The full mock log: every planted attack is found and nothing else

def test_mock_log_end_to_end(tmp_path):
    log_file = tmp_path / "mock.log"
    report_file = tmp_path / "report.md"
    log_generator.create_logs(str(log_file))

    findings = analyze_logs(str(log_file), str(report_file), year=2026)
    found = sorted((f["rule"], f["ip"] or f["users"][0]) for f in findings)
    assert found == [
        ("LW-1", "203.0.113.45"),    # attack 1: brute force
        ("LW-1", "203.0.113.99"),    # attack 3: brute force...
        ("LW-2", "198.51.100.23"),   # attack 2: password spraying
        ("LW-3", "203.0.113.99"),    # attack 3: ...that worked
        ("LW-4", "192.0.2.200"),     # attack 5: root login
        ("LW-5", "student01"),       # attack 4: su to root
        ("LW-6", "research_user"),   # attack 3: risky sudo commands
    ]
    assert report_file.read_text(encoding="utf-8").startswith("# LogWarden INCIDENT REPORT")


def test_missing_file_does_not_crash(tmp_path):
    assert analyze_logs(str(tmp_path / "missing.log"), str(tmp_path / "r.md")) is None
