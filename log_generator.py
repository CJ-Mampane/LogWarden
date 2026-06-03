import random
from datetime import datetime, timedelta


def generate_ip():
    return (
        f"{random.randint(1, 255)}."
        f"{random.randint(0, 255)}."
        f"{random.randint(0, 255)}."
        f"{random.randint(1, 254)}"
    )


def create_logs(file_name, number_of_events):

    current_time = datetime.now() - timedelta(days=1)

    users = [
        "cathrene",
        "student01",
        "research_user",
        "faculty_admin"
    ]

    pages = [
        "/index.html",
        "/about.html",
        "/images/logo.png",
        "/api/status"
    ]

    services = [
        "Periodic Command Scheduler (cron)",
        "Daily System Backup Utility",
        "Security-Auditing Service"
    ]

    # used to simulate repeated attacker behavior
    failed_ips = []

    with open(file_name, "w") as file:

        for _ in range(number_of_events):

            current_time += timedelta(seconds=random.randint(20, 300))
            timestamp = current_time.strftime("%Y-%m-%d %H:%M:%S")

            event_type = random.choice(
                ["ssh", "web", "system", "failed_login", "bruteforce", "root_attempt"]
            )

            if event_type == "ssh":

                ip = generate_ip()
                user = random.choice(users)

                file.write(
                    f"{timestamp} INFO inbound-traffic IP {ip} connection established port 22\n"
                )

                file.write(
                    f"{timestamp} INFO sshd: Accepted password for {user} from {ip} port 22 ssh2\n"
                )

            elif event_type == "web":

                ip = generate_ip()

                file.write(
                    f"{timestamp} INFO web-server GET {random.choice(pages)} HTTP/1.1 200 OK from {ip}\n"
                )

            elif event_type == "system":

                file.write(
                    f"{timestamp} INFO systemd[1]: Started {random.choice(services)}.\n"
                )

            elif event_type == "failed_login":

                ip = generate_ip()
                user = random.choice(users)

                file.write(
                    f"{timestamp} WARN sshd: Failed password for {user} from {ip} port 22 ssh2\n"
                )

            elif event_type == "bruteforce":

                attacker_ip = generate_ip()
                target_user = "admin"

                for _ in range(random.randint(4, 7)):

                    current_time += timedelta(seconds=random.randint(1, 3))
                    burst_time = current_time.strftime("%Y-%m-%d %H:%M:%S")

                    file.write(
                        f"{burst_time} WARN sshd: Failed password for invalid user "
                        f"{target_user} from {attacker_ip} port 22 ssh2\n"
                    )

            elif event_type == "root_attempt":

                ip = generate_ip()

                file.write(
                    f"{timestamp} INFO inbound-traffic IP {ip} connection established port 22\n"
                )

                current_time += timedelta(seconds=2)
                crit_time = current_time.strftime("%Y-%m-%d %H:%M:%S")

                file.write(
                    f"{crit_time} CRIT sshd: Unauthorized su root attempt failed from {ip}\n"
                )

    print(f"Generated {number_of_events} log events in '{file_name}'")


if __name__ == "__main__":
    create_logs("mock_server_log.txt", 100)