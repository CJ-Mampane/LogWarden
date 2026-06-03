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

    with open(file_name, "w") as file:

        for _ in range(number_of_events):

            current_time += timedelta(seconds=random.randint(20, 300))

            timestamp = current_time.strftime("%Y-%m-%d %H:%M:%S")

            event_type = random.choice(
                ["ssh", "web", "system"]
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

            else:

                file.write(
                    f"{timestamp} INFO systemd[1]: Started {random.choice(services)}.\n"
                )

    print(f"Generated {number_of_events} log events in '{file_name}'")


if __name__ == "__main__":

    create_logs("mock_server_log.txt", 50)