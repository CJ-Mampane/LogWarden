from datetime import datetime

def analyze_logs(log_file_path):
    print("Initializing LogWarden security scan...")

    # Trackers
    failed_login_counts = {}
    critical_alerts = []

    try:
        # Open and read the log file
        with open(log_file_path, 'r') as file:
            for line in file:
                # Remove extra spaces and newline characters
                clean_line = line.strip()

                # Check for failed password attempts
                if "Failed password" in clean_line:
                    # Extract the IP address manually.
                    # In logs, the IP comes right after the word "from"
                    parts = clean_line.split(" ")
                    if "from" in parts:
                        from_index = parts.index("from")
                        ip_address = parts[from_index + 1]

                        # Count failed attempts for this specific IP
                        failed_login_counts[ip_address] = failed_login_counts.get(ip_address, 0) + 1

                # Check for critical alerts
                elif "CRIT" in clean_line or "Unauthorized su root" in clean_line:
                    critical_alerts.append(clean_line)

        # Show results
        print("\nSECURITY ANALYSIS REPORT")

        # Flag brute force suspicion
        print("\n!!! Checking for brute force attacks")
        brute_force_detected = False
        for ip, count in failed_login_counts.items():
            if count > 3:
                print(f"ALERT: Suspicious activity from IP [{ip}]")
                print(f"Total failures: {count}")
                brute_force_detected = True
        if not brute_force_detected:
            print("No brute force patterns detected.")

        # Flag critical system alerts
        print("\n!!! Checking critical alerts")
        if critical_alerts:
            for alert in critical_alerts:
                print(f"CRITICAL: {alert}")
        else:
            print("No critical infrastructure alerts found.")


        report_path = "incident_report.md"
        print(f"\nSaving incident report to '{report_path}'...")

        try:
            with open(report_path, "w") as report:

                # Upgraded Header with Emojis and Timestamp
                report.write("# LogWarden INCIDENT REPORT\n\n")
                report.write(f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

                report.write("## SUMMARY\n\n")
                report.write("Automated scan of system logs completed. "
                             "Below are the detected anomalies and flagged activities.\n\n")

                # Brute force section upgraded with bullet points and code formatting (`ip`)
                report.write("## BRUTE FORCE DETECTION\n\n")

                bf_found = False

                for ip, count in failed_login_counts.items():
                    if count > 3:
                        report.write(f"* **Suspicious IP:** `{ip}`\n")
                        report.write(f"* **Failed attempts:** `{count}`\n")
                        report.write(f"* **Status:** Flagged for possible brute force activity\n\n")
                        bf_found = True

                if not bf_found:
                    report.write("> *No brute force patterns detected in this scan.*\n\n")

                # Critical alerts section upgraded with code blocks
                report.write("## CRITICAL EVENTS\n\n")

                if critical_alerts:
                    for alert in critical_alerts:
                        report.write(f"```text\n{alert}\n```\n\n")
                else:
                    report.write("> *No critical system alerts found.*\n\n")

                report.write("---\n")
                report.write("*LogWarden scan complete.*\n")

        except Exception as e:
            print(f"Error while writing report: {e}")

        print("\nScan finished. Report generated successfully.")

    except FileNotFoundError:
        print(f"Error: Could not find the log file at '{log_file_path}'. Please check the path.")

# Run the monitor
if __name__ == "__main__":
    # And point it to the file created, the one with logs
    analyze_logs("mock_server_log.txt")