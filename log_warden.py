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

        print("\nMission complete. All logs have been inspected.")

    except FileNotFoundError:
        print(f"Error: Could not find the log file at '{log_file_path}'. Please check the path.")


# Run the monitor
if __name__ == "__main__":
    # And point it to the file created, the one with logs
    analyze_logs("mock_server_log.txt")