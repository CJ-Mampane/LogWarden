# LogWarden: Automated SOC Log Analyzer

## Project Overview

In a modern Security Operations Centre (SOC), analysts deal with large volumes of daily log data that are difficult to review manually. LogWarden is a Python-based tool I built to automate basic log triage.

It reads Linux authentication logs, identifies suspicious patterns such as brute-force login attempts, detects possible privilege escalation activity, and generates an incident report for review.

---

## Key skills demonstrated

- Security Operations: log parsing, brute-force detection, incident reporting  
- Python Scripting: file handling, string processing, dictionaries  
- Threat Detection: identifying repeated failed logins and unauthorized `su root` attempts  

---

## How it works

The program reads a server log file line by line and applies simple rule-based checks.

- Failed login attempts are tracked per IP address  
- If an IP exceeds 3 failed attempts, it is flagged as a possible brute-force attack  
- Critical log entries such as `su root` attempts are also flagged  

The output is written into an automatically generated `incident_report.md` file for review.

---

## How to Run Locally

1. Clone the repository:
   ```bash
   git clone https://github.com/CJ-Mampane/LogWarden.git
