"""
SENTINEL
Security Log Intelligence Platform

A beginner-friendly cybersecurity project that analyzes
login activity and detects suspicious behavior.
"""

from collections import Counter


# ============================================================
# SAMPLE SECURITY LOGS
# ============================================================

logs = [
    {
        "time": "10:01",
        "user": "alice",
        "ip": "192.168.1.10",
        "event": "SUCCESS"
    },
    {
        "time": "10:02",
        "user": "bob",
        "ip": "192.168.1.15",
        "event": "SUCCESS"
    },
    {
        "time": "10:03",
        "user": "admin",
        "ip": "185.44.21.91",
        "event": "FAILED"
    },
    {
        "time": "10:03",
        "user": "admin",
        "ip": "185.44.21.91",
        "event": "FAILED"
    },
    {
        "time": "10:03",
        "user": "admin",
        "ip": "185.44.21.91",
        "event": "FAILED"
    },
    {
        "time": "10:03",
        "user": "admin",
        "ip": "185.44.21.91",
        "event": "FAILED"
    },
    {
        "time": "10:03",
        "user": "admin",
        "ip": "185.44.21.91",
        "event": "FAILED"
    },
    {
        "time": "10:04",
        "user": "charlie",
        "ip": "192.168.1.20",
        "event": "SUCCESS"
    },
    {
        "time": "10:05",
        "user": "admin",
        "ip": "185.44.21.91",
        "event": "FAILED"
    },
    {
        "time": "10:05",
        "user": "admin",
        "ip": "185.44.21.91",
        "event": "FAILED"
    },
    {
        "time": "10:05",
        "user": "admin",
        "ip": "185.44.21.91",
        "event": "FAILED"
    },
    {
        "time": "10:06",
        "user": "alice",
        "ip": "192.168.1.10",
        "event": "SUCCESS"
    }
]


# ============================================================
# SECURITY ANALYSIS
# ============================================================

def analyze_security(logs):

    successful_logins = 0
    failed_logins = 0

    failed_ips = []

    users = set()

    for log in logs:

        users.add(log["user"])

        if log["event"] == "SUCCESS":
            successful_logins += 1

        elif log["event"] == "FAILED":
            failed_logins += 1
            failed_ips.append(log["ip"])

    # Count failed attempts from each IP
    ip_counts = Counter(failed_ips)

    suspicious_ips = []

    # Five or more failures = suspicious
    for ip, count in ip_counts.items():

        if count >= 5:

            suspicious_ips.append(
                {
                    "ip": ip,
                    "attempts": count,
                    "severity": "HIGH",
                    "reason": "Possible brute-force attack"
                }
            )

    return {
        "total_logs": len(logs),
        "successful_logins": successful_logins,
        "failed_logins": failed_logins,
        "unique_users": len(users),
        "suspicious_ips": suspicious_ips
    }


# ============================================================
# SECURITY REPORT
# ============================================================

def display_report(results):

    print()
    print("=" * 60)
    print("              SENTINEL SECURITY")
    print("             INTELLIGENCE REPORT")
    print("=" * 60)

    print()

    print(f"Total Events:       {results['total_logs']}")
    print(f"Successful Logins:  {results['successful_logins']}")
    print(f"Failed Logins:      {results['failed_logins']}")
    print(f"Unique Users:       {results['unique_users']}")

    print()
    print("-" * 60)
    print("SECURITY ALERTS")
    print("-" * 60)

    if len(results["suspicious_ips"]) == 0:

        print("No suspicious activity detected.")

    else:

        for alert in results["suspicious_ips"]:

            print()
            print("🚨 HIGH RISK ALERT")
            print(f"IP Address: {alert['ip']}")
            print(f"Failed Attempts: {alert['attempts']}")
            print(f"Reason: {alert['reason']}")

    print()
    print("=" * 60)


# ============================================================
# MAIN PROGRAM
# ============================================================

def main():

    print()
    print("Starting Sentinel Security Analysis...")

    results = analyze_security(logs)

    display_report(results)


if __name__ == "__main__":
    main()
