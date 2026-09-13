"""
SENTINEL
Security Intelligence Platform

Sentinel reads login events from a SQLite database
and detects suspicious authentication activity.
"""

import sqlite3
from collections import Counter


# ============================================================
# CONFIGURATION
# ============================================================

DATABASE_NAME = "sentinel.db"

# Number of failed attempts required to trigger an alert
FAILED_LOGIN_THRESHOLD = 5


# ============================================================
# DATABASE FUNCTIONS
# ============================================================

def get_events():
    """
    Retrieve all login events from the Sentinel database.
    """

    connection = sqlite3.connect(DATABASE_NAME)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT time, username, ip_address, event
        FROM login_events
    """)

    events = cursor.fetchall()

    connection.close()

    return events


# ============================================================
# SECURITY ANALYSIS
# ============================================================

def analyze_events(events):
    """
    Analyze login events and identify suspicious activity.
    """

    total_events = len(events)

    successful_logins = 0
    failed_logins = 0

    failed_ips = []

    users = set()

    # Examine every event
    for event in events:

        time = event[0]
        username = event[1]
        ip_address = event[2]
        event_type = event[3]

        # Keep track of unique users
        users.add(username)

        if event_type == "SUCCESS":

            successful_logins += 1

        elif event_type == "FAILED":

            failed_logins += 1

            failed_ips.append(ip_address)

    # Count failed attempts for each IP
    ip_counts = Counter(failed_ips)

    suspicious_ips = []

    # Check each IP against our security threshold
    for ip, count in ip_counts.items():

        if count >= FAILED_LOGIN_THRESHOLD:

            suspicious_ips.append(
                {
                    "ip": ip,
                    "attempts": count,
                    "severity": "HIGH",
                    "reason": "Possible brute-force attack"
                }
            )

    return {
        "total_events": total_events,
        "successful_logins": successful_logins,
        "failed_logins": failed_logins,
        "unique_users": len(users),
        "suspicious_ips": suspicious_ips
    }


# ============================================================
# SECURITY REPORT
# ============================================================

def display_report(results):
    """
    Display the Sentinel security report.
    """

    print()

    print("=" * 60)
    print("              SENTINEL")
    print("        SECURITY INTELLIGENCE REPORT")
    print("=" * 60)

    print()

    print(
        f"Total Events:       "
        f"{results['total_events']}"
    )

    print(
        f"Successful Logins:  "
        f"{results['successful_logins']}"
    )

    print(
        f"Failed Logins:      "
        f"{results['failed_logins']}"
    )

    print(
        f"Unique Users:       "
        f"{results['unique_users']}"
    )

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

            print(
                f"IP Address: "
                f"{alert['ip']}"
            )

            print(
                f"Failed Attempts: "
                f"{alert['attempts']}"
            )

            print(
                f"Severity: "
                f"{alert['severity']}"
            )

            print(
                f"Reason: "
                f"{alert['reason']}"
            )

    print()

    print("=" * 60)


# ============================================================
# MAIN PROGRAM
# ============================================================

def main():

    print()
    print("Connecting to Sentinel database...")

    try:

        events = get_events()

        print(
            f"Loaded {len(events)} "
            f"security events."
        )

        print("Analyzing activity...")

        results = analyze_events(events)

        display_report(results)

    except sqlite3.OperationalError:

        print()
        print("ERROR")
        print("-" * 60)
        print("Sentinel could not find the database.")
        print()
        print("Run database.py first:")
        print()
        print("python3 database.py")
        print("-" * 60)


# ============================================================
# START SENTINEL
# ============================================================

if __name__ == "__main__":
    main()
