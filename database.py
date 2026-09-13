"""
Sentinel Security Intelligence Platform
Database Layer

This file creates and manages the SQLite database
used by Sentinel.
"""

import sqlite3


DATABASE_NAME = "sentinel.db"


def create_database():
    """
    Create the Sentinel database and login_events table.
    """

    connection = sqlite3.connect(DATABASE_NAME)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time TEXT NOT NULL,
            username TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            event TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


def add_login_event(time, username, ip_address, event):
    """
    Add a login event to the database.
    """

    connection = sqlite3.connect(DATABASE_NAME)

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO login_events
        (time, username, ip_address, event)
        VALUES (?, ?, ?, ?)
    """, (
        time,
        username,
        ip_address,
        event
    ))

    connection.commit()
    connection.close()


def get_all_events():
    """
    Retrieve every login event from the database.
    """

    connection = sqlite3.connect(DATABASE_NAME)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            time,
            username,
            ip_address,
            event
        FROM login_events
        ORDER BY id
    """)

    events = cursor.fetchall()

    connection.close()

    return events


def get_failed_events():
    """
    Retrieve only failed login attempts.
    """

    connection = sqlite3.connect(DATABASE_NAME)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            time,
            username,
            ip_address,
            event
        FROM login_events
        WHERE event = 'FAILED'
        ORDER BY id
    """)

    events = cursor.fetchall()

    connection.close()

    return events


if __name__ == "__main__":

    print("Starting Sentinel database...")

    create_database()

    print("Database created successfully.")

    print()
    print("Adding sample security events...")

    add_login_event(
        "10:01",
        "alice",
        "192.168.1.10",
        "SUCCESS"
    )

    add_login_event(
        "10:02",
        "bob",
        "192.168.1.15",
        "SUCCESS"
    )

    add_login_event(
        "10:03",
        "admin",
        "185.44.21.91",
        "FAILED"
    )

    add_login_event(
        "10:03",
        "admin",
        "185.44.21.91",
        "FAILED"
    )

    add_login_event(
        "10:03",
        "admin",
        "185.44.21.91",
        "FAILED"
    )

    add_login_event(
        "10:03",
        "admin",
        "185.44.21.91",
        "FAILED"
    )

    add_login_event(
        "10:03",
        "admin",
        "185.44.21.91",
        "FAILED"
    )

    print("Sample events added.")

    print()
    print("Database contents:")
    print("-" * 60)

    events = get_all_events()

    for event in events:
        print(event)

    print("-" * 60)
    print("Sentinel database is ready.")
