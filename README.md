# Sentinel Security Intelligence Platform

Sentinel is a Python-based cybersecurity project that analyzes login activity and identifies potentially suspicious behavior.

## Project Goal

The goal of Sentinel is to demonstrate how software can analyze security events and turn raw login data into useful security alerts.

The current version detects repeated failed login attempts that could indicate a brute-force attack.

## Current Features

- Analyzes login activity
- Tracks successful and failed logins
- Tracks unique users
- Identifies suspicious IP addresses
- Counts failed login attempts
- Generates HIGH-risk security alerts
- Detects possible brute-force attacks

## How It Works

```text
        LOGIN EVENTS
             ↓
      ┌─────────────┐
      │   SENTINEL  │
      │   ANALYZER  │
      └──────┬──────┘
             ↓
      Analyze Activity
             ↓
      Count Failed Logins
             ↓
      Identify Suspicious IPs
             ↓
       SECURITY ALERT
Example:
If an IP address attempts to log in repeatedly:
185.44.21.91
185.44.21.91
185.44.21.91
185.44.21.91
185.44.21.91
Sentinel identifies the repeated activity and generates:
HIGH RISK ALERT

IP Address: 185.44.21.91
Failed Attempts: 8
Reason: Possible brute-force attack
Through this project I am developing experience with:
Python programming
Software architecture
Cybersecurity concepts
Data analysis
Algorithms
Databases
APIs
Testing
Git/GitHub
Cloud technologies
Sentinel is an educational cybersecurity project that uses synthetic data.
It is designed for defensive security learning and software development practice.

This project is actively being developed and improved.
