# sentinel-secutity-platform
Security detection system/
Initial Project Structure
from collections import Counter

ips = [
    "192.168.1.10",
    "185.44.21.91",
    "185.44.21.91",
    "192.168.1.10",
    "185.44.21.91",
    "10.0.0.5",
]

counts = Counter(ips)

print(counts)
for ip, count in counts.items():
    if count >= 3:
        print(f"Suspicious IP: {ip}")
sentinel-security-platform/
├── app/
├── data/
├── tests/
├── README.md
├── requirements.txt
└── .gitignore
