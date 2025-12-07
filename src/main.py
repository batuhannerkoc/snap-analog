import re
from collections import Counter
from datetime import datetime

log_pattern = re.compile(
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"  # IP address
    + r"(?P<identd>\S+)\s+"  # Identd (genellikle -)
    + r"(?P<authuser>\S+)\s+"  # Authuser (genellikle -)
    + r"\[(?P<timestamp>[^\]]+)\]\s+"  # Timestamp [07/Dec/2025:10:15:32 +0000]
    + r'"(?P<request>[^"]+)"\s+'  # Request line "GET /index.html HTTP/1.1"
    + r"(?P<status>\d{3})\s+"  # Status code 200
    + r"(?P<size>\S+)"  # Response size
)


totalRequests = 0
totalSize = 0
failedAttempts = Counter()
ips = Counter()
statues = Counter()
minutes = Counter()
urls = Counter()

try:

    with open("../sample_logs/sample.log", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            match = log_pattern.match(line)
            try:
                if match:
                    # matching is succesful

                    totalRequests += 1

                    size = match.group("size")
                    if size.isdigit():
                        totalSize += int(size)

                    ip = match.group("ip")
                    ips[ip] += 1

                    status = match.group("status")
                    statues[status] += 1

                    timestamp = match.group("timestamp")
                    timestamp_datetime = datetime.strptime(
                        timestamp, "%d/%b/%Y:%H:%M:%S %z"
                    )
                    minute_str = timestamp_datetime.strftime("%Y-%m-%d %H:%M")
                    minutes[minute_str] += 1

                    url = match.group("request")
                    urls[url] += 1

                else:
                    failedAttempts[line] += 1
            except AttributeError:
                print("log_pattern error")

except FileNotFoundError:
    print("cant find the file")

print("\nTotal Request Amount: ")
print(totalRequests)

print("\nTotal Size: ")
print(totalSize)

print("\nTop 5 IP adresses:")
for ip, cnt in ips.most_common(5):
    print(f"{ip}: {cnt}")

print("\nStatus Code Spread: ")
for status, cnt in statues.items():
    print(f"{status}: {cnt}")

print("\nTop 5 Busiest Minutes: ")
for minute, cnt in minutes.most_common(5):
    print(f"{minute}: {cnt}")

print("\nTop 5 URLs that got requested: ")
for url, cnt in urls.most_common(5):
    print(f"{url}: {cnt}")

print("\nFailed Attempts:")
for attempt, cnt in failedAttempts.items():
    print(f"{attempt}: {cnt}")
