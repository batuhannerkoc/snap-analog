import re
from collections import Counter
from datetime import datetime
import json

log_pattern = re.compile(
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"  # IP address
    + r"(?P<identd>\S+)\s+"  # Identd (genellikle -)
    + r"(?P<authuser>\S+)\s+"  # Authuser (genellikle -)
    + r"\[(?P<timestamp>[^\]]+)\]\s+"  # Timestamp [07/Dec/2025:10:15:32 +0000]
    + r'"(?P<request>[^"]+)"\s+'  # Request line "GET /index.html HTTP/1.1"
    + r"(?P<status>\d{3})\s+"  # Status code 200
    + r"(?P<size>\S+)"  # Response size
)


def analyze_log(filepath):

    total_requests = 0
    sizes = []
    failed_attempt = Counter()
    ips = Counter()
    statuses = Counter()
    status_groups = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0}
    minutes = Counter()
    urls = Counter()
    methods = Counter()

    def update_counter(counter, key):
        counter[key] += 1

    def parse_minute(timestamp_str):
        timestamp_datetime = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
        return timestamp_datetime.strftime("%Y-%m-%d %H:%M")

    try:
        with open(filepath, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                try:
                    match = log_pattern.match(line)

                    if match:
                        # matching is succesful

                        total_requests += 1

                        size = match.group("size")
                        if size.isdigit():
                            sizes.append(int(size))
                        ip = match.group("ip")
                        update_counter(ips, ip)

                        status = match.group("status")
                        group = f"{status[0]}xx"
                        status_groups[group] += 1

                        update_counter(statuses, status)

                        timestamp = match.group("timestamp")
                        minute = parse_minute(timestamp)
                        update_counter(minutes, minute)

                        method = match.group("request").split()[0]
                        methods[method] += 1

                        url = match.group("request")
                        update_counter(urls, url)

                    else:
                        update_counter(failed_attempt, line)

                except Exception as e:
                    print("Failed Parsing: ", line, "Error: ", e)
                    update_counter(failed_attempt, line)

    except FileNotFoundError:
        print("cant find the file")

    stats = {
        "total_requests": total_requests,
        "size_stats": {
            "min": min(sizes),
            "max": max(sizes),
            "avg": sum(sizes) // len(sizes),
            "total": sum(sizes),
        },
        "top_ips": ips.most_common(5),
        "status_distribution": dict(statuses),
        "status_groups": status_groups,
        "top_minutes": minutes.most_common(5),
        "methods": dict(methods),
        "top_urls": urls.most_common(5),
        "failed_attempts": dict(failed_attempt),
    }
    return stats


with open("report.json", "w", encoding="utf-8") as f:
    json.dump(analyze_log("../sample_logs/sample.log"), f, indent=4)
