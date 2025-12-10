import re
from collections import Counter
from datetime import datetime
import json

log_pattern = re.compile(
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"  # IP
    r"(?P<identd>\S+)\s+"  # identd
    r"(?P<authuser>\S+)\s+"  # authuser
    r"\[(?P<timestamp>[^\]]+)\]\s+"  # timestamp
    r'"(?P<request>[^"]*)"\s+'  # request (can be empty)
    r"(?P<status>\d{3})"  # status
    r"(?:\s+(?P<size>\S+))?"  # optional size
    r"\s*$"  # end of line
)


def update_counter(counter, key):
    counter[key] += 1


def parse_minute(timestamp_str):
    try:
        timestamp_datetime = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
        return timestamp_datetime.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return "UNKNOWN"


def analyze_log(filepath):
    total_requests = 0
    sizes = []
    failed_attempt = Counter()
    ips = Counter()
    statuses = Counter()
    status_groups = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "Unknown": 0}
    minutes = Counter()
    urls = Counter()
    methods = Counter()

    try:
        with open(filepath, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                try:
                    match = log_pattern.match(line)

                    if match:
                        total_requests += 1

                        # Size parse
                        size = match.group("size")
                        if size and size.isdigit():
                            sizes.append(int(size))

                        # IP
                        ip = match.group("ip")
                        update_counter(ips, ip)

                        # Status
                        status = match.group("status")
                        group = (
                            f"{status[0]}xx"
                            if status and len(status) == 3
                            else "Unknown"
                        )
                        status_groups[group] += 1
                        update_counter(statuses, status)

                        # Timestamp
                        timestamp = match.group("timestamp")
                        minute = parse_minute(timestamp)
                        update_counter(minutes, minute)

                        # Request / Method
                        request_raw = match.group("request")
                        request_parts = request_raw.split() if request_raw else []
                        method = (
                            request_parts[0]
                            if request_parts and request_parts[0] != "-"
                            else "UNKNOWN"
                        )
                        methods[method] += 1

                        # URL
                        url = (
                            request_raw
                            if request_raw and request_raw != "-"
                            else "UNKNOWN"
                        )
                        update_counter(urls, url)

                    else:
                        update_counter(failed_attempt, line)

                except Exception as e:
                    print("Failed Parsing:", line, "Error:", e)
                    update_counter(failed_attempt, line)

    except FileNotFoundError:
        print("Cannot find the file:", filepath)

    # Size stats
    if sizes:
        sizes_min = min(sizes)
        sizes_max = max(sizes)
        sizes_avg = sum(sizes) // len(sizes)
        sizes_total = sum(sizes)
    else:
        sizes_min = sizes_max = sizes_avg = sizes_total = None

    # Stats dict
    stats = {
        "total_requests": total_requests,
        "size_stats": {
            "min": sizes_min,
            "max": sizes_max,
            "avg": sizes_avg,
            "total": sizes_total,
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


# Çalıştır ve JSON’a yaz
if __name__ == "__main__":
    stats = analyze_log("../sample_logs/broken_sample.log")
    with open("report.json", "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=4)
    print("Analysis complete. JSON report generated.")
