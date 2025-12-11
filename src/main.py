import re
from collections import defaultdict
from datetime import datetime
import json
import ipaddress
import heapq

TIMESTAMP_INPUT_FORMAT = "%d/%b/%Y:%H:%M:%S %z"
TIMESTAMP_OUTPUT_FORMAT = "%Y-%m-%d %H:%M"
TOP_N_RESULTS = 10
STATUS_CODE_LENGTH = 3
DEFAULT_ENCODING = "utf-8"
VALID_HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE"]
BUFFER_SIZE = 1024 * 1024
BOM = '\ufeff'

MAX_UNIQUE_IPS = 100000
MAX_UNIQUE_URLS = 50000
MAX_UNIQUE_MINUTES = 10000

VALIDATE_IP_FORMAT = True
VALIDATE_STATUS_CODE = True
MIN_STATUS_CODE = 100
MAX_STATUS_CODE = 599

log_pattern = re.compile(
    r"(?P<ip>\S+)\s+"
    r"(?P<identd>\S+)\s+"
    r"(?P<authuser>\S+)\s+"
    r"\[(?P<timestamp>[^\]]+)\]\s+"
    r'"(?P<request>[^"]*)"\s+'
    r"(?P<status>\d{3})\s+"
    r"(?P<size>\d+|-)" 
)

class TopKTracker:
    def __init__(self, k):
        self.k = k
        self.counts = defaultdict(int)
        self.heap = []
        self.counter = 0
        
    def add(self, item):
        self.counter += 1
        self.counts[item] += 1
        count = self.counts[item]
        
        if len(self.heap) < self.k:
            heapq.heappush(self.heap, (count, self.counter, item))
        elif count > self.heap[0][0]:
            heapq.heappushpop(self.heap, (count, self.counter, item))
            
    def get_top_k(self):
        return [(item, self.counts[item]) for _, _, item in sorted(self.heap, key=lambda x: (-x[0], x[1]))]
    
    def prune(self, percent=10):
        if len(self.counts) <= self.k:
            return
            
        to_remove = max(self.k // 10, 1)
        items_to_remove = []
        
        for item, count in list(self.counts.items()):
            is_in_heap = any(item == heap_item for _, _, heap_item in self.heap)
            if not is_in_heap:
                items_to_remove.append((count, item))
        
        items_to_remove.sort()
        for _, item in items_to_remove[:to_remove]:
            del self.counts[item]

def parse_minute(timestamp_str):
    timestamp_datetime = datetime.strptime(timestamp_str, TIMESTAMP_INPUT_FORMAT)
    return timestamp_datetime.strftime(TIMESTAMP_OUTPUT_FORMAT)

def parse_timestamp(data):
    return parse_minute(data["timestamp"])

def parse_ip(data):
    ip = data["ip"]
    if VALIDATE_IP_FORMAT:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise ValueError(f"Invalid IP format: {ip}")
    return ip

def parse_status(data):
    status = data["status"]
    if VALIDATE_STATUS_CODE:
        try:
            status_int = int(status)
            if not (MIN_STATUS_CODE <= status_int <= MAX_STATUS_CODE):
                raise ValueError(f"Status code out of range: {status}")
        except ValueError as e:
            if "out of range" not in str(e):
                raise ValueError(f"Invalid status code format: {status}")
            raise
    group = f"{status[0]}xx" if status and len(status) == STATUS_CODE_LENGTH else "Unknown"
    return status, group

def parse_request(data):
    request_raw = data["request"]
    request_parts = request_raw.split() if request_raw else []
    method = request_parts[0] if request_parts and request_parts[0] != "-" else "UNKNOWN"
    if method != "UNKNOWN" and method not in VALID_HTTP_METHODS:
        raise ValueError(f"Invalid HTTP method: {method}")
    url = request_parts[1] if len(request_parts) > 1 else "UNKNOWN"
    return method, url

def parse_size(data):
    size = data["size"]
    if size and size.isdigit():
        return int(size)
    return None

def record_failure(failed_attempts, line, reason):
    if line not in failed_attempts:
        failed_attempts[line] = {"count": 1, "reason": reason}
    else:
        failed_attempts[line]["count"] += 1

def analyze_log_optimized(filepath):
    total_requests = 0
    total_lines_processed = 0
    total_size = 0
    size_count = 0
    min_size = None
    max_size = None
    
    failed_attempts = {}
    ips_tracker = TopKTracker(MAX_UNIQUE_IPS)
    urls_tracker = TopKTracker(MAX_UNIQUE_URLS)
    minutes_tracker = TopKTracker(MAX_UNIQUE_MINUTES)
    
    statuses = defaultdict(int)
    status_groups = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "Unknown": 0}
    methods = defaultdict(int)
    
    try:
        with open(filepath, 'r', encoding=DEFAULT_ENCODING, buffering=BUFFER_SIZE) as f:
            for line_num, line in enumerate(f, 1):
                total_lines_processed += 1
                
                if line and line[0] == BOM:
                    line = line[1:]
                line_original = line.rstrip('\r\n')
                
                if not line_original or line_original.startswith("#"):
                    continue
                
                try:
                    match = log_pattern.match(line_original)
                    
                    if not match:
                        record_failure(failed_attempts, line_original, "regex_no_match")
                        continue
                    
                    data = match.groupdict()
                    parsed_timestamp = parsed_ip = parsed_status = parsed_request = False
                    
                    try:
                        minute = parse_timestamp(data)
                        minutes_tracker.add(minute)
                        parsed_timestamp = True
                    except (ValueError, KeyError) as e:
                        record_failure(failed_attempts, line_original, "timestamp_error")
                    
                    try:
                        ip = parse_ip(data)
                        ips_tracker.add(ip)
                        parsed_ip = True
                    except (ValueError, KeyError) as e:
                        record_failure(failed_attempts, line_original, "ip_error")
                    
                    try:
                        status, group = parse_status(data)
                        statuses[status] += 1
                        status_groups[group] += 1
                        parsed_status = True
                    except (ValueError, KeyError) as e:
                        record_failure(failed_attempts, line_original, "status_error")
                    
                    try:
                        method, url = parse_request(data)
                        methods[method] += 1
                        urls_tracker.add(url)
                        parsed_request = True
                    except (ValueError, KeyError) as e:
                        record_failure(failed_attempts, line_original, "request_error")
                    
                    if parsed_timestamp and parsed_ip and parsed_status and parsed_request:
                        total_requests += 1
                        
                        try:
                            size = parse_size(data)
                            if size is not None:
                                total_size += size
                                size_count += 1
                                if min_size is None or size < min_size:
                                    min_size = size
                                if max_size is None or size > max_size:
                                    max_size = size
                        except KeyError:
                            pass
                    
                    if line_num % 100000 == 0:
                        ips_tracker.prune(10)
                        urls_tracker.prune(10)
                
                except Exception as e:
                    record_failure(failed_attempts, line_original, "unexpected_error")
    
    except FileNotFoundError:
        print("Cannot find the file:", filepath)
        return {"error": "FileNotFoundError"}
    
    if size_count > 0:
        sizes_avg = total_size / size_count
        sizes_total = total_size
    else:
        sizes_min = sizes_max = sizes_avg = sizes_total = None
    
    stats = {
        "total_lines_processed": total_lines_processed,
        "total_requests": total_requests,
        "size_stats": {
            "min": min_size,
            "max": max_size,
            "avg": sizes_avg,
            "total": sizes_total,
        },
        "top_ips": ips_tracker.get_top_k()[:TOP_N_RESULTS],
        "status_distribution": dict(statuses),
        "status_groups": status_groups,
        "top_minutes": minutes_tracker.get_top_k()[:TOP_N_RESULTS],
        "methods": dict(methods),
        "top_urls": urls_tracker.get_top_k()[:TOP_N_RESULTS],
        "failed_attempts": dict(failed_attempts),
        "memory_stats": {
            "unique_ips_tracked": len(ips_tracker.counts),
            "unique_urls_tracked": len(urls_tracker.counts),
            "unique_minutes_tracked": len(minutes_tracker.counts)
        }
    }
    
    return stats

if __name__ == "__main__":
    import sys
    import time
    
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = "../sample_logs/sample.log"
    
    print(f"Analyzing {log_file}...")
    start_time = time.time()
    
    stats = analyze_log_optimized(log_file)
    
    end_time = time.time()
    elapsed = end_time - start_time
    
    output_file = f"report_optimized_{int(time.time())}.json"
    with open(output_file, "w", encoding=DEFAULT_ENCODING) as f:
        json.dump(stats, f, indent=2)
    
    print(f"\n✓ Analysis completed in {elapsed:.2f} seconds")
    print(f"✓ Processed {stats['total_lines_processed']} lines")
    print(f"✓ Found {stats['total_requests']} valid requests")
    print(f"✓ Top IP: {stats['top_ips'][0] if stats['top_ips'] else 'None'}")
    print(f"✓ Report saved to {output_file}")
    print(f"✓ Memory usage: {stats['memory_stats']['unique_ips_tracked']} unique IPs tracked")
