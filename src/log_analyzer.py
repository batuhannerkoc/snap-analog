import re
import heapq
import os
from collections import Counter, defaultdict
from datetime import datetime
import json
import ipaddress
import sys
import time

TIMESTAMP_INPUT_FORMAT = "%d/%b/%Y:%H:%M:%S %z"
TIMESTAMP_OUTPUT_FORMAT = "%Y-%m-%d %H:%M"
TOP_N_RESULTS = 10
STATUS_CODE_LENGTH = 3
DEFAULT_ENCODING = "utf-8"
VALID_HTTP_METHODS = [
    "GET", "POST", "PUT", "DELETE", "PATCH", 
    "HEAD", "OPTIONS", "CONNECT", "TRACE"
]

BUFFER_SIZE = 1024 * 1024
BOM = "\ufeff"

MAX_UNIQUE_IPS = 100000
MAX_UNIQUE_URLS = 50000
MAX_UNIQUE_MINUTES = 10000
PRUNE_EVERY_N_LINES = 100000

SMALL_FILE_THRESHOLD = 100
MEDIUM_FILE_THRESHOLD = 1000
LARGE_FILE_THRESHOLD = 10000

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
    def __init__(self, k=10000, name="tracker"):
        self.k = k
        self.name = name
        self.counts = defaultdict(int)
        self.heap = []
        self.insertion_counter = 0
        self.total_adds = 0
        
    def add(self, item):
        self.total_adds += 1
        self.insertion_counter += 1
        
        self.counts[item] += 1
        current_count = self.counts[item]
        
        item_in_heap = any(item == heap_item for _, _, heap_item in self.heap)
        
        if item_in_heap:
            self._update_heap()
        else:
            if len(self.heap) < self.k:
                heapq.heappush(self.heap, (current_count, self.insertion_counter, item))
            elif current_count > self.heap[0][0]:
                heapq.heappushpop(self.heap, (current_count, self.insertion_counter, item))
    
    def _update_heap(self):
        items_in_heap = {item for _, _, item in self.heap}
        new_heap = []
        
        for item in items_in_heap:
            count = self.counts[item]
            heapq.heappush(new_heap, (count, 0, item))
        
        self.heap = new_heap
    
    def prune(self, percent=10):
        if len(self.counts) <= self.k:
            return
        
        heap_items = {item for _, _, item in self.heap}
        non_heap_items = [item for item in self.counts if item not in heap_items]
        
        if not non_heap_items:
            return
        
        to_remove = max(len(non_heap_items) * percent // 100, 1)
        
        non_heap_with_counts = [(item, self.counts[item]) for item in non_heap_items]
        non_heap_with_counts.sort(key=lambda x: x[1])
        
        for item, _ in non_heap_with_counts[:to_remove]:
            del self.counts[item]
    
    def get_top_k(self, n=None):
        if n is None:
            n = len(self.heap)
        
        sorted_items = sorted(self.heap, key=lambda x: (-x[0], x[1]))
        return [(item, self.counts[item]) for _, _, item in sorted_items[:n]]
    
    def get_count(self, item):
        return self.counts.get(item, 0)
    
    def __len__(self):
        return len(self.counts)
    
    def get_stats(self):
        return {
            "name": self.name,
            "k": self.k,
            "unique_items": len(self.counts),
            "heap_size": len(self.heap),
            "total_adds": self.total_adds,
            "memory_estimate_bytes": len(self.counts) * 100
        }

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
                raise ValueError(
                    f"Status code out of range: {status} (valid: {MIN_STATUS_CODE}-{MAX_STATUS_CODE})"
                )
        except ValueError as e:
            if "out of range" in str(e):
                raise
            raise ValueError(f"Invalid status code format: {status}")

    group = (
        f"{status[0]}xx" if status and len(status) == STATUS_CODE_LENGTH else "Unknown"
    )
    return status, group

def parse_request(data):
    request_raw = data["request"]
    
    if not request_raw:
        raise ValueError("empty request")

    parts = request_raw.split()

    if len(parts) != 3:
        raise ValueError("malformed request: expected 3 parts")

    method, path, protocol = parts

    if method not in VALID_HTTP_METHODS:
        raise ValueError(f"Invalid HTTP method: {method}")

    if not path.startswith("/"):
        raise ValueError("invalid path: must start with /")

    if not protocol.startswith("HTTP/"):
        raise ValueError("invalid protocol: must start with HTTP/")

    return method, path

def parse_size(data):
    size = data["size"]
    if size and size.isdigit():
        return int(size)
    return None

def record_failure(failed_attempts, line, reason):
    if len(failed_attempts) < 1000:
        if line not in failed_attempts:
            failed_attempts[line] = {"count": 1, "reason": reason}
        else:
            failed_attempts[line]["count"] += 1

def get_memory_mode_for_file(filepath):
    try:
        file_size_bytes = os.path.getsize(filepath)
        file_size_mb = file_size_bytes / (1024 * 1024)
    except:
        file_size_mb = 0
    
    if file_size_mb < SMALL_FILE_THRESHOLD:
        mode = "FULL"
        limits = {'max_ips': 0, 'max_urls': 0, 'max_minutes': 0}
    elif file_size_mb < MEDIUM_FILE_THRESHOLD:
        mode = "BALANCED"
        limits = {'max_ips': MAX_UNIQUE_IPS, 'max_urls': MAX_UNIQUE_URLS, 'max_minutes': MAX_UNIQUE_MINUTES}
    else:
        mode = "AGGRESSIVE"
        limits = {'max_ips': MAX_UNIQUE_IPS // 2, 'max_urls': MAX_UNIQUE_URLS // 2, 'max_minutes': MAX_UNIQUE_MINUTES // 2}
    
    return mode, limits, file_size_mb

def analyze_log_optimized(filepath):
    print(f"Analyzing: {filepath}")
    
    memory_mode, limits, file_size_mb = get_memory_mode_for_file(filepath)
    print(f"File size: {file_size_mb:.1f}MB | Mode: {memory_mode}")
    
    total_requests = 0
    total_lines_processed = 0
    total_size = 0
    size_count = 0
    min_size = None
    max_size = None
    failed_attempts = {}
    
    if limits['max_ips'] > 0:
        ips_tracker = TopKTracker(limits['max_ips'], "IPs")
        urls_tracker = TopKTracker(limits['max_urls'], "URLs")
        minutes_tracker = TopKTracker(limits['max_minutes'], "Minutes")
        use_top_k = True
    else:
        ips_counter = Counter()
        urls_counter = Counter()
        minutes_counter = Counter()
        use_top_k = False
    
    statuses = Counter()
    status_groups = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "Unknown": 0}
    methods = Counter()
    
    start_time = time.time()
    
    try:
        with open(filepath, "r", encoding=DEFAULT_ENCODING, buffering=BUFFER_SIZE) as f:
            for line_num, line in enumerate(f, 1):
                total_lines_processed += 1
                
                if line_num % 100000 == 0:
                    elapsed = time.time() - start_time
                    lines_per_sec = line_num / elapsed if elapsed > 0 else 0
                    print(f"  📈 {line_num:,} lines ({lines_per_sec:,.0f} lines/sec)", end='\r', flush=True)
                    
                    if use_top_k and line_num % PRUNE_EVERY_N_LINES == 0:
                        prune_percent = 5 if memory_mode == "BALANCED" else 20
                        ips_tracker.prune(prune_percent)
                        urls_tracker.prune(prune_percent)
                
                if line and line[0] == BOM:
                    line = line[1:]
                line_original = line.rstrip("\r\n")
                
                if not line_original or line_original.startswith("#"):
                    continue
                
                temp_minute = temp_ip = temp_status = temp_group = temp_method = temp_path = None
                line_is_valid = True
                
                try:
                    match = log_pattern.match(line_original)
                    
                    if not match:
                        record_failure(failed_attempts, line_original, "regex_no_match")
                        continue
                    
                    data = match.groupdict()
                    
                    try:
                        temp_minute = parse_timestamp(data)
                    except (ValueError, KeyError):
                        record_failure(failed_attempts, line_original, "timestamp_error")
                        line_is_valid = False
                    
                    if line_is_valid:
                        try:
                            temp_ip = parse_ip(data)
                        except (ValueError, KeyError):
                            record_failure(failed_attempts, line_original, "ip_error")
                            line_is_valid = False
                    
                    if line_is_valid:
                        try:
                            temp_status, temp_group = parse_status(data)
                        except (ValueError, KeyError):
                            record_failure(failed_attempts, line_original, "status_error")
                            line_is_valid = False
                    
                    if line_is_valid:
                        try:
                            temp_method, temp_path = parse_request(data)
                        except (ValueError, KeyError):
                            record_failure(failed_attempts, line_original, "request_error")
                            line_is_valid = False
                    
                    if (line_is_valid and temp_ip and temp_minute and 
                        temp_status and temp_method and temp_path):
                        
                        total_requests += 1
                        
                        if use_top_k:
                            ips_tracker.add(temp_ip)
                            urls_tracker.add(temp_path)
                            minutes_tracker.add(temp_minute)
                        else:
                            ips_counter[temp_ip] += 1
                            urls_counter[temp_path] += 1
                            minutes_counter[temp_minute] += 1
                        
                        statuses[temp_status] += 1
                        status_groups[temp_group] += 1
                        methods[temp_method] += 1
                        
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
                
                except Exception:
                    if line_is_valid:
                        record_failure(failed_attempts, line_original, "unexpected_error")
        
        print()
        
    except FileNotFoundError:
        print("Cannot find the file:", filepath)
        return {"error": "FileNotFoundError"}
    except Exception as e:
        print(f"Unexpected error: {e}")
        return {"error": str(e)}
    
    elapsed_time = time.time() - start_time
    
    if use_top_k:
        top_ips = ips_tracker.get_top_k(TOP_N_RESULTS)
        top_urls = urls_tracker.get_top_k(TOP_N_RESULTS)
        top_minutes = minutes_tracker.get_top_k(TOP_N_RESULTS)
        
        tracker_stats = {
            "ips": ips_tracker.get_stats(),
            "urls": urls_tracker.get_stats(),
            "minutes": minutes_tracker.get_stats()
        }
    else:
        top_ips = ips_counter.most_common(TOP_N_RESULTS)
        top_urls = urls_counter.most_common(TOP_N_RESULTS)
        top_minutes = minutes_counter.most_common(TOP_N_RESULTS)
        
        tracker_stats = {
            "ips": {"unique_items": len(ips_counter), "mode": "FULL"},
            "urls": {"unique_items": len(urls_counter), "mode": "FULL"},
            "minutes": {"unique_items": len(minutes_counter), "mode": "FULL"}
        }
    
    success_2xx = status_groups.get("2xx", 0)
    success_3xx = status_groups.get("3xx", 0)
    client_error_4xx = status_groups.get("4xx", 0)
    server_error_5xx = status_groups.get("5xx", 0)
    
    if total_requests > 0:
        success_rate = ((success_2xx + success_3xx) / total_requests) * 100
        server_error_rate = (server_error_5xx / total_requests) * 100
        client_error_rate = (client_error_4xx / total_requests) * 100
    else:
        success_rate = server_error_rate = client_error_rate = 0.0
    
    if size_count > 0:
        sizes_avg = total_size / size_count
        sizes_total = total_size
    else:
        min_size = max_size = sizes_avg = sizes_total = None
    
    stats = {
        "summary": {
            "file": filepath,
            "file_size_mb": round(file_size_mb, 1),
            "memory_mode": memory_mode,
            "total_lines": total_lines_processed,
            "total_requests": total_requests,
            "analysis_time_seconds": round(elapsed_time, 2),
            "lines_per_second": round(total_lines_processed / elapsed_time if elapsed_time > 0 else 0, 0),
            "parsing_success_rate": f"{(total_requests / total_lines_processed * 100):.1f}%" if total_lines_processed > 0 else "0%"
        },
        "health_metrics": {
            "success_rate_2xx_3xx": f"{success_rate:.1f}%",
            "client_error_rate_4xx": f"{client_error_rate:.1f}%",
            "server_error_rate_5xx": f"{server_error_rate:.1f}%",
            "status_groups": status_groups
        },
        "traffic_analysis": {
            "top_ips": top_ips,
            "top_urls": top_urls,
            "top_minutes": top_minutes,
            "status_distribution": dict(statuses),
            "methods": dict(methods)
        },
        "size_analysis": {
            "min_bytes": min_size,
            "max_bytes": max_size,
            "avg_bytes": sizes_avg,
            "total_bytes": sizes_total,
            "requests_with_size": size_count
        },
        "memory_optimization": {
            "mode": memory_mode,
            "limits": limits,
            "tracker_stats": tracker_stats,
            "failed_attempts_count": len(failed_attempts)
        }
    }
    
    if failed_attempts:
        sample_failures = dict(list(failed_attempts.items())[:5])
        stats["memory_optimization"]["sample_failures"] = sample_failures
    
    return stats

if __name__ == "__main__":
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
        if not os.path.exists(log_file):
            print(f"File not found: {log_file}")
            sys.exit(1)
    else:
        log_file = "../sample_logs/sample.log"
        if not os.path.exists(log_file):
            with open("sample.log", "w") as f:
                for i in range(1000):
                    ip = f"192.168.{i % 256}.{i % 256}"
                    f.write(f'{ip} - - [10/Oct/2023:12:00:{i%60:02d} +0300] "GET /page/{i} HTTP/1.1" 200 1000\n')
            log_file = "sample.log"
    
    print(f"{'='*60}")
    print("ANALOG - LOG ANALYZER2.0 by batuhannerkoc")
    print(f"{'='*60}")
    
    stats = analyze_log_optimized(log_file)
    
    if "error" in stats:
        print(f"Analysis failed: {stats['error']}")
        sys.exit(1)
    
    print(f"\n{'='*60}")
    print("ANALYSIS COMPLETE")
    print(f"{'='*60}")
    
    summary = stats["summary"]
    print(f"File: {summary['file']}")
    print(f"Size: {summary['file_size_mb']}MB | Mode: {summary['memory_mode']}")
    print(f"Time: {summary['analysis_time_seconds']}s ({summary['lines_per_second']} lines/sec)")
    print(f"Lines: {summary['total_lines']:,} | Requests: {summary['total_requests']:,}")
    print(f"Success rate: {stats['health_metrics']['success_rate_2xx_3xx']}")
    
    if stats["traffic_analysis"]["top_ips"]:
        top_ip, count = stats["traffic_analysis"]["top_ips"][0]
        print(f"Top IP: {top_ip} ({count} requests)")
    
    mem_stats = stats["memory_optimization"]
    print(f"\nMEMORY OPTIMIZATION:")
    print(f"  Mode: {mem_stats['mode']}")
    
    for tracker_name, tracker_info in mem_stats['tracker_stats'].items():
        if 'unique_items' in tracker_info:
            print(f"  {tracker_name.upper()}: {tracker_info['unique_items']:,} unique items")
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"log_analysis_report_{timestamp}.json"
    
    try:
        with open(output_file, "w", encoding=DEFAULT_ENCODING) as f:
            json.dump(stats, f, indent=2, default=str)
        print(f"\nReport saved to: {output_file}")
    except Exception as e:
        print(f"\nCould not save report: {e}")
    
    print(f"{'='*60}\n")
    
    if log_file == "sample.log" and os.path.exists("sample.log"):
        os.remove("sample.log")
