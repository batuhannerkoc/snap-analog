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
VALID_HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE"}

BUFFER_SIZE = 1024 * 1024 * 10  # 10MB buffer
BOM = "\ufeff"

MAX_UNIQUE_IPS = 50000
MAX_UNIQUE_URLS = 25000
MAX_UNIQUE_MINUTES = 5000
PRUNE_EVERY_N_LINES = 50000

SMALL_FILE_THRESHOLD = 10  # 10MB
MEDIUM_FILE_THRESHOLD = 100  # 100MB
LARGE_FILE_THRESHOLD = 1000  # 1GB

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

class AnalysisConfig:
    """Configuration for log analysis."""
    def __init__(self, memory_mode="auto", validate=False, quiet=False):
        self.memory_mode = memory_mode
        self.validate = validate
        self.quiet = quiet
        
        if memory_mode == "aggressive":
            self.limits = {'max_ips': 10000, 'max_urls': 5000, 'max_minutes': 1000}
        elif memory_mode == "balanced":
            self.limits = {'max_ips': 50000, 'max_urls': 25000, 'max_minutes': 5000}
        elif memory_mode == "full":
            self.limits = {'max_ips': 0, 'max_urls': 0, 'max_minutes': 0}
        else:
            self.limits = {}

class FastTopKTracker:
    """Memory-efficient Top-K tracker using min-heap with O(1) lookups.
    
    Optimizations:
    - Hash set for O(1) membership check (instead of O(k) linear search)
    - Lazy heap rebuilding (batch updates instead of per-item)
    - Results in ~1000x speedup for large k values
    """
    def __init__(self, k=10000, name="tracker"):
        self.k = k
        self.name = name
        self.counts = defaultdict(int)
        self.heap = []
        self.heap_items = set()  # O(1) lookup instead of O(k)
        self.dirty = False  # Flag for lazy rebuild
        self.total_adds = 0
        self.rebuild_count = 0  # Track rebuild frequency
        
    def add(self, item):
        """Add or update an item with O(log k) complexity.
        
        Performance:
        - O(1) for membership check (hash set)
        - O(log k) for heap operations
        - Lazy rebuild: O(k) amortized over many operations
        """
        self.total_adds += 1
        self.counts[item] += 1
        current_count = self.counts[item]
        
        # O(1) lookup using hash set!
        if item in self.heap_items:
            # Item already in heap - mark for lazy rebuild
            self.dirty = True
        elif len(self.heap) < self.k:
            # Heap not full - add item
            heapq.heappush(self.heap, (current_count, item))
            self.heap_items.add(item)
        elif current_count > self.heap[0][0]:
            # Item count exceeds min in heap - replace
            old_count, old_item = self.heap[0]
            self.heap_items.remove(old_item)  # Remove old item from set
            
            heapq.heapreplace(self.heap, (current_count, item))
            self.heap_items.add(item)  # Add new item to set
    
    def _rebuild_heap(self):
        """Rebuild heap with updated counts (called lazily).
        
        This is expensive (O(k)) but done only when necessary.
        """
        if not self.dirty:
            return
        
        self.rebuild_count += 1
        
        # Rebuild heap with current counts
        self.heap = [(self.counts[item], item) for _, item in self.heap]
        heapq.heapify(self.heap)
        
        # Rebuild set (ensure consistency)
        self.heap_items = {item for _, item in self.heap}
        
        self.dirty = False
    
    def prune(self, percent=20):
        """Remove items not in heap to save memory.
        
        Args:
            percent: Percentage of non-heap items to remove
        """
        if len(self.counts) <= self.k * 2:
            return
        
        # Ensure heap is up-to-date before pruning
        if self.dirty:
            self._rebuild_heap()
        
        to_remove = len(self.counts) * percent // 100
        
        # Use set for O(1) membership check
        for item in list(self.counts.keys()):
            if item not in self.heap_items and to_remove > 0:
                del self.counts[item]
                to_remove -= 1
    
    def get_top_k(self, n=None):
        """Get top-k items sorted by count (descending).
        
        Triggers lazy rebuild if needed.
        """
        # Rebuild heap if dirty (lazy update)
        if self.dirty:
            self._rebuild_heap()
        
        if n is None:
            n = len(self.heap)
        
        # Sort by count (descending) and return with current counts
        sorted_items = sorted(self.heap, key=lambda x: -x[0])
        return [(item, self.counts[item]) for _, item in sorted_items[:n]]
    
    def __len__(self):
        return len(self.counts)
    
    def get_stats(self):
        """Get performance statistics."""
        return {
            "total_adds": self.total_adds,
            "rebuild_count": self.rebuild_count,
            "heap_size": len(self.heap),
            "counts_size": len(self.counts),
            "rebuild_ratio": f"{(self.rebuild_count / max(self.total_adds, 1)) * 100:.2f}%"
        }

# Month name to number mapping for fast parsing
month_dict = {
    'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04',
    'May': '05', 'Jun': '06', 'Jul': '07', 'Aug': '08',
    'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12'
}

def parse_minute_fast(timestamp_str):
    """Fast timestamp parser using string slicing instead of strptime.
    
    ~10x faster than datetime.strptime()
    """
    try:
        day = timestamp_str[0:2]
        month = timestamp_str[3:6]
        year = timestamp_str[7:11]
        hour = timestamp_str[12:14]
        minute = timestamp_str[15:17]
        return f"{year}-{month_dict.get(month, '01')}-{day} {hour}:{minute}"
    except:
        return "0000-00-00 00:00"

def parse_ip_fast(ip, validate=False):
    """Parse and optionally validate IP address."""
    if not validate:
        return ip
    
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        return None

def parse_status_fast(status, validate=False):
    """Parse and optionally validate status code."""
    if not status or len(status) != 3 or not status.isdigit():
        return None, "Unknown"
    
    if validate:
        status_int = int(status)
        if not (MIN_STATUS_CODE <= status_int <= MAX_STATUS_CODE):
            return None, "Unknown"
    
    group = f"{status[0]}xx"
    return status, group

def parse_request_fast(request_raw, validate=False):
    """Parse request string to extract method and path.
    
    Args:
        request_raw: Raw request string (e.g., "GET /index.html HTTP/1.1")
        validate: If True, perform strict validation
    
    Returns:
        tuple: (method, path) or (None, None) if invalid
    """
    if not request_raw:
        return None, None
    
    try:
        # Find method (first space-separated token)
        method_end = request_raw.find(' ')
        if method_end == -1:
            return None, None
        
        method = request_raw[:method_end]
        if method not in VALID_HTTP_METHODS:
            return None, None
        
        # Find path (between first and second space)
        path_start = method_end + 1
        path_end = request_raw.find(' ', path_start)
        if path_end == -1:
            return None, None
        
        path = request_raw[path_start:path_end]
        
        # Validate path starts with /
        if not path.startswith('/'):
            return None, None
        
        if validate:
            # Validate protocol (after second space)
            protocol = request_raw[path_end + 1:]
            if not protocol.startswith('HTTP/'):
                return None, None
        
        return method, path
    except Exception as e:
        return None, None

def analyze_log_optimized(filepath, config=None, progress_callback=None):
    """Analyze log file with adaptive memory management.
    
    Args:
        filepath: Path to log file
        config: AnalysisConfig object
        progress_callback: Optional callback function(current, total)
    
    Returns:
        dict: Analysis statistics
    """
    if config is None:
        config = AnalysisConfig()
    
    if not config.quiet:
        print(f"Analyzing: {filepath}")
    
    # Determine file size
    file_size_mb = 0
    try:
        file_size_bytes = os.path.getsize(filepath)
        file_size_mb = file_size_bytes / (1024 * 1024)
    except Exception as e:
        if not config.quiet:
            print(f"Warning: Could not determine file size: {e}")
    
    # Select memory mode based on file size
    if config.memory_mode == "auto":
        if file_size_mb < SMALL_FILE_THRESHOLD:
            memory_mode = "FULL"
            limits = {'max_ips': 0, 'max_urls': 0, 'max_minutes': 0}
        elif file_size_mb < MEDIUM_FILE_THRESHOLD:
            memory_mode = "BALANCED"
            limits = {'max_ips': MAX_UNIQUE_IPS, 'max_urls': MAX_UNIQUE_URLS, 'max_minutes': MAX_UNIQUE_MINUTES}
        else:
            memory_mode = "AGGRESSIVE"
            limits = {'max_ips': 10000, 'max_urls': 5000, 'max_minutes': 1000}
    else:
        memory_mode = config.memory_mode.upper()
        limits = config.limits
    
    if not config.quiet:
        print(f"File size: {file_size_mb:.1f}MB | Mode: {memory_mode} | Validation: {'ON' if config.validate else 'OFF'}")
        if limits.get('max_ips', 0) > 0:
            print(f"Limits: IPs={limits.get('max_ips', 0)}, URLs={limits.get('max_urls', 0)}, Minutes={limits.get('max_minutes', 0)}")
    
    # Initialize counters
    total_requests = 0
    total_lines_processed = 0
    total_size = 0
    size_count = 0
    parse_errors = 0
    
    # Initialize trackers based on memory mode
    if limits.get('max_ips', 0) > 0:
        ips_tracker = FastTopKTracker(limits.get('max_ips', 10000), "IPs")
        urls_tracker = FastTopKTracker(limits.get('max_urls', 5000), "URLs")
        minutes_tracker = FastTopKTracker(limits.get('max_minutes', 1000), "Minutes")
        use_top_k = True
    else:
        ips_counter = Counter()
        urls_counter = Counter()
        minutes_counter = Counter()
        use_top_k = False
    
    statuses = Counter()
    status_groups = Counter({"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "Unknown": 0})
    methods = Counter()
    
    start_time = time.time()
    last_print_time = start_time
    
    try:
        with open(filepath, "r", encoding=DEFAULT_ENCODING, buffering=BUFFER_SIZE) as f:
            for line_num, line in enumerate(f, 1):
                total_lines_processed += 1
                
                # Progress callback
                if progress_callback and line_num % 5000 == 0:
                    progress_callback(line_num, 0)
                
                # Progress printing
                current_time = time.time()
                if not config.quiet and current_time - last_print_time > 1.0:
                    elapsed = current_time - start_time
                    lines_per_sec = line_num / elapsed if elapsed > 0 else 0
                    print(f"  {line_num:,} lines ({lines_per_sec:,.0f} lines/sec)", end='\r')
                    last_print_time = current_time
                    
                    # Periodic pruning for TopK trackers
                    if use_top_k and line_num % PRUNE_EVERY_N_LINES == 0:
                        ips_tracker.prune(25)
                        urls_tracker.prune(25)
                        minutes_tracker.prune(20)
                
                # Remove BOM if present
                if line and line[0] == BOM:
                    line = line[1:]
                
                # Clean line
                line = line.rstrip("\r\n")
                if not line or line.startswith("#"):
                    continue
                
                # Regex match
                match = log_pattern.match(line)
                if not match:
                    parse_errors += 1
                    continue
                
                data = match.groupdict()
                
                try:
                    # Parse all fields
                    minute = parse_minute_fast(data["timestamp"])
                    ip = parse_ip_fast(data["ip"], validate=config.validate)
                    status, group = parse_status_fast(data["status"], validate=config.validate)
                    method, path = parse_request_fast(data["request"], validate=config.validate)
                    
                    # Validate all critical fields
                    if not all([minute, ip, status, method, path]):
                        parse_errors += 1
                        continue
                    
                    # Valid request - increment counters
                    total_requests += 1
                    
                    # Update trackers
                    if use_top_k:
                        ips_tracker.add(ip)
                        urls_tracker.add(path)
                        minutes_tracker.add(minute)
                    else:
                        ips_counter[ip] += 1
                        urls_counter[path] += 1
                        minutes_counter[minute] += 1
                    
                    statuses[status] += 1
                    status_groups[group] += 1
                    methods[method] += 1
                    
                    # Optional: Size parsing
                    size_str = data.get("size", "")
                    if size_str and size_str.isdigit():
                        size = int(size_str)
                        total_size += size
                        size_count += 1
                        
                except Exception as e:
                    parse_errors += 1
                    if not config.quiet and parse_errors < 10:  # Limit error messages
                        print(f"\nParse error at line {line_num}: {e}")
                    continue
        
        if not config.quiet:
            print()  # New line after progress
    
    except FileNotFoundError:
        print(f"Error: File not found: {filepath}")
        return {"error": "FileNotFoundError"}
    except Exception as e:
        print(f"Error reading file: {e}")
        return {"error": str(e)}
    
    elapsed_time = time.time() - start_time
    
    # Collect results
    if use_top_k:
        top_ips = ips_tracker.get_top_k(TOP_N_RESULTS)
        top_urls = urls_tracker.get_top_k(TOP_N_RESULTS)
        top_minutes = minutes_tracker.get_top_k(TOP_N_RESULTS)
        
        tracker_stats = {
            "ips": {
                "unique_items": len(ips_tracker), 
                "mode": "TOP_K", 
                "capacity": ips_tracker.k,
                "performance": ips_tracker.get_stats()
            },
            "urls": {
                "unique_items": len(urls_tracker), 
                "mode": "TOP_K", 
                "capacity": urls_tracker.k,
                "performance": urls_tracker.get_stats()
            },
            "minutes": {
                "unique_items": len(minutes_tracker), 
                "mode": "TOP_K", 
                "capacity": minutes_tracker.k,
                "performance": minutes_tracker.get_stats()
            }
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
    
    # Calculate health metrics
    success_total = status_groups.get("2xx", 0) + status_groups.get("3xx", 0)
    client_errors = status_groups.get("4xx", 0)
    server_errors = status_groups.get("5xx", 0)
    
    if total_requests > 0:
        success_rate = (success_total / total_requests) * 100
        client_error_rate = (client_errors / total_requests) * 100
        server_error_rate = (server_errors / total_requests) * 100
        parsing_success_rate = (total_requests / total_lines_processed) * 100
    else:
        success_rate = client_error_rate = server_error_rate = parsing_success_rate = 0.0
    
    avg_size = total_size / size_count if size_count > 0 else 0
    
    # Build statistics dictionary
    stats = {
        "summary": {
            "file": filepath,
            "file_size_mb": round(file_size_mb, 1),
            "memory_mode": memory_mode,
            "validation_enabled": config.validate,
            "total_lines": total_lines_processed,
            "total_requests": total_requests,
            "parse_errors": parse_errors,
            "analysis_time_seconds": round(elapsed_time, 2),
            "lines_per_second": round(total_lines_processed / elapsed_time if elapsed_time > 0 else 0, 0),
            "parsing_success_rate": f"{parsing_success_rate:.1f}%"
        },
        "health_metrics": {
            "success_rate_2xx_3xx": f"{success_rate:.1f}%",
            "client_error_rate_4xx": f"{client_error_rate:.1f}%",
            "server_error_rate_5xx": f"{server_error_rate:.1f}%",
            "status_groups": dict(status_groups)
        },
        "traffic_analysis": {
            "top_ips": top_ips,
            "top_urls": top_urls,
            "top_minutes": top_minutes,
            "status_distribution": dict(statuses),
            "methods": dict(methods)
        },
        "size_analysis": {
            "avg_bytes": round(avg_size, 1) if avg_size else None,
            "total_bytes": total_size,
            "requests_with_size": size_count
        },
        "memory_optimization": {
            "mode": memory_mode,
            "limits": limits,
            "tracker_stats": tracker_stats
        }
    }
    
    return stats

if __name__ == "__main__":
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
        if not os.path.exists(log_file):
            print(f"File not found: {log_file}")
            sys.exit(1)
    else:
        # Generate sample log if no file provided
        log_file = "sample.log"
        if not os.path.exists(log_file):
            print("Generating sample log file...")
            with open("sample.log", "w") as f:
                for i in range(1000):
                    ip = f"192.168.{i % 256}.{i % 256}"
                    f.write(f'{ip} - - [10/Oct/2023:12:00:{i%60:02d} +0300] "GET /page/{i} HTTP/1.1" 200 1000\n')
    
    # Run analysis
    config = AnalysisConfig(memory_mode="auto", validate=False, quiet=False)
    stats = analyze_log_optimized(log_file, config)
    
    if "error" in stats:
        print(f"Analysis failed: {stats['error']}")
        sys.exit(1)
    
    # Save report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"log_analysis_report_{timestamp}.json"
    
    try:
        with open(output_file, "w", encoding=DEFAULT_ENCODING) as f:
            json.dump(stats, f, indent=2, default=str)
        print(f"\n{'='*60}")
        print(f"✓ Analysis complete!")
        print(f"✓ Report saved: {output_file}")
        print(f"✓ Total lines: {stats['summary']['total_lines']:,}")
        print(f"✓ Valid requests: {stats['summary']['total_requests']:,}")
        print(f"✓ Success rate: {stats['health_metrics']['success_rate_2xx_3xx']}")
        
        # Show performance stats if TopK was used
        if stats['summary']['memory_mode'] != 'FULL':
            print(f"\n📊 TopK Tracker Performance:")
            for tracker_name, tracker_info in stats['memory_optimization']['tracker_stats'].items():
                if 'performance' in tracker_info:
                    perf = tracker_info['performance']
                    print(f"  {tracker_name.upper()}: {perf['total_adds']:,} adds, "
                          f"{perf['rebuild_count']} rebuilds ({perf['rebuild_ratio']})")
        
        print(f"{'='*60}")
    except Exception as e:
        print(f"Could not save report: {e}")
    
    # Clean up sample file
    if log_file == "sample.log" and os.path.exists("sample.log"):
        os.remove("sample.log")
