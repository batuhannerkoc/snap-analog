#!/usr/bin/env python3
"""
Log Analysis Toolkit - Complete Log Processing Pipeline
Usage: logtool <command> [options]
"""

import argparse
import sys
import os
import json
from datetime import datetime

def main():
    parser = argparse.ArgumentParser(
        description='Log Analysis Toolkit - Complete Log Processing Pipeline',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze log file with default settings
  logtool analyze access.log
  
  # Analyze with aggressive memory mode
  logtool analyze access.log --mode aggressive
  
  # Analyze and generate visualization
  logtool analyze access.log --visualize
  
  # Visualize existing JSON report
  logtool visualize report_20231201.json
  
  # Generate test log file to current directory
  logtool generate-test --lines 10000 --output ./test.log
  
  # Generate test log to specific directory
  logtool generate-test --lines 5000 --output /tmp/test_logs/access.log
  
  # Show system info
  logtool info
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # ==================== ANALYZE COMMAND ====================
    analyze_parser = subparsers.add_parser('analyze', help='Analyze log file')
    analyze_parser.add_argument('logfile', help='Path to log file')
    analyze_parser.add_argument('--mode', choices=['auto', 'full', 'balanced', 'aggressive'],
                               default='auto', help='Memory mode (default: auto)')
    analyze_parser.add_argument('--output', help='Custom output filename')
    analyze_parser.add_argument('--visualize', action='store_true', 
                               help='Generate visualization after analysis')
    analyze_parser.add_argument('--quiet', action='store_true', 
                               help='Suppress progress output')
    analyze_parser.add_argument('--validate', action='store_true',
                               help='Enable strict validation')
    
    # ==================== VISUALIZE COMMAND ====================
    visualize_parser = subparsers.add_parser('visualize', help='Visualize JSON report')
    visualize_parser.add_argument('json_file', help='Path to JSON report file')
    visualize_parser.add_argument('--theme', choices=['whitegrid', 'darkgrid', 'white', 'dark', 'ticks'],
                                 default='whitegrid', help='Seaborn theme style')
    visualize_parser.add_argument('--palette', default='viridis', 
                                 help='Color palette for charts')
    visualize_parser.add_argument('--size', choices=['small', 'medium', 'large', 'xlarge'],
                                 default='medium', help='Figure size')
    visualize_parser.add_argument('--dpi', type=int, default=150, 
                                 help='Output DPI (default: 150)')
    visualize_parser.add_argument('--no-values', action='store_true', 
                                 help='Hide values on bars')
    visualize_parser.add_argument('--output-dir', default='reports',
                                 help='Output directory')
    visualize_parser.add_argument('--title', help='Custom dashboard title')
    
    # ==================== GENERATE-TEST COMMAND ====================
    generate_parser = subparsers.add_parser('generate-test', 
                                          help='Generate test log file')
    generate_parser.add_argument('--lines', type=int, default=1000,
                                help='Number of lines (default: 1000)')
    generate_parser.add_argument('--output', required=True,
                                help='Output file path (required)')
    generate_parser.add_argument('--format', choices=['apache', 'nginx', 'json', 'syslog'],
                                default='apache', help='Log format (default: apache)')
    generate_parser.add_argument('--overwrite', action='store_true',
                                help='Overwrite existing file')
    
    # ==================== INFO COMMAND ====================
    subparsers.add_parser('info', help='Show system information')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # ==================== COMMAND ROUTING ====================
    print(f"Log Analysis Toolkit v1.0")
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    try:
        if args.command == 'analyze':
            # Check if log_analyzer exists
            try:
                from log_analyzer import analyze_log_optimized
            except ImportError:
                print("Error: log_analyzer.py not found in current directory")
                print("Please ensure log_analyzer.py is in the same directory")
                sys.exit(1)
            
            import time
            
            print(f"Analyzing: {args.logfile}")
            print(f"Mode: {args.mode}")
            
            if not os.path.exists(args.logfile):
                print(f"Error: File not found: {args.logfile}")
                sys.exit(1)
            
            start_time = time.time()
            stats = analyze_log_optimized(args.logfile)
            elapsed = time.time() - start_time
            
            if 'error' in stats:
                print(f"Analysis failed: {stats['error']}")
                sys.exit(1)
            
            # Save report
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            if args.output:
                output_file = args.output
            else:
                output_file = f"log_analysis_{timestamp}.json"
            
            with open(output_file, 'w') as f:
                json.dump(stats, f, indent=2)
            
            print(f"\nAnalysis completed in {elapsed:.2f}s")
            print(f"Report saved to: {output_file}")
            print(f"Total lines: {stats['summary']['total_lines']:,}")
            print(f"Success rate: {stats['health_metrics']['success_rate_2xx_3xx']}")
            
            if args.visualize:
                print("\nGenerating visualization...")
                try:
                    from log_visualizer import visualize_results
                    viz_file = visualize_results(stats, f"dashboard_{timestamp}")
                    print(f"Visualization saved to: {viz_file}")
                except ImportError:
                    print("Warning: log_visualizer.py not found, skipping visualization")
        
        elif args.command == 'visualize':
            try:
                from log_visualizer import visualize_results, load_stats_from_json
            except ImportError:
                print("Error: log_visualizer.py not found in current directory")
                print("Please ensure log_visualizer.py is in the same directory")
                sys.exit(1)
            
            print(f"Visualizing: {args.json_file}")
            print(f"Theme: {args.theme}")
            print(f"Palette: {args.palette}")
            
            if not os.path.exists(args.json_file):
                print(f"Error: File not found: {args.json_file}")
                sys.exit(1)
            
            stats = load_stats_from_json(args.json_file)
            
            # Customize visualization based on args
            output_file = visualize_results(
                stats,
                output_filename_base=f"dashboard_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            )
            
            print(f"\nVisualization completed!")
            print(f"Dashboard saved to: {output_file}")
        
        elif args.command == 'generate-test':
            print(f"Generating test log...")
            print(f"Lines: {args.lines:,}")
            print(f"Format: {args.format}")
            print(f"Output: {args.output}")
            
            # Check if output directory exists
            output_dir = os.path.dirname(args.output)
            if output_dir and not os.path.exists(output_dir):
                print(f"Creating directory: {output_dir}")
                os.makedirs(output_dir, exist_ok=True)
            
            # Check if file exists
            if os.path.exists(args.output) and not args.overwrite:
                print(f"Error: File already exists: {args.output}")
                print("Use --overwrite flag to overwrite")
                sys.exit(1)
            
            # Generate test log
            test_file = generate_test_log(
                filename=args.output,
                num_lines=args.lines,
                format_type=args.format
            )
            
            file_size = os.path.getsize(test_file)
            print(f"\nTest log generated successfully!")
            print(f"File: {test_file}")
            print(f"Size: {file_size / 1024:.1f} KB ({file_size:,} bytes)")
            print(f"Lines: {args.lines:,}")
            print(f"Format: {args.format}")
            
            # Show sample
            print(f"\nSample of first 3 lines:")
            with open(test_file, 'r') as f:
                for i, line in enumerate(f):
                    if i >= 3:
                        break
                    print(f"  {line.strip()}")
        
        elif args.command == 'info':
            import platform
            
            print("SYSTEM INFORMATION")
            print("-" * 40)
            print(f"Python: {platform.python_version()}")
            print(f"OS: {platform.system()} {platform.release()}")
            
            # Try to get additional info
            try:
                import psutil
                print(f"CPU: {psutil.cpu_count()} cores")
                print(f"Memory: {psutil.virtual_memory().total / 1024**3:.1f} GB")
                print(f"Disk: {psutil.disk_usage('/').free / 1024**3:.1f} GB free")
            except ImportError:
                print("Install psutil for detailed system info: pip install psutil")
            
            print("\nINSTALLED PACKAGES")
            print("-" * 40)
            packages = ['matplotlib', 'seaborn', 'pandas', 'numpy']
            for pkg in packages:
                try:
                    module = __import__(pkg)
                    print(f"✓ {pkg}: {getattr(module, '__version__', 'unknown')}")
                except ImportError:
                    print(f"✗ {pkg}: Not installed")
    
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

def generate_test_log(filename, num_lines, format_type='apache'):
    """Generate test log file with customizable output path"""
    import random
    from datetime import datetime, timedelta
    
    methods = ['GET', 'POST', 'PUT', 'DELETE']
    statuses = ['200', '404', '500', '301', '400', '403']
    paths = ['/', '/index.html', '/api/users', '/api/data', '/admin', '/login', '/products', '/cart']
    user_agents = ['Mozilla/5.0', 'Chrome/91.0', 'Safari/14.0', 'PostmanRuntime/7.28']
    
    start_time = datetime(2023, 10, 10, 9, 0, 0)
    
    with open(filename, 'w') as f:
        for i in range(num_lines):
            ip = f"192.168.{random.randint(1,255)}.{random.randint(1,255)}"
            timestamp = (start_time + timedelta(seconds=i*2)).strftime('%d/%b/%Y:%H:%M:%S +0300')
            method = random.choice(methods)
            path = random.choice(paths)
            
            # Add query parameters sometimes
            if random.random() < 0.3:
                path += f'?id={random.randint(1000, 9999)}'
            
            status = random.choice(statuses)
            size = random.randint(100, 10000)
            
            if format_type == 'apache':
                f.write(f'{ip} - - [{timestamp}] "{method} {path} HTTP/1.1" {status} {size}\n')
            elif format_type == 'nginx':
                referer = '-' if random.random() < 0.5 else f'"http://example.com{random.choice(paths)}"'
                user_agent = random.choice(user_agents)
                f.write(f'{ip} - - [{timestamp}] "{method} {path} HTTP/1.1" {status} {size} {referer} "{user_agent}"\n')
            elif format_type == 'json':
                log_entry = {
                    'timestamp': timestamp,
                    'ip': ip,
                    'method': method,
                    'path': path,
                    'status': int(status),
                    'size': size,
                    'user_agent': random.choice(user_agents)
                }
                f.write(json.dumps(log_entry) + '\n')
            elif format_type == 'syslog':
                process = random.choice(['sshd', 'kernel', 'cron', 'nginx', 'apache'])
                pid = random.randint(1000, 9999)
                messages = [
                    f'Connection from {ip}',
                    f'Failed password for root',
                    f'CPU temperature above threshold',
                    f'User login successful',
                    f'Disk space warning'
                ]
                message = random.choice(messages)
                f.write(f'{timestamp} server1 {process}[{pid}]: {message}\n')
    
    return filename

if __name__ == "__main__":
    main()
