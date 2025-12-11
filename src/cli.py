#!/usr/bin/env python3

import argparse
import sys
import os
import json
from datetime import datetime, timedelta
import time
import platform
import random
import shutil # Terminal boyutunu almak için eklendi

# psutil ve traceback sadece gerektiğinde içe aktarılır.

class Color:
    """CLI çıktısı için renk ve stil kodları (ANSI)."""
    PURPLE = '\033[95m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'

# Yardımcı print fonksiyonları
def print_success(msg):
    """Başarı mesajını yeşil renkte basar."""
    print(f"{Color.GREEN}✓ {msg}{Color.END}")

def print_error(msg):
    """Hata mesajını kırmızı renkte basar."""
    print(f"{Color.RED}✗ {msg}{Color.END}")

def print_warning(msg):
    """Uyarı mesajını sarı renkte basar."""
    print(f"{Color.YELLOW}⚠ {msg}{Color.END}")

def print_info(msg):
    """Bilgi mesajını yeşil renkte basar."""
    print(f"{Color.GREEN}ℹ {msg}{Color.END}")

def print_header(is_welcome = False):
    """
    Özel stilize edilmiş başlığı/karşılama ekranını basar.
    Terminal genişliğine dinamik olarak uyum sağlar.
    """
    # Dinamik Terminal Boyutu: Minimum 70 genişlik garantilenir
    try:
        WIDTH = max(70, shutil.get_terminal_size().columns)
    except OSError:
        WIDTH = 70 # Terminal boyutu alınamazsa varsayılan

    
    # Başlık içeriğini ekrana göre ayarla
    if is_welcome:
        main_title = "LOG ANALYSIS SYSTEM"
        version_line = "v2.0 - Developed by batuhannerkoc"
        time_line = datetime.now().strftime('INITIALIZING: %Y-%m-%d %H:%M:%S')
    else:
        main_title = "LOG ANALYSIS TOOLKIT v2.0"
        version_line = "made by batuhannerkoc"
        time_line = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Metinleri ortala
    title_line = main_title.center(WIDTH - 4)
    author_line = version_line.center(WIDTH - 4)
    time_line_centered = time_line.center(WIDTH - 4)
    
    separator = f"{Color.PURPLE}{Color.BOLD}{'*' * WIDTH}{Color.END}"
    
    # Çerçeve
    print(f"\n{separator}")
    
    # Karşılama ekranında ekstra mor çerçeve çizgileri
    if is_welcome:
        print(f"{Color.PURPLE}{Color.BOLD}*{' ' * (WIDTH - 2)}*{Color.END}")
        
    # İçerik
    print(f"{Color.PURPLE}{Color.BOLD}*{Color.END}{Color.GREEN}{Color.BOLD}{title_line}{Color.END}{Color.PURPLE}{Color.BOLD}*{Color.END}")
    print(f"{Color.PURPLE}{Color.BOLD}*{Color.END}{Color.GREEN}{Color.BOLD}{author_line}{Color.END}{Color.PURPLE}{Color.BOLD}*{Color.END}")
    print(f"{Color.PURPLE}{Color.BOLD}*{Color.END}{Color.GREEN}{time_line_centered}{Color.END}{Color.PURPLE}{Color.BOLD}*{Color.END}")
    
    # Kapatma ve Alt Çizgi
    if is_welcome:
        print(f"{Color.PURPLE}{Color.BOLD}*{' ' * (WIDTH - 2)}*{Color.END}")
        
    print(f"{separator}\n")

def simple_progress_bar(iteration, total, prefix = '', length = 30):
    """Tek satırlık basit ilerleme çubuğunu basar."""
    if total > 0:
        percent = ("{0:.1f}").format(100 * (iteration / float(total)))
        filled_length = int(length * iteration // total)
        bar = '█' * filled_length + '░' * (length - filled_length)
        
        sys.stdout.write(f'\r{prefix} |{bar}| {percent}%')
        sys.stdout.flush()
        
        if iteration == total:
            sys.stdout.write('\n')
            sys.stdout.flush()

def progress_callback_wrapper():
    """simple_progress_bar için debounce mantığı eklenmiş sarmalayıcı."""
    last_update = 0
    def callback(current, total):
        nonlocal last_update
        # Her 0.3 saniyede bir veya total'e ulaşıldığında güncelle
        if time.time() - last_update > 0.3 or current == total:
            simple_progress_bar(current, total, prefix = f"{Color.PURPLE}Processing{Color.END}")
            last_update = time.time()
    return callback

def generate_test_log(filename, num_lines, format_type = 'apache'):
    """Test amaçlı rastgele log satırları oluşturur."""
    methods = ['GET', 'POST', 'PUT', 'DELETE']
    statuses = ['200', '404', '500', '301', '400', '403']
    paths = ['/', '/index.html', '/api/users', '/api/data', '/admin', '/login', '/products', '/cart']
    user_agents = ['Mozilla/5.0', 'Chrome/91.0', 'Safari/14.0', 'PostmanRuntime/7.28']
    
    start_time = datetime(2023, 10, 10, 9, 0, 0)
    
    with open(filename, 'w') as f:
        for i in range(num_lines):
            ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"
            timestamp = (start_time + timedelta(seconds = i * 2)).strftime('%d/%b/%Y:%H:%M:%S +0300')
            method = random.choice(methods)
            path = random.choice(paths)
            
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
                    'Failed password for root',
                    'CPU temperature above threshold',
                    'User login successful',
                    'Disk space warning'
                ]
                message = random.choice(messages)
                f.write(f'{timestamp} server1 {process}[{pid}]: {message}\n')
    
    return filename

def main():
    parser = argparse.ArgumentParser(
        description = f'{Color.GREEN}Log Analysis Toolkit{Color.END}',
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog = f"""
{Color.PURPLE}Examples:{Color.END}
  {Color.GREEN}python cli.py analyze access.log{Color.END}
  {Color.GREEN}python cli.py analyze access.log --mode aggressive --visualize{Color.END}
  {Color.GREEN}python cli.py visualize report.json{Color.END}
  {Color.GREEN}python cli.py generate-test --lines 5000 --output test.log{Color.END}
  {Color.GREEN}python cli.py info{Color.END}
        """
    )
    
    subparsers = parser.add_subparsers(dest = 'command', help = 'Commands')
    
    # analyze komutu (Renk eklendi)
    analyze_parser = subparsers.add_parser(
        'analyze', 
        help = f'{Color.GREEN}Analyze log file{Color.END}'
    )
    analyze_parser.add_argument('logfile', help = 'Path to log file')
    analyze_parser.add_argument('--mode', choices = ['auto', 'full', 'balanced', 'aggressive'], default = 'auto', help = 'Memory mode')
    analyze_parser.add_argument('--output', help = 'Custom output filename')
    analyze_parser.add_argument('--visualize', action = 'store_true', help = 'Generate visualization after analysis')
    analyze_parser.add_argument('--quiet', action = 'store_true', help = 'Suppress progress output')
    analyze_parser.add_argument('--validate', action = 'store_true', help = 'Enable strict validation')
    
    # visualize komutu (Renk eklendi)
    visualize_parser = subparsers.add_parser(
        'visualize', 
        help = f'{Color.GREEN}Visualize JSON report{Color.END}'
    )
    visualize_parser.add_argument('json_file', help = 'Path to JSON report file')
    visualize_parser.add_argument('--theme', choices = ['whitegrid', 'darkgrid', 'white', 'dark', 'ticks'], default = 'whitegrid')
    visualize_parser.add_argument('--palette', default = 'viridis')
    visualize_parser.add_argument('--size', choices = ['small', 'medium', 'large', 'xlarge'], default = 'medium')
    visualize_parser.add_argument('--dpi', type = int, default = 150)
    visualize_parser.add_argument('--no-values', action = 'store_true')
    visualize_parser.add_argument('--output-dir', default = 'reports')
    visualize_parser.add_argument('--title', help = 'Custom dashboard title')
    
    # generate-test komutu (Renk eklendi)
    generate_parser = subparsers.add_parser(
        'generate-test', 
        help = f'{Color.YELLOW}Generate test log file{Color.END}'
    )
    generate_parser.add_argument('--lines', type = int, default = 1000)
    generate_parser.add_argument('--output', required = True)
    generate_parser.add_argument('--format', choices = ['apache', 'nginx', 'json', 'syslog'], default = 'apache')
    generate_parser.add_argument('--overwrite', action = 'store_true')
    
    # info komutu (Renk eklendi)
    subparsers.add_parser(
        'info', 
        help = f'{Color.BLUE}Show system information{Color.END}'
    )
    
    args = parser.parse_args()
    
    if not args.command:
        # Karşılama Ekranı (Dinamik Genişlikli) + Yardım Menüsü
        print_header(is_welcome = True)
        parser.print_help()
        sys.exit(0)
    else:
        # Komut Başlığı (Dinamik Genişlikli)
        print_header(is_welcome = False)
    
    try:
        if args.command == 'analyze':
            try:
                from log_analyzer import analyze_log_optimized, AnalysisConfig
            except ImportError as e:
                print_error(f"log_analyzer.py not found: {e}")
                print_info("Make sure log_analyzer.py is in the same directory")
                sys.exit(1)
            
            if not os.path.exists(args.logfile):
                print_error(f"File not found: {args.logfile}")
                sys.exit(1)
            
            print_info(f"Analyzing: {args.logfile}")
            print_info(f"Mode: {args.mode}")
            
            config = AnalysisConfig(
                memory_mode = args.mode if args.mode != 'auto' else 'auto',
                validate = args.validate,
                quiet = args.quiet
            )
            
            if not args.quiet:
                print(f"{Color.PURPLE}Starting analysis...{Color.END}")
                progress_cb = progress_callback_wrapper()
            else:
                progress_cb = None
            
            start_time = time.time()
            stats = analyze_log_optimized(args.logfile, config, progress_cb)
            elapsed = time.time() - start_time
            stats['elapsed_time'] = elapsed # Analiz süresini istatistiklere ekle
            
            if not args.quiet:
                print()
            
            if 'error' in stats:
                print_error(f"Analysis failed: {stats['error']}")
                sys.exit(1)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = args.output if args.output else f"log_analysis_{timestamp}.json"
            
            with open(output_file, 'w') as f:
                json.dump(stats, f, indent = 2)
            
            print_success(f"Analysis completed in {elapsed:.2f} seconds")
            print_info(f"Report saved to: {output_file}")
            print_info(f"Total lines processed: {stats['summary']['total_lines']:,}")
            print_info(f"Valid requests: {stats['summary']['total_requests']:,}")
            print_info(f"Success rate: {stats['health_metrics']['success_rate_2xx_3xx']}")
            
            if args.visualize:
                print_info("Generating visualization...")
                try:
                    from log_visualizer import visualize_results, VisualizationConfig
                    viz_config = VisualizationConfig(output_dir = "reports")
                    viz_file = visualize_results(stats, viz_config, f"dashboard_{timestamp}")
                    print_success(f"Visualization saved to: {viz_file}")
                except ImportError:
                    print_warning("log_visualizer.py or its dependencies (matplotlib, seaborn) not found, skipping visualization")
        
        elif args.command == 'visualize':
            try:
                from log_visualizer import visualize_results, load_stats_from_json, VisualizationConfig
            except ImportError as e:
                print_error(f"log_visualizer.py not found: {e}")
                print_info("Make sure log_visualizer.py and its dependencies are installed")
                sys.exit(1)
            
            if not os.path.exists(args.json_file):
                print_error(f"File not found: {args.json_file}")
                sys.exit(1)
            
            print_info(f"Visualizing: {args.json_file}")
            print_info(f"Theme: {args.theme}")
            print_info(f"Size: {args.size}")
            
            stats = load_stats_from_json(args.json_file)
            
            config = VisualizationConfig(
                theme = args.theme,
                palette = args.palette,
                fig_size = args.size,
                dpi = args.dpi,
                show_values = not args.no_values,
                output_dir = args.output_dir,
                custom_title = args.title
            )
            
            output_file = visualize_results(
                stats,
                config,
                f"dashboard_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            )
            
            print_success("Visualization completed!")
            print_info(f"Dashboard saved to: {output_file}")
        
        elif args.command == 'generate-test':
            print_info("Generating test log...")
            print_info(f"Lines: {args.lines:,}")
            print_info(f"Format: {args.format}")
            print_info(f"Output: {args.output}")
            
            output_dir = os.path.dirname(args.output)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir, exist_ok = True)
            
            if os.path.exists(args.output) and not args.overwrite:
                print_error(f"File already exists: {args.output}")
                print_info("Use --overwrite flag to overwrite")
                sys.exit(1)
            
            print(f"{Color.PURPLE}Generating {args.lines:,} lines...{Color.END}")
            test_file = generate_test_log(
                filename = args.output,
                num_lines = args.lines,
                format_type = args.format
            )
            
            file_size = os.path.getsize(test_file)
            print_success("Test log generated successfully!")
            print_info(f"File: {test_file}")
            print_info(f"Size: {file_size / 1024:.1f} KB")
            print_info(f"Lines: {args.lines:,}")
            
            print_info("Sample of first 3 lines:")
            with open(test_file, 'r') as f:
                for i, line in enumerate(f):
                    if i >= 3:
                        break
                    print(f"  {Color.GREEN}{line.strip()}{Color.END}")
        
        elif args.command == 'info':
            print_info("SYSTEM INFORMATION")
            print(f"{Color.PURPLE}{'=' * 40}{Color.END}")
            print(f"{Color.GREEN}Python: {platform.python_version()}{Color.END}")
            print(f"{Color.GREEN}OS: {platform.system()} {platform.release()}{Color.END}")
            
            try:
                import psutil
                print(f"{Color.GREEN}CPU: {psutil.cpu_count()} cores{Color.END}")
                print(f"{Color.GREEN}Memory: {psutil.virtual_memory().total / 1024**3:.1f} GB{Color.END}")
                print(f"{Color.GREEN}Disk: {psutil.disk_usage('/').free / 1024**3:.1f} GB free{Color.END}")
            except ImportError:
                print_warning("Install psutil for detailed system info: pip install psutil")
            
            print(f"\n{Color.GREEN}INSTALLED PACKAGES{Color.END}")
            print(f"{Color.PURPLE}{'=' * 40}{Color.END}")
            packages = ['matplotlib', 'seaborn', 'pandas', 'numpy']
            for pkg in packages:
                try:
                    module = __import__(pkg)
                    version = getattr(module, '__version__', 'unknown')
                    print(f"{Color.GREEN}✓ {pkg}: {version}{Color.END}")
                except ImportError:
                    print(f"{Color.RED}✗ {pkg}: Not installed{Color.END}")
    
    except KeyboardInterrupt:
        print(f"\n{Color.YELLOW}Operation cancelled by user{Color.END}")
        sys.exit(0)
    except Exception as e:
        print_error(f"An unexpected error occurred: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
