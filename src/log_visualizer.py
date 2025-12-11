import json
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from datetime import datetime
import sys
import os

class VisualizationConfig:
    def __init__(self, theme="whitegrid", palette="viridis", fig_size="medium", dpi=150, show_values=True, output_dir="reports", custom_title=None):
        self.theme = theme
        self.palette = palette
        self.fig_size = fig_size
        self.dpi = dpi
        self.show_values = show_values
        self.output_dir = output_dir
        self.custom_title = custom_title
        
        self.size_map = {
            'small': (12, 10), 
            'medium': (18, 15), 
            'large': (20, 16), 
            'xlarge': (24, 18)
        }

def load_stats_from_json(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: JSON file not found at {filepath}")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON format in {filepath}")
        sys.exit(1)

def parse_minute_safe(minute_str):
    formats = ["%Y-%m-%d %H:%M", "%d/%b/%Y:%H:%M", "%H:%M", "%Y-%m-%d %H:%M:%S"]
    for fmt in formats:
        try:
            return datetime.strptime(minute_str, fmt)
        except ValueError:
            continue
    return None

def create_memory_plot(ax, stats):
    mem_stats = stats["memory_optimization"]["tracker_stats"]
    
    data = []
    for tracker_name, tracker_info in mem_stats.items():
        if 'unique_items' in tracker_info:
            data.append({
                "Tracker": tracker_name.upper(),
                "Unique Items": tracker_info["unique_items"],
                "Mode": tracker_info.get("mode", "TOP_K")
            })
    
    if not data:
        ax.text(0.5, 0.5, "No memory data available", ha='center', va='center', fontsize=12)
        ax.set_title("Memory Usage", fontsize=12, pad=20)
        return
    
    df_mem = pd.DataFrame(data)
    
    bars = sns.barplot(x="Tracker", y="Unique Items", data=df_mem, ax=ax, palette="Blues_r")
    
    ax.set_title("Unique Items Tracked", fontsize=12, pad=20)
    ax.set_xlabel("Tracker Type", fontweight='bold')
    ax.set_ylabel("Count", fontweight='bold')
    
    for i, bar in enumerate(bars.patches):
        height = bar.get_height()
        if height > 0:
            ax.text(bar.get_x() + bar.get_width()/2., height + (height * 0.01), f'{int(height):,}', ha='center', va='bottom', fontsize=9)
    
    for i, row in df_mem.iterrows():
        ax.text(i, -max(df_mem["Unique Items"]) * 0.05, f'Mode: {row["Mode"]}', ha='center', va='top', fontsize=8, style='italic')

def create_error_rate_chart(ax, stats):
    try:
        success_rate = float(stats["health_metrics"]["success_rate_2xx_3xx"].rstrip('%'))
        client_error_rate = float(stats["health_metrics"]["client_error_rate_4xx"].rstrip('%'))
        server_error_rate = float(stats["health_metrics"]["server_error_rate_5xx"].rstrip('%'))
    except:
        success_rate = client_error_rate = server_error_rate = 0
    
    rates = [success_rate, client_error_rate, server_error_rate]
    labels = ['Success\n(2xx/3xx)', 'Client Errors\n(4xx)', 'Server Errors\n(5xx)']
    colors = ['#06D6A0', '#FFD166', '#EF476F']
    
    bars = ax.bar(labels, rates, color=colors, edgecolor='black', linewidth=1.5)
    
    ax.set_title("Error Rate Analysis", fontsize=12, fontweight='bold', pad=20)
    ax.set_ylabel("Percentage (%)", fontweight='bold')
    
    max_rate = max(rates) if max(rates) > 0 else 100
    ax.set_ylim(0, max_rate * 1.3)
    
    for bar, rate in zip(bars, rates):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height + 1, f'{rate:.1f}%', ha='center', va='bottom', fontsize=10, fontweight='bold')
        
        if rate > 5 and bar.get_label() in ['Client Errors\n(4xx)', 'Server Errors\n(5xx)']:
            bar.set_edgecolor('darkred')
            bar.set_linewidth(3)
            bar.set_alpha(0.9)
            ax.text(bar.get_x() + bar.get_width()/2., height + (max_rate * 0.05), 'HIGH!', ha='center', va='bottom', color='darkred', fontsize=9, fontweight='bold')
    
    ax.axhline(y=5, color='darkred', linestyle='--', linewidth=2, alpha=0.7, label='5% Error Threshold')
    ax.axhspan(5, max_rate * 1.3, alpha=0.1, color='red', label='High Error Zone')
    
    if server_error_rate > 5 or client_error_rate > 5:
        warning_text = 'WARNING: High Error Rates!\n'
        if server_error_rate > 5:
            warning_text += f'Server: {server_error_rate:.1f}% '
        if client_error_rate > 5:
            warning_text += f'Client: {client_error_rate:.1f}%'
        
        ax.text(0.02, 0.98, warning_text, transform=ax.transAxes, color='darkred', fontsize=10, fontweight='bold', verticalalignment='top', bbox=dict(boxstyle="round,pad=0.5", facecolor="yellow", alpha=0.4))
    
    ax.legend(loc='upper right', fontsize=9, framealpha=0.9)

def visualize_results(stats, config=None, output_filename_base="log_analysis_dashboard"):
    if config is None:
        config = VisualizationConfig()
    
    os.makedirs(config.output_dir, exist_ok=True)
    
    plt.rcParams['font.family'] = 'DejaVu Sans'
    sns.set_theme(style=config.theme)
    fig_size = config.size_map.get(config.fig_size, (18, 15))
    
    fig = plt.figure(figsize=fig_size)
    
    if config.custom_title:
        main_title = config.custom_title
    else:
        main_title = (f"Log Analysis Dashboard | Total Requests: {stats['summary']['total_requests']:,} | "
                     f"Mode: {stats['summary']['memory_mode']} | "
                     f"File: {os.path.basename(stats['summary']['file'])}")
    
    fig.suptitle(main_title, fontsize=14, fontweight="bold", y=0.98)
    
    ax1 = fig.add_subplot(3, 2, 1)
    ax2 = fig.add_subplot(3, 2, 2)
    ax3 = fig.add_subplot(3, 2, 3)
    ax4 = fig.add_subplot(3, 2, 4)
    ax5 = fig.add_subplot(3, 2, 5)
    ax6 = fig.add_subplot(3, 2, 6)
    
    groups = stats["health_metrics"]["status_groups"]
    labels = [k for k, v in groups.items() if v > 0 and k != "Unknown"]
    sizes = [v for k, v in groups.items() if v > 0 and k != "Unknown"]
    
    colors = ["mediumseagreen" if k.startswith("2") else "skyblue" if k.startswith("3") else "salmon" if k.startswith("4") else "lightcoral" for k in labels]
    
    total = sum(sizes)
    if total > 0:
        threshold = total * 0.05
        
        main_labels = []
        main_sizes = []
        main_colors = []
        other_size = 0
        
        for label, size, color in zip(labels, sizes, colors):
            if size >= threshold:
                main_labels.append(f'{label}\n({size/total:.1%})')
                main_sizes.append(size)
                main_colors.append(color)
            else:
                other_size += size
        
        if other_size > 0:
            main_labels.append(f'Other\n({other_size/total:.1%})')
            main_sizes.append(other_size)
            main_colors.append('lightgray')
        
        wedges, texts = ax1.pie(main_sizes, labels=main_labels, autopct=None, startangle=90, colors=main_colors, textprops={'color': 'black', 'fontweight': 'bold', 'fontsize': 9})
        
        ax1.set_title("HTTP Status Groups", fontsize=11, fontweight='bold', pad=20)
        ax1.axis('equal')
    
    top_ips_data = stats["traffic_analysis"]["top_ips"]
    df_ips = pd.DataFrame(top_ips_data, columns=["IP Address", "Count"])
    
    if not df_ips.empty:
        sns.barplot(x="Count", y="IP Address", data=df_ips, ax=ax2, palette=config.palette + "_r", hue="IP Address", legend=False, dodge=False)
        
        ax2.set_title(f"Top {len(df_ips)} IP Addresses", fontsize=11, fontweight='bold', pad=20)
        ax2.set_xlabel("Request Count", fontweight='bold')
        ax2.set_ylabel("IP Address", fontweight='bold')
        
        if len(df_ips) > 0:
            top_ip_count = df_ips.iloc[0]["Count"]
            total_reqs = stats["summary"]["total_requests"]
            if total_reqs > 0:
                percentage = (top_ip_count / total_reqs) * 100
                if percentage > 10:
                    ax2.annotate(f'{percentage:.1f}% of total', xy=(top_ip_count, 0), xytext=(top_ip_count*1.1, 0), arrowprops=dict(arrowstyle="->", color='darkred', lw=2), fontsize=9, fontweight='bold')
    
    top_urls_data = stats["traffic_analysis"]["top_urls"]
    df_urls = pd.DataFrame(top_urls_data, columns=["URL Path", "Count"])
    
    if not df_urls.empty:
        df_urls["URL Path Short"] = df_urls["URL Path"].apply(lambda x: (x[:35] + '...') if len(x) > 38 else x)
        
        sns.barplot(x="Count", y="URL Path Short", data=df_urls, ax=ax3, palette="mako_r", hue="URL Path Short", legend=False, dodge=False)
        
        ax3.set_title(f"Top {len(df_urls)} URLs", fontsize=11, fontweight='bold', pad=20)
        ax3.set_xlabel("Request Count", fontweight='bold')
        ax3.set_ylabel("URL Path", fontweight='bold')
    
    minutes_data = stats["traffic_analysis"]["top_minutes"]
    
    has_time_data = False
    if minutes_data:
        parsed_data = []
        for minute_str, count in minutes_data:
            dt = parse_minute_safe(minute_str)
            if dt:
                parsed_data.append((dt, count))
        
        if parsed_data:
            sorted_minutes = sorted(parsed_data, key=lambda x: x[0])
            df_minutes = pd.DataFrame(sorted_minutes, columns=["Minute", "Count"])
            
            if not df_minutes.empty:
                sns.lineplot(x="Minute", y="Count", data=df_minutes, ax=ax4, marker="o", color="darkorange", linewidth=2.5)
                
                ax4.tick_params(axis='x', rotation=45)
                ax4.grid(True, alpha=0.3)
                
                start = df_minutes['Minute'].min()
                end = df_minutes['Minute'].max()
                time_range = f"{start.strftime('%H:%M')} - {end.strftime('%H:%M')}"
                if (end - start).days > 0:
                    time_range = f"{start.strftime('%Y-%m-%d')} to {end.strftime('%Y-%m-%d')}"
                
                ax4.set_title(f"Traffic Trend - {time_range}", fontsize=11, fontweight='bold', pad=20)
                ax4.set_xlabel("Time", fontweight='bold')
                ax4.set_ylabel("Request Count", fontweight='bold')
                has_time_data = True
    
    if not has_time_data:
        ax4.text(0.5, 0.5, "No time series data available", ha='center', va='center', fontsize=11)
        ax4.set_title("Traffic Trend", fontsize=11, fontweight='bold', pad=20)
        ax4.axis('off')
    
    methods_data = stats["traffic_analysis"]["methods"]
    df_methods = pd.DataFrame(methods_data.items(), columns=["Method", "Count"])
    
    if not df_methods.empty:
        sns.barplot(x="Method", y="Count", data=df_methods, ax=ax5, palette="Set2", hue="Method", legend=False, dodge=False)
        
        ax5.set_title("HTTP Method Distribution", fontsize=11, fontweight='bold', pad=20)
        ax5.set_xlabel("HTTP Method", fontweight='bold')
        ax5.set_ylabel("Request Count", fontweight='bold')
        
        if config.show_values:
            for i, bar in enumerate(ax5.patches):
                height = bar.get_height()
                if height > 0:
                    ax5.text(bar.get_x() + bar.get_width()/2., height + (height * 0.02), f'{int(height):,}', ha='center', va='bottom', fontsize=9)
    
    create_error_rate_chart(ax6, stats)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_filename = f"{output_filename_base}_{timestamp}.png"
    output_path = os.path.join(config.output_dir, output_filename)
    
    plt.subplots_adjust(hspace=0.35, wspace=0.25, top=0.94, bottom=0.06)
    plt.tight_layout(rect=[0, 0.03, 1, 0.96])
    
    try:
        plt.savefig(output_path, dpi=config.dpi, bbox_inches='tight')
        print(f"Dashboard saved to: {output_path}")
        
        json_output = os.path.join(config.output_dir, f"dashboard_data_{timestamp}.json")
        with open(json_output, 'w') as f:
            json.dump({
                "visualization_created": timestamp,
                "source_json": stats['summary']['file'],
                "chart_count": 6,
                "output_path": output_path
            }, f, indent=2)
        print(f"Metadata saved to: {json_output}")
        
    except Exception as e:
        print(f"Failed to save visualization: {e}")
    
    plt.close(fig)
    return output_path

if __name__ == "__main__":
    if len(sys.argv) > 1:
        json_file = sys.argv[1]
        if not os.path.exists(json_file):
            print(f"Error: File not found: {json_file}")
            sys.exit(1)
    else:
        print("Usage: python log_visualizer.py <path_to_json_report>")
        sys.exit(1)
    
    stats_data = load_stats_from_json(json_file)
    
    if stats_data:
        output_file = visualize_results(stats_data)
        if output_file:
            print(f"Visualization completed!")
            print(f"Output: {output_file}")
