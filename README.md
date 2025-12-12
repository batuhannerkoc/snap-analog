# 📊 snap-analog

### Advanced Log Analysis & Visualization Toolkit for Apache Logs

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)](https://github.com/batuhannerkoc/snap-analog)
[![Status](https://img.shields.io/badge/Status-Active-success)](https://github.com/batuhannerkoc/snap-analog)

**snap-analog** is a powerful command-line toolkit for parsing, analyzing, optimizing, and visualizing large-scale Apache log files. It generates both beautiful visual dashboards and structured JSON datasets, making it perfect for DevOps monitoring, security analysis, and data analytics pipelines.

## 📑 Quick Links

⚡ [Quick Start](#-quick-start) •
🚀 [Features](#-features) •
🎯 [Use Cases](#-use-cases) •
📦 [Installation](#-installation) •
🧪 [Usage](#-usage-examples) •
📊 [JSON Output](#-json-output-example) •
💡 [Performance](#-performance-benchmarks) •
🎨 [Visualization Features](#-visualization-features) •
🧑‍💻 [Development](#-development) •
🤝 [Contributing](#-contributing) •
📜 [License](#-license) •
🌟 [Roadmap](#-roadmap) •
📞 [Support & Contact](#-support--contact) •
⭐ [Show Your Support](#-show-your-support)

---

## ⚡ Quick Start

```bash
# Install
git clone https://github.com/batuhannerkoc/snap-analog.git
cd snap-analog
pip install .

# Generate test data
snap-analog generate-test --lines 5000 --output test.log

# Analyze & visualize
snap-analog analyze test.log --visualize

# View dashboard in: reports/dashboard_*.png
```

**That's it!** 🎉

---

## 📸 Screenshots

### Dashboard Visualization
![Dashboard Example](images/dashboard.png)

### Terminal Output
![Terminal UI](images/terminal.png)

---

## 🚀 Features

- 🔍 **High-performance log parsing** — optimized for millions of lines
- 💾 **Memory-optimized modes** — `auto`, `balanced`, `full`, `aggressive`
- 📈 **JSON export** — structured data for analytics pipelines and dashboards
- 🎨 **Beautiful visualizations** — powered by Matplotlib + Seaborn
- 🧠 **Traffic insights** — top IPs, URLs, methods, status groups, time-series
- ⚠️ **Error rate detection** — automatic threshold alerts
- 🧪 **Test log generator** — built-in random data generation
- 🛠 **Modern CLI** — colorful output with progress bars
- 📊 **6 chart types** — pie charts, bar charts, time-series, heatmaps

---

## 🎯 Use Cases

| Use Case | Description |
|----------|-------------|
| 🖥 **Web Server Monitoring** | Track traffic patterns, identify bottlenecks |
| 🔒 **Security Analysis** | Detect suspicious IPs, analyze attack patterns |
| 📊 **SRE/DevOps Dashboards** | Feed data into Grafana, Kibana, or custom tools |
| 🚀 **API Performance Tracking** | Monitor endpoint response times and error rates |
| 📉 **Data Analytics** | Preprocess logs for ML pipelines |
| 🧪 **Performance Testing** | Generate realistic test data at scale |

---

## 📦 Installation

### ✔ Option 1 — Virtual Environment (Recommended)

```bash
git clone https://github.com/batuhannerkoc/snap-analog.git
cd snap-analog

python3 -m venv venv
source venv/bin/activate  # macOS/Linux
# .\venv\Scripts\activate # Windows

pip install -r requirements.txt
pip install .
```

Verify installation:
```bash
snap-analog --help
```

### ✔ Option 2 — Direct Install

```bash
pip install .
```

If you encounter "externally managed environment" error:
```bash
pip install --user .
```

### ✔ Option 3 — Development Mode

```bash
pip install -e .
```

---

## 🧪 Usage Examples

### Generating Test Logs

```bash
# Apache format
snap-analog generate-test --lines 5000 --output logs/test.log --format apache

# JSON format
snap-analog generate-test --format json --lines 3000 --output logs/sample.json
```

### Analyzing Logs

```bash
# Basic analysis
snap-analog analyze access.log

# With visualization
snap-analog analyze access.log --visualize

# Aggressive memory mode (for huge files)
snap-analog analyze access.log --mode aggressive

# Custom output path
snap-analog analyze access.log --output reports/result.json

# Quiet mode (no terminal output)
snap-analog analyze access.log --quiet
```

### Visualizing Reports

```bash
# Basic visualization
snap-analog visualize reports/log_analysis_20250101_120000.json

# Custom theme and size
snap-analog visualize report.json --theme darkgrid --size large --dpi 200
```

---

## 📊 JSON Output Example

```json
{
  "summary": {
    "total_lines": 50214,
    "total_requests": 48711,
    "memory_mode": "balanced",
    "file": "access.log",
    "analysis_date": "2025-01-12T10:30:45"
  },
  "health_metrics": {
    "success_rate_2xx_3xx": "94.1%",
    "client_error_rate_4xx": "3.2%",
    "server_error_rate_5xx": "2.7%"
  },
  "traffic_analysis": {
    "top_ips": [
      {"ip": "192.168.1.1", "count": 1250},
      {"ip": "10.0.0.5", "count": 980}
    ],
    "top_urls": [
      {"url": "/api/users", "count": 5420},
      {"url": "/home", "count": 3210}
    ],
    "methods": {
      "GET": 35420,
      "POST": 8940,
      "PUT": 2130,
      "DELETE": 1221
    }
  },
  "elapsed_time": 3.51
}
```

**📄 Full Schema:** [View complete JSON structure](docs/json_schema.md)

---

## 🏗 Project Structure

```
snap-analog/
│
├── src/
│   ├── cli.py                # Main CLI entry point
│   ├── log_analyzer.py       # Memory-optimized analyzer
│   └── log_visualizer.py     # Dashboard generator
│
├── images/
│   ├── dashboard.png         # Dashboard screenshot
│   └── terminal.png          # Terminal UI screenshot
│
├── sample_logs/                     # Sample Log files
├── requirements.txt
├── setup.py
├── LICENSE
└── README.md
```

---

## ⚙️ Requirements

```
matplotlib>=3.5.0
seaborn>=0.12.0
pandas>=1.4.0
numpy>=1.22.0
psutil>=5.9.0  # optional, for system info
```

Install all dependencies:
```bash
pip install -r requirements.txt
```

---

## 💡 Performance Benchmarks

Tested on: MacBook Pro M4, 16GB RAM

| Log Size | Lines | Mode | Time | Memory |
|----------|-------|------|------|--------|
| Small | 10K | auto | 0.5s | 45 MB |
| Medium | 100K | balanced | 2.1s | 120 MB |
| Large | 1M | balanced | 8.4s | 380 MB |
| Huge | 10M | aggressive | 42s | 850 MB |

---

## 🎨 Visualization Features

The dashboard includes:

1. **Status Groups Pie Chart** — 2xx, 3xx, 4xx, 5xx distribution
2. **Top IPs Bar Chart** — Most active IP addresses
3. **Top URLs Bar Chart** — Most requested endpoints
4. **Time-Series Traffic** — Requests over time
5. **HTTP Methods Distribution** — GET, POST, PUT, DELETE breakdown
6. **Error Rate Heatmap** — Visual error rate indicators

All visualizations support:
- Custom themes (`white`, `dark`, `darkgrid`, `whitegrid`)
- Adjustable DPI (72, 100, 150, 200, 300)
- Multiple sizes (`small`, `medium`, `large`, `xlarge`)

---

## 🧑‍💻 Development

### Editable Install

```bash
git clone https://github.com/batuhannerkoc/snap-analog.git
cd snap-analog
pip install -e .
```

### Run CLI Directly

```bash
python3 src/cli.py analyze logs/test.log
```

### Code Style

This project follows [Black](https://github.com/psf/black) code style:

```bash
pip install black
black src/
```

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

For bug reports or feature requests, please [open an issue](https://github.com/batuhannerkoc/snap-analog/issues).

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 Batuhan Erkoc

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 🌟 Roadmap

- [ ] Support for Nginx logs
- [ ] Real-time monitoring mode (`snap-analog watch`)
- [ ] HTML report generation
- [ ] CSV export option
- [ ] Docker image
- [ ] PyPI package (`pip install snap-analog`)
- [ ] Filtering capabilities (`--filter "status=500"`)
- [ ] Log comparison tool

---

## 📞 Support & Contact

- **GitHub Issues:** [Report bugs or request features](https://github.com/batuhannerkoc/snap-analog/issues)
- **Email:** [batuhannerkoc@gmail.com](mailto:batuhannerkoc@gmail.com)
- **LinkedIn:** [Batuhan Erkoc](https://www.linkedin.com/in/batuhan-erkoç-aa618224a/)

---

## ⭐ Show Your Support

If you find this project useful, please consider:
- ⭐ Starring the repository
- 🐛 Reporting bugs
- 💡 Suggesting new features
- 🔀 Contributing code

---

<div align="center">

**Developed with ❤️ by [Batuhan Erkoc](https://github.com/batuhannerkoc)**

[![GitHub followers](https://img.shields.io/github/followers/batuhannerkoc?style=social)](https://github.com/batuhannerkoc)
[![GitHub stars](https://img.shields.io/github/stars/batuhannerkoc/snap-analog?style=social)](https://github.com/batuhannerkoc/snap-analog/stargazers)

</div>

