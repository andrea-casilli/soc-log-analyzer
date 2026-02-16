# SOC Log Analyzer

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

A SOC-style log analyzer for Linux auth.log (SSH) and web server access logs (Apache/Nginx). Identifies suspicious IPs based on failed authentication attempts.
## Installation

```bash
# Clone the repository
git clone https://github.com/Andrea2137/soc-log-analyzer.git
cd soc-log-analyzer

# No installation required! Just run the script
## Features

- Dual log support: Parse both auth.log (SSH events) and web access logs
- Suspicious IP detection: Identify IPs exceeding failed attempt thresholds
- JSON reporting: Detailed statistics and event analysis
- CSV export: Export suspicious IPs for further investigation
- No dependencies: Single-file Python script, just download and run

## Quick Start
