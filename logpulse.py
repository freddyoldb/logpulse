#!/usr/bin/env python3
"""
LogPulse - Standalone High-Performance Log & Security Analyzer
Zero Dependencies. Pure Python 3.8+
"""

import os
import re
import sys
import json
import time
from collections import Counter
from datetime import datetime

# Common Attack Patterns
SECURITY_PATTERNS = {
    "SQL Injection": re.compile(r"(?i)(UNION\s+SELECT|SELECT\s+.*\s+FROM|INSERT\s+INTO|DROP\s+TABLE|OR\s+1=1|' OR ')"),
    "Path Traversal": re.compile(r"(\.\./\.\./|\.\.\\\.\.\\|/etc/passwd|/etc/shadow)"),
    "XSS Attack": re.compile(r"(?i)(<script>|javascript:|onerror=|onload=)"),
    "Command Injection": re.compile(r"(;|\|\||&&)\s*(wget|curl|nc|bash|sh|exec)\s+"),
    "Sensitive File Access": re.compile(r"(\.env|\.git/config|\.htaccess|wp-config\.php)")
}

LOG_REGEX = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)\s*(?P<protocol>[^"]*)" (?P<status>\d{3}) (?P<bytes>\d+|-)'
)

def parse_line(line):
    match = LOG_REGEX.match(line)
    if not match:
        return None
    data = match.groupdict()
    data['status'] = int(data['status'])
    data['bytes'] = int(data['bytes']) if data['bytes'] != '-' else 0
    return data

def analyze_log(file_path):
    if not os.path.exists(file_path):
        print(f"\033[91mError: File '{file_path}' not found.\033[0m")
        sys.exit(1)

    print(f"\033[94m[+] Analyzing: {file_path}...\033[0m")
    start_time = time.time()

    total_requests = 0
    total_bytes = 0
    status_codes = Counter()
    ips = Counter()
    paths = Counter()
    threats = []

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, start=1):
            total_requests += 1
            
            # Security Scanning
            for threat_type, pattern in SECURITY_PATTERNS.items():
                if pattern.search(line):
                    threats.append({
                        "line": line_num,
                        "type": threat_type,
                        "raw": line.strip()[:150]
                    })

            # Structured Log Parsing
            parsed = parse_line(line)
            if parsed:
                status_codes[parsed['status']] += 1
                ips[parsed['ip']] += 1
                paths[parsed['path']] += 1
                total_bytes += parsed['bytes']

    elapsed = time.time() - start_time

    # Console Output
    print(f"\n\033[92m=== LOGPULSE SUMMARY ===\033[0m")
    print(f"Processed:     {total_requests:,} lines in {elapsed:.2f}s ({int(total_requests/(elapsed+0.0001)):,} lines/sec)")
    print(f"Total Traffic: {total_bytes / (1024*1024):.2f} MB")
    print(f"Unique IPs:    {len(ips)}")
    
    print("\n\033[1mTop IP Addresses:\033[0m")
    for ip, count in ips.most_common(5):
        print(f"  {ip:<15} -> {count:,} requests")

    print("\n\033[1mHTTP Status Codes:\033[0m")
    for status, count in sorted(status_codes.items()):
        color = "\033[92m" if status < 400 else "\033[91m"
        print(f"  {color}{status}\033[0m: {count:,}")

    if threats:
        print(f"\n\033[91m[!] SECURITY WARNING: {len(threats)} potential threats detected!\033[0m")
        for t in threats[:5]:
            print(f"  Line {t['line']}: \033[93m[{t['type']}]\033[0m {t['raw']}")
        if len(threats) > 5:
            print(f"  ...and {len(threats) - 5} more threats.")
    else:
        print("\n\033[92m[✓] No obvious security threats detected.\033[0m")

    # Generate JSON Report
    report = {
        "timestamp": datetime.now().isoformat(),
        "file": file_path,
        "performance": {"seconds": elapsed, "lines_per_sec": int(total_requests/(elapsed+0.0001))},
        "stats": {
            "total_requests": total_requests,
            "total_mb": round(total_bytes / (1024*1024), 2),
            "unique_ips": len(ips),
            "status_codes": dict(status_codes),
            "top_ips": dict(ips.most_common(10)),
            "top_paths": dict(paths.most_common(10))
        },
        "threats": threats
    }

    report_name = f"logpulse_report_{int(time.time())}.json"
    with open(report_name, 'w', encoding='utf-8') as rf:
        json.dump(report, rf, indent=2)

    print(f"\n\033[94m[+] Detailed JSON report saved to '{report_name}'\033[0m")

def generate_sample_log():
    sample_file = "sample_access.log"
    print(f"[+] Generating sample log file '{sample_file}' for testing...")
    sample_lines = [
        '192.168.1.10 - - [10/Oct/2026:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326',
        '10.0.0.5 - - [10/Oct/2026:13:55:37 +0000] "POST /login HTTP/1.1" 200 512',
        '192.168.1.15 - - [10/Oct/2026:13:55:38 +0000] "GET /admin/db.php?id=1%20OR%201=1 HTTP/1.1" 403 128',
        '172.16.0.4 - - [10/Oct/2026:13:55:40 +0000] "GET /../../etc/passwd HTTP/1.1" 404 280',
        '192.168.1.10 - - [10/Oct/2026:13:55:41 +0000] "GET /styles.css HTTP/1.1" 200 5412',
        '10.0.0.5 - - [10/Oct/2026:13:55:42 +0000] "GET /<script>alert(1)</script> HTTP/1.1" 400 150',
    ] * 50
    with open(sample_file, 'w') as f:
        f.write("\n".join(sample_lines))
    return sample_file

if __name__ == "__main__":
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = generate_sample_log()
    
    analyze_log(log_file)
