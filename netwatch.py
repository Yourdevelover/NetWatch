#!/usr/bin/env python3
"""
NetWatch - Alat Monitoring Jaringan LAN Lokal
==============================================
Fitur:
- Memindai perangkat aktif di jaringan LAN
- Mengecek status koneksi internet
- Troubleshooting otomatis (ping, DNS, traceroute)
- Mencatat log aktivitas jaringan
- Menampilkan hasil dalam bentuk HTML statis
"""

import subprocess
import socket
import ipaddress
import datetime
import platform
import re
import json
import os
import sys
import threading
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed

# ============================================================
# KONFIGURASI
# ============================================================

REPORT_FILENAME = "netwatch.html"

# Warna untuk output terminal
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

# ============================================================
# FUNGSI UTILITY
# ============================================================

def get_timestamp():
    """Mengembalikan timestamp format: YYYY-MM-DD HH:MM:SS"""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def get_local_ip():
    """Mendapatkan IP lokal dan subnet mask"""
    try:
        # Windows
        if platform.system() == "Windows":
            result = subprocess.run(
                ["ipconfig"], capture_output=True, text=True, timeout=10
            )
            # Cari IPv4 Address
            ip_match = re.search(r"IPv4 Address[.\s]*:[\s]*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", result.stdout)
            mask_match = re.search(r"Subnet Mask[.\s]*:[\s]*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", result.stdout)
            
            local_ip = ip_match.group(1) if ip_match else "127.0.0.1"
            subnet_mask = mask_match.group(1) if mask_match else "255.255.255.0"
            
            # Hitung prefix length dari subnet mask
            mask_bits = sum(bin(int(x)).count('1') for x in subnet_mask.split('.'))
            
            return local_ip, subnet_mask, mask_bits
        else:
            # Linux/Mac
            result = subprocess.run(
                ["ip", "-4", "addr", "show"], capture_output=True, text=True, timeout=10
            )
            ip_match = re.search(r"inet\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/([0-9]+)", result.stdout)
            if ip_match:
                local_ip = ip_match.group(1)
                prefix = int(ip_match.group(2))
                # Konversi prefix ke subnet mask
                mask_bits = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
                subnet_mask = ".".join([str((mask_bits >> (8 * (3 - i))) & 0xFF) for i in range(4)])
                return local_ip, subnet_mask, prefix
            
            return "127.0.0.1", "255.255.255.0", 24
    except Exception as e:
        print(f"{Colors.YELLOW}[!] Gagal mendapatkan IP lokal: {e}{Colors.END}")
        return "192.168.1.1", "255.255.255.0", 24


def get_gateway():
    """Mendapatkan IP gateway default"""
    try:
        if platform.system() == "Windows":
            result = subprocess.run(
                ["ipconfig"], capture_output=True, text=True, timeout=10
            )
            gw_match = re.search(r"Default Gateway[.\s]*:[\s]*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", result.stdout)
            if gw_match:
                return gw_match.group(1)
        else:
            result = subprocess.run(
                ["ip", "route", "show", "default"], capture_output=True, text=True, timeout=10
            )
            gw_match = re.search(r"default via\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", result.stdout)
            if gw_match:
                return gw_match.group(1)
    except:
        pass
    
    # Fallback: tebak dari IP lokal
    local_ip, _, _ = get_local_ip()
    parts = local_ip.split('.')
    return f"{parts[0]}.{parts[1]}.{parts[2]}.1"


def get_hostname(ip_address):
    """Mendapatkan hostname dari IP address"""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except:
        return "Tidak diketahui"


def get_mac_address(ip_address):
    """Mendapatkan MAC address dari IP (Windows)"""
    try:
        if platform.system() == "Windows":
            result = subprocess.run(
                ["arp", "-a", ip_address], capture_output=True, text=True, timeout=5
            )
            # Format: Interface: ... Internet Address ... Physical Address ... Type
            mac_match = re.search(
                rf"{re.escape(ip_address)}\s+([0-9a-fA-F-]{{17}})", result.stdout
            )
            if mac_match:
                return mac_match.group(1)
    except:
        pass
    return "Tidak diketahui"


# ============================================================
# FUNGSI PING
# ============================================================

def ping(host, count=2, timeout=3):
    """
    Melakukan ping ke host dan mengembalikan status serta latency.
    Returns: (success: bool, latency_ms: float or None, packet_loss: int)
    """
    try:
        if platform.system() == "Windows":
            cmd = ["ping", "-n", str(count), "-w", str(timeout * 1000), host]
        else:
            cmd = ["ping", "-c", str(count), "-W", str(timeout), host]
        
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout + 2
        )
        
        success = result.returncode == 0
        
        # Ekstrak latency
        latency = None
        if success:
            if platform.system() == "Windows":
                # Cari "Average = Xms" atau "time=Xms"
                avg_match = re.search(r"Average\s*=\s*([0-9]+)", result.stdout)
                time_match = re.findall(r"time[=<]\s*([0-9]+)", result.stdout)
                if avg_match:
                    latency = float(avg_match.group(1))
                elif time_match:
                    latencies = [float(t) for t in time_match]
                    latency = sum(latencies) / len(latencies) if latencies else None
            else:
                # Cari "time=X ms" atau "rtt min/avg/max/mdev = X/Y/Z/W"
                avg_match = re.search(r"rtt min/avg/max/mdev\s*=\s*[0-9.]+/([0-9.]+)", result.stdout)
                time_match = re.findall(r"time=([0-9.]+)\s*ms", result.stdout)
                if avg_match:
                    latency = float(avg_match.group(1))
                elif time_match:
                    latencies = [float(t) for t in time_match]
                    latency = sum(latencies) / len(latencies) if latencies else None
        
        # Ekstrak packet loss
        packet_loss = 0
        loss_match = re.search(r"(\d+)%", result.stdout)
        if loss_match:
            packet_loss = int(loss_match.group(1))
        
        return success, latency, packet_loss
    except subprocess.TimeoutExpired:
        return False, None, 100
    except Exception as e:
        return False, None, 100


# ============================================================
# FUNGSI SCANNING JARINGAN
# ============================================================

def scan_network(local_ip, prefix_length):
    """
    Memindai jaringan lokal untuk menemukan perangkat aktif.
    Menggunakan ping sweep dengan threading.
    """
    print(f"{Colors.BLUE}[*] Memindai jaringan...{Colors.END}")
    
    try:
        network = ipaddress.IPv4Network(f"{local_ip}/{prefix_length}", strict=False)
    except:
        # Fallback ke /24
        parts = local_ip.split('.')
        network = ipaddress.IPv4Network(f"{parts[0]}.{parts[1]}.{parts[2]}.0/24", strict=False)
    
    hosts = list(network.hosts())
    active_devices = []
    lock = threading.Lock()
    
    def check_host(ip):
        ip_str = str(ip)
        success, latency, loss = ping(ip_str, count=1, timeout=2)
        if success:
            hostname = get_hostname(ip_str)
            mac = get_mac_address(ip_str)
            with lock:
                active_devices.append({
                    "ip": ip_str,
                    "hostname": hostname,
                    "mac": mac,
                    "latency": latency,
                    "status": "aktif",
                    "last_seen": get_timestamp()
                })
            print(f"{Colors.GREEN}[+] {ip_str} - {hostname} ({latency}ms){Colors.END}")
    
    # Gunakan ThreadPoolExecutor untuk scanning paralel
    max_workers = min(50, len(hosts))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(check_host, ip) for ip in hosts[:254]]  # Max 254 host
        for future in as_completed(futures):
            pass
    
    # Urutkan berdasarkan IP
    active_devices.sort(key=lambda x: [int(octet) for octet in x["ip"].split('.')])
    
    return active_devices


# ============================================================
# FUNGSI TROUBLESHOOTING
# ============================================================

def check_internet():
    """Memeriksa koneksi internet dengan ping ke beberapa server"""
    test_hosts = [
        {"name": "Google DNS", "host": "8.8.8.8"},
        {"name": "Cloudflare DNS", "host": "1.1.1.1"},
        {"name": "Google.com", "host": "google.com"},
    ]
    
    results = []
    for test in test_hosts:
        success, latency, loss = ping(test["host"], count=2, timeout=5)
        results.append({
            "name": test["name"],
            "host": test["host"],
            "success": success,
            "latency": latency,
            "packet_loss": loss
        })
        status = f"{Colors.GREEN}OK{Colors.END}" if success else f"{Colors.RED}GAGAL{Colors.END}"
        latency_str = f"{latency}ms" if latency else "-"
        print(f"  {status} {test['name']} ({test['host']}) - {latency_str}")
    
    return results


def check_dns():
    """Memeriksa resolusi DNS"""
    test_domains = [
        "google.com",
        "youtube.com",
        "facebook.com",
        "github.com",
    ]
    
    results = []
    for domain in test_domains:
        try:
            ip = socket.gethostbyname(domain)
            results.append({
                "domain": domain,
                "ip": ip,
                "success": True
            })
            print(f"  {Colors.GREEN}OK{Colors.END} {domain} -> {ip}")
        except Exception as e:
            results.append({
                "domain": domain,
                "ip": str(e),
                "success": False
            })
            print(f"  {Colors.RED}GAGAL{Colors.END} {domain} -> {e}")
    
    return results


def traceroute(host="8.8.8.8", max_hops=15):
    """Melakukan traceroute ke host tujuan"""
    print(f"{Colors.BLUE}[*] Traceroute ke {host}...{Colors.END}")
    
    hops = []
    try:
        if platform.system() == "Windows":
            cmd = ["tracert", "-d", "-h", str(max_hops), host]
        else:
            cmd = ["traceroute", "-m", str(max_hops), host]
        
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30
        )
        
        # Parse hasil traceroute
        for line in result.stdout.split('\n'):
            line = line.strip()
            # Format Windows: " 1  <1 ms  <1 ms  <1 ms  192.168.1.1"
            # Format Linux: " 1  192.168.1.1 (192.168.1.1)  0.5 ms  0.4 ms  0.4 ms"
            
            hop_match = re.search(r"^\s*(\d+)\s+", line)
            if hop_match:
                hop_num = int(hop_match.group(1))
                
                # Cari IP address
                ip_match = re.search(r"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", line)
                ip_addr = ip_match.group(1) if ip_match else "*"
                
                # Cari latency
                latencies = re.findall(r"<\s*(\d+)\s*ms|(\d+)\s*ms", line)
                avg_latency = None
                if latencies:
                    vals = []
                    for l in latencies:
                        vals.extend([x for x in l if x])
                    if vals:
                        avg_latency = sum(float(v) for v in vals) / len(vals)
                
                hops.append({
                    "hop": hop_num,
                    "ip": ip_addr,
                    "latency": avg_latency
                })
                
                if ip_addr != "*":
                    try:
                        hostname = socket.gethostbyaddr(ip_addr)[0]
                    except:
                        hostname = ip_addr
                    print(f"  {hop_num}. {hostname} ({ip_addr}) - {avg_latency}ms" if avg_latency else f"  {hop_num}. {hostname} ({ip_addr})")
                else:
                    print(f"  {hop_num}. * * * (Timeout)")
    
    except Exception as e:
        print(f"  {Colors.RED}[!] Traceroute gagal: {e}{Colors.END}")
    
    return hops


def check_port(host, port, timeout=2):
    """Memeriksa apakah port terbuka pada host"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False


def scan_common_ports(ip_address):
    """Memindai port-port umum pada perangkat"""
    common_ports = [
        (80, "HTTP"),
        (443, "HTTPS"),
        (22, "SSH"),
        (21, "FTP"),
        (3389, "RDP"),
        (8080, "HTTP-Alt"),
        (53, "DNS"),
        (445, "SMB"),
    ]
    
    open_ports = []
    for port, service in common_ports:
        if check_port(ip_address, port):
            open_ports.append({"port": port, "service": service})
    
    return open_ports


# ============================================================
# FUNGSI LOGGING
# ============================================================

class NetworkLogger:
    """Mencatat semua aktivitas jaringan ke dalam log"""
    
    def __init__(self):
        self.logs = []
        # Simpan log di folder aplikasi/exe agar konsisten saat dibangun jadi EXE
        try:
            base_path = get_base_path()
        except Exception:
            base_path = os.path.dirname(os.path.abspath(__file__))

        self.log_file = os.path.join(base_path, "netwatch_log.txt")

        # Jika file log tidak ada, buat dengan header awal
        try:
            if not os.path.exists(self.log_file):
                with open(self.log_file, 'w', encoding='utf-8') as f:
                    f.write(f"[{get_timestamp()}] [INFO] Log file created\n")
        except Exception:
            pass

        self._load_logs()
    
    def _load_logs(self):
        """Memuat log dari file jika ada"""
        try:
            if os.path.exists(self.log_file):
                with open(self.log_file, 'r', encoding='utf-8') as f:
                    for line in f.readlines()[-100:]:  # Max 100 baris terakhir
                        line = line.strip()
                        if line:
                            # Parse format: [TIMESTAMP] [LEVEL] MESSAGE
                            match = re.match(r"\[(.*?)\]\s*\[(.*?)\]\s*(.*)", line)
                            if match:
                                self.logs.append({
                                    "timestamp": match.group(1),
                                    "level": match.group(2),
                                    "message": match.group(3)
                                })
        except:
            pass
    
    def add_log(self, level, message):
        """Menambahkan log baru"""
        timestamp = get_timestamp()
        log_entry = {
            "timestamp": timestamp,
            "level": level,
            "message": message
        }
        self.logs.append(log_entry)
        
        # Simpan ke file
        try:
            with open(self.log_file, 'a') as f:
                f.write(f"[{timestamp}] [{level}] {message}\n")
        except:
            pass
        
        # Tampilkan di terminal
        color_map = {
            "INFO": Colors.BLUE,
            "OK": Colors.GREEN,
            "WARNING": Colors.YELLOW,
            "ERROR": Colors.RED,
        }
        color = color_map.get(level, Colors.END)
        print(f"{color}[{timestamp}] [{level}] {message}{Colors.END}")
    
    def get_logs(self, limit=50):
        """Mengembalikan log terbaru"""
        return self.logs[-limit:]


# ============================================================
# GENERATOR HTML
# ============================================================

def generate_html(data):
    """
    Menghasilkan file HTML statis dari data monitoring.
    """
    html = f"""<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetWatch - Monitoring Jaringan LAN</title>
    <style>
        /* ===== RESET & BASE ===== */
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0f0f1a;
            color: #e0e0e0;
            min-height: 100vh;
        }}
        
        /* ===== HEADER ===== */
        .header {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            padding: 20px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid #0f3460;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        }}
        
        .header-left {{
            display: flex;
            align-items: center;
            gap: 15px;
        }}
        
        .logo {{
            width: 50px;
            height: 50px;
            background: linear-gradient(135deg, #00d2ff, #3a7bd5);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            font-weight: bold;
            color: white;
            box-shadow: 0 0 20px rgba(0, 210, 255, 0.3);
        }}
        
        .header h1 {{
            font-size: 28px;
            font-weight: 700;
            background: linear-gradient(135deg, #00d2ff, #3a7bd5);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}
        
        .header-subtitle {{
            font-size: 12px;
            color: #888;
            -webkit-text-fill-color: #888;
        }}
        
        .header-right {{
            text-align: right;
        }}
        
        .last-update {{
            font-size: 13px;
            color: #aaa;
        }}
        
        .status-badge {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            margin-top: 5px;
        }}
        
        .status-badge.online {{
            background: rgba(0, 200, 83, 0.2);
            color: #00c853;
            border: 1px solid rgba(0, 200, 83, 0.3);
        }}
        
        .status-badge.offline {{
            background: rgba(255, 82, 82, 0.2);
            color: #ff5252;
            border: 1px solid rgba(255, 82, 82, 0.3);
        }}
        
        /* ===== CONTAINER ===== */
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        /* ===== STATS CARDS ===== */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }}
        
        .stat-card {{
            background: linear-gradient(135deg, #1a1a2e, #16213e);
            border-radius: 12px;
            padding: 20px;
            border: 1px solid #1e2d4a;
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        
        .stat-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.3);
        }}
        
        .stat-card .label {{
            font-size: 12px;
            color: #888;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 8px;
        }}
        
        .stat-card .value {{
            font-size: 28px;
            font-weight: 700;
        }}
        
        .stat-card .value.green {{ color: #00c853; }}
        .stat-card .value.yellow {{ color: #ffd600; }}
        .stat-card .value.red {{ color: #ff5252; }}
        .stat-card .value.blue {{ color: #448aff; }}
        .stat-card .value.cyan {{ color: #00e5ff; }}
        
        .stat-card .sub {{
            font-size: 11px;
            color: #666;
            margin-top: 5px;
        }}
        
        /* ===== SECTION ===== */
        .section {{
            background: linear-gradient(135deg, #1a1a2e, #16213e);
            border-radius: 12px;
            border: 1px solid #1e2d4a;
            margin-bottom: 25px;
            overflow: hidden;
        }}
        
        .section-header {{
            padding: 15px 20px;
            border-bottom: 1px solid #1e2d4a;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            user-select: none;
        }}
        
        .section-header:hover {{
            background: rgba(255,255,255,0.02);
        }}
        
        .section-header h2 {{
            font-size: 16px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .section-header h2 .icon {{
            font-size: 20px;
        }}
        
        .section-header .toggle-btn {{
            background: none;
            border: none;
            color: #888;
            font-size: 18px;
            cursor: pointer;
            transition: transform 0.3s;
        }}
        
        .section-header .toggle-btn.collapsed {{
            transform: rotate(-90deg);
        }}
        
        .section-body {{
            padding: 20px;
            transition: max-height 0.3s ease;
        }}
        
        .section-body.hidden {{
            display: none;
        }}
        
        /* ===== TABLE ===== */
        .table-container {{
            overflow-x: auto;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        thead th {{
            background: rgba(15, 52, 96, 0.5);
            padding: 12px 15px;
            text-align: left;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #888;
            font-weight: 600;
            border-bottom: 2px solid #1e2d4a;
        }}
        
        tbody td {{
            padding: 12px 15px;
            border-bottom: 1px solid #1a1a2e;
            font-size: 14px;
        }}
        
        tbody tr:hover {{
            background: rgba(255,255,255,0.03);
        }}
        
        .status-dot {{
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 8px;
        }}
        
        .status-dot.active {{ background: #00c853; box-shadow: 0 0 8px rgba(0,200,83,0.5); }}
        .status-dot.inactive {{ background: #666; }}
        .status-dot.error {{ background: #ff5252; box-shadow: 0 0 8px rgba(255,82,82,0.5); }}
        
        .latency-bar {{
            display: inline-block;
            height: 6px;
            border-radius: 3px;
            min-width: 30px;
            max-width: 100px;
            background: #1e2d4a;
            position: relative;
            vertical-align: middle;
        }}
        
        .latency-bar .fill {{
            height: 100%;
            border-radius: 3px;
            transition: width 0.5s;
        }}
        
        .latency-bar .fill.good {{ background: linear-gradient(90deg, #00c853, #00e676); }}
        .latency-bar .fill.fair {{ background: linear-gradient(90deg, #ffd600, #ffab00); }}
        .latency-bar .fill.poor {{ background: linear-gradient(90deg, #ff5252, #ff1744); }}
        
        .latency-text {{
            margin-left: 8px;
            font-size: 12px;
        }}
        
        /* ===== INTERNET STATUS ===== */
        .internet-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }}
        
        .internet-card {{
            background: rgba(15, 52, 96, 0.3);
            border-radius: 10px;
            padding: 15px;
            border: 1px solid #1e2d4a;
        }}
        
        .internet-card .service-name {{
            font-size: 14px;
            font-weight: 600;
            margin-bottom: 5px;
        }}
        
        .internet-card .service-host {{
            font-size: 12px;
            color: #888;
            margin-bottom: 10px;
        }}
        
        .internet-card .service-status {{
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        /* ===== DNS TABLE ===== */
        .dns-success {{ color: #00c853; }}
        .dns-failed {{ color: #ff5252; }}
        
        /* ===== LOGS ===== */
        .log-container {{
            max-height: 400px;
            overflow-y: auto;
        }}
        
        .log-entry {{
            padding: 8px 12px;
            border-bottom: 1px solid #1a1a2e;
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 12px;
            display: flex;
            gap: 10px;
        }}
        
        .log-entry:hover {{
            background: rgba(255,255,255,0.02);
        }}
        
        .log-time {{
            color: #666;
            min-width: 140px;
        }}
        
        .log-level {{
            min-width: 70px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        
        .log-level.INFO {{ color: #448aff; }}
        .log-level.OK {{ color: #00c853; }}
        .log-level.WARNING {{ color: #ffd600; }}
        .log-level.ERROR {{ color: #ff5252; }}
        
        .log-message {{
            color: #ccc;
        }}
        
        /* ===== TRACEROUTE ===== */
        .trace-container {{
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 13px;
        }}
        
        .trace-hop {{
            padding: 6px 10px;
            border-bottom: 1px solid #1a1a2e;
            display: flex;
            gap: 15px;
        }}
        
        .trace-hop .hop-num {{
            color: #888;
            min-width: 30px;
        }}
        
        .trace-hop .hop-ip {{
            color: #00e5ff;
        }}
        
        .trace-hop .hop-latency {{
            color: #aaa;
        }}
        
        .trace-hop.timeout .hop-ip {{
            color: #ff5252;
        }}
        
        /* ===== PORTS ===== */
        .port-badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 600;
            margin: 2px;
            background: rgba(0, 200, 83, 0.15);
            color: #00c853;
            border: 1px solid rgba(0, 200, 83, 0.2);
        }}
        
        /* ===== SCROLLBAR ===== */
        ::-webkit-scrollbar {{
            width: 6px;
            height: 6px;
        }}
        
        ::-webkit-scrollbar-track {{
            background: #1a1a2e;
        }}
        
        ::-webkit-scrollbar-thumb {{
            background: #0f3460;
            border-radius: 3px;
        }}
        
        ::-webkit-scrollbar-thumb:hover {{
            background: #1a4a8a;
        }}
        
        /* ===== RESPONSIVE ===== */
        @media (max-width: 768px) {{
            .header {{
                flex-direction: column;
                text-align: center;
                gap: 10px;
            }}
            
            .header-right {{
                text-align: center;
            }}
            
            .stats-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}
            
            .internet-grid {{
                grid-template-columns: 1fr;
            }}
        }}
        
        /* ===== ANIMATIONS ===== */
        @keyframes pulse {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0.5; }}
        }}
        
        .pulse {{
            animation: pulse 2s infinite;
        }}
        
        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(10px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
        
        .fade-in {{
            animation: fadeIn 0.5s ease forwards;
        }}
        
        /* ===== REFRESH BUTTON ===== */
        .refresh-btn {{
            background: linear-gradient(135deg, #00d2ff, #3a7bd5);
            border: none;
            color: white;
            padding: 8px 20px;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
        }}
        
        .refresh-btn:hover {{
            transform: translateY(-1px);
            box-shadow: 0 4px 15px rgba(0, 210, 255, 0.3);
        }}
        
        .refresh-btn:active {{
            transform: translateY(0);
        }}
        
        /* ===== EMPTY STATE ===== */
        .empty-state {{
            text-align: center;
            padding: 40px;
            color: #666;
        }}
        
        .empty-state .icon {{
            font-size: 48px;
            margin-bottom: 15px;
        }}
        
        /* ===== TOOLTIP ===== */
        .tooltip {{
            position: relative;
            cursor: help;
        }}
        
        .tooltip:hover::after {{
            content: attr(data-tip);
            position: absolute;
            bottom: 100%;
            left: 50%;
            transform: translateX(-50%);
            background: #333;
            color: white;
            padding: 5px 10px;
            border-radius: 5px;
            font-size: 11px;
            white-space: nowrap;
            z-index: 10;
        }}
    </style>
</head>
<body>
    <!-- HEADER -->
    <div class="header">
        <div class="header-left">
            <div class="logo">NW</div>
            <div>
                <h1>NetWatch</h1>
                <div class="header-subtitle">Network Monitoring Tool</div>
            </div>
        </div>
        <div class="header-right">
            <div class="last-update">Terakhir diperbarui: <span id="updateTime">{data['timestamp']}</span></div>
            <span class="status-badge {'online' if data['internet_status'] else 'offline'}">
                {'&#9679; Terkoneksi' if data['internet_status'] else '&#9679; Terputus'}
            </span>
            <button class="refresh-btn" onclick="location.reload()" style="margin-left: 15px;">&#8635; Refresh</button>
        </div>
    </div>
    
    <div class="container">
        <!-- STATS -->
        <div class="stats-grid">
            <div class="stat-card fade-in">
                <div class="label">Perangkat Aktif</div>
                <div class="value cyan">{data['total_devices']}</div>
                <div class="sub">dari {data['total_scanned']} IP dipindai</div>
            </div>
            <div class="stat-card fade-in">
                <div class="label">Koneksi Internet</div>
                <div class="value {'green' if data['internet_status'] else 'red'}">{'Terkoneksi' if data['internet_status'] else 'Terputus'}</div>
                <div class="sub">{data['internet_latency']}</div>
            </div>
            <div class="stat-card fade-in">
                <div class="label">Gateway</div>
                <div class="value blue" style="font-size: 20px;">{data['gateway']}</div>
                <div class="sub">{'&#9679; Terjangkau' if data['gateway_status'] else '&#9679; Tidak Terjangkau'}</div>
            </div>
            <div class="stat-card fade-in">
                <div class="label">IP Lokal</div>
                <div class="value blue" style="font-size: 20px;">{data['local_ip']}</div>
                <div class="sub">Subnet: {data['subnet_mask']}</div>
            </div>
            <div class="stat-card fade-in">
                <div class="label">Total Log</div>
                <div class="value yellow">{data['total_logs']}</div>
                <div class="sub">aktivitas tercatat</div>
            </div>
            <div class="stat-card fade-in">
                <div class="label">Hostname</div>
                <div class="value blue" style="font-size: 18px;">{data['hostname']}</div>
                <div class="sub">Nama perangkat Anda</div>
            </div>
        </div>
        
        <!-- PERANGKAT AKTIF -->
        <div class="section fade-in">
            <div class="section-header" onclick="toggleSection(this)">
                <h2><span class="icon">&#128268;</span> Perangkat Aktif di Jaringan</h2>
                <span class="toggle-btn">&#9660;</span>
            </div>
            <div class="section-body">
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>No</th>
                                <th>IP Address</th>
                                <th>Hostname</th>
                                <th>MAC Address</th>
                                <th>Status</th>
                                <th>Latency</th>
                                <th>Port Terbuka</th>
                                <th>Terakhir Terlihat</th>
                            </tr>
                        </thead>
                        <tbody>
                            {generate_device_rows(data['devices'])}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        
        <!-- KONEKSI INTERNET -->
        <div class="section fade-in">
            <div class="section-header" onclick="toggleSection(this)">
                <h2><span class="icon">&#127760;</span> Status Koneksi Internet</h2>
                <span class="toggle-btn">&#9660;</span>
            </div>
            <div class="section-body">
                <div class="internet-grid">
                    {generate_internet_cards(data['internet_checks'])}
                </div>
            </div>
        </div>
        
        <!-- DNS RESOLUTION -->
        <div class="section fade-in">
            <div class="section-header" onclick="toggleSection(this)">
                <h2><span class="icon">&#128220;</span> Resolusi DNS</h2>
                <span class="toggle-btn">&#9660;</span>
            </div>
            <div class="section-body">
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Domain</th>
                                <th>IP Address</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            {generate_dns_rows(data['dns_checks'])}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        
        <!-- TRACEROUTE -->
        <div class="section fade-in">
            <div class="section-header" onclick="toggleSection(this)">
                <h2><span class="icon">&#128640;</span> Traceroute (8.8.8.8)</h2>
                <span class="toggle-btn">&#9660;</span>
            </div>
            <div class="section-body">
                <div class="trace-container">
                    {generate_trace_rows(data['traceroute'])}
                </div>
            </div>
        </div>
        
        <!-- LOG AKTIVITAS -->
        <div class="section fade-in">
            <div class="section-header" onclick="toggleSection(this)">
                <h2><span class="icon">&#128196;</span> Log Aktivitas</h2>
                <span class="toggle-btn">&#9660;</span>
            </div>
            <div class="section-body">
                <div class="log-container">
                    {generate_log_rows(data['logs'])}
                </div>
            </div>
        </div>
        
        <!-- INFORMASI SISTEM -->
        <div class="section fade-in">
            <div class="section-header" onclick="toggleSection(this)">
                <h2><span class="icon">&#128295;</span> Informasi Sistem</h2>
                <span class="toggle-btn">&#9660;</span>
            </div>
            <div class="section-body">
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Parameter</th>
                                <th>Nilai</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr><td>Sistem Operasi</td><td>{data['system_info']['os']}</td></tr>
                            <tr><td>Hostname</td><td>{data['system_info']['hostname']}</td></tr>
                            <tr><td>Python Version</td><td>{data['system_info']['python']}</td></tr>
                            <tr><td>Waktu Monitoring</td><td>{data['timestamp']}</td></tr>
                            <tr><td>Durasi Scanning</td><td>{data['scan_duration']} detik</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // Toggle section collapse
        function toggleSection(header) {{
            const body = header.nextElementSibling;
            const btn = header.querySelector('.toggle-btn');
            body.classList.toggle('hidden');
            btn.classList.toggle('collapsed');
        }}
        
        // Auto refresh setiap 60 detik
        setTimeout(function() {{
            location.reload();
        }}, 60000);
        
        // Update waktu
        function updateTime() {{
            const now = new Date();
            const timeStr = now.toLocaleString('id-ID');
            document.getElementById('updateTime').textContent = timeStr;
        }}
        setInterval(updateTime, 1000);
    </script>
</body>
</html>"""
    
    return html


def generate_device_rows(devices):
    """Menghasilkan baris tabel untuk perangkat aktif"""
    if not devices:
        return '<tr><td colspan="8" class="empty-state">Tidak ada perangkat ditemukan</td></tr>'
    
    rows = ""
    for i, dev in enumerate(devices, 1):
        latency = dev.get('latency')
        if latency is not None:
            if latency < 10:
                bar_class = "good"
                bar_width = min(latency * 3, 100)
            elif latency < 50:
                bar_class = "fair"
                bar_width = min(latency * 2, 100)
            else:
                bar_class = "poor"
                bar_width = min(latency, 100)
            latency_html = f'<div class="latency-bar"><div class="fill {bar_class}" style="width:{bar_width}%"></div></div><span class="latency-text">{latency:.1f} ms</span>'
        else:
            latency_html = '<span style="color:#666">-</span>'
        
        # Ports
        ports = dev.get('ports', [])
        if ports:
            ports_html = ''.join([f'<span class="port-badge">{p["service"]}:{p["port"]}</span>' for p in ports])
        else:
            ports_html = '<span style="color:#666">-</span>'
        
        rows += f"""<tr>
            <td>{i}</td>
            <td style="font-family:monospace">{dev['ip']}</td>
            <td>{dev.get('hostname', 'Tidak diketahui')}</td>
            <td style="font-family:monospace;font-size:12px">{dev.get('mac', 'Tidak diketahui')}</td>
            <td><span class="status-dot active"></span>Aktif</td>
            <td>{latency_html}</td>
            <td>{ports_html}</td>
            <td style="font-size:12px;color:#888">{dev.get('last_seen', '-')}</td>
        </tr>"""
    
    return rows


def generate_internet_cards(checks):
    """Menghasilkan kartu status internet"""
    if not checks:
        return '<div class="empty-state">Tidak ada data koneksi internet</div>'
    
    cards = ""
    for check in checks:
        status_class = "active" if check['success'] else "error"
        status_text = "Online" if check['success'] else "Offline"
        latency = f"{check['latency']:.1f} ms" if check['latency'] else "-"
        loss = f"{check['packet_loss']}% packet loss" if check['packet_loss'] else "0% packet loss"
        
        cards += f"""<div class="internet-card">
            <div class="service-name">{check['name']}</div>
            <div class="service-host">{check['host']}</div>
            <div class="service-status">
                <span class="status-dot {status_class}"></span>
                <span>{status_text}</span>
                <span style="color:#888;font-size:12px">| {latency} | {loss}</span>
            </div>
        </div>"""
    
    return cards


def generate_dns_rows(checks):
    """Menghasilkan baris tabel DNS"""
    if not checks:
        return '<tr><td colspan="3" class="empty-state">Tidak ada data DNS</td></tr>'
    
    rows = ""
    for check in checks:
        status_class = "dns-success" if check['success'] else "dns-failed"
        status_text = "&#10003; Berhasil" if check['success'] else "&#10007; Gagal"
        
        rows += f"""<tr>
            <td>{check['domain']}</td>
            <td style="font-family:monospace">{check['ip']}</td>
            <td class="{status_class}">{status_text}</td>
        </tr>"""
    
    return rows


def generate_trace_rows(hops):
    """Menghasilkan baris traceroute"""
    if not hops:
        return '<div class="empty-state">Tidak ada data traceroute</div>'
    
    rows = ""
    for hop in hops:
        timeout_class = "timeout" if hop['ip'] == "*" else ""
        latency = f"{hop['latency']:.1f} ms" if hop['latency'] else "*"
        
        rows += f"""<div class="trace-hop {timeout_class}">
            <span class="hop-num">{hop['hop']}.</span>
            <span class="hop-ip">{hop['ip']}</span>
            <span class="hop-latency">{latency}</span>
        </div>"""
    
    return rows


def generate_log_rows(logs):
    """Menghasilkan baris log"""
    if not logs:
        return '<div class="empty-state">Belum ada log aktivitas</div>'
    
    rows = ""
    for log in reversed(logs):  # Tampilkan yang terbaru di atas
        rows += f"""<div class="log-entry">
            <span class="log-time">{log['timestamp']}</span>
            <span class="log-level {log['level']}">{log['level']}</span>
            <span class="log-message">{log['message']}</span>
        </div>"""
    
    return rows


# ============================================================
# FUNGSI UTAMA
# ============================================================

def main():
    """Fungsi utama NetWatch"""
    print(f"""
{Colors.HEADER}{Colors.BOLD}
╔══════════════════════════════════════════╗
║           NetWatch v1.0                  ║
║     Alat Monitoring Jaringan LAN         ║
╚══════════════════════════════════════════╝{Colors.END}
    """)
    
    # Inisialisasi logger
    logger = NetworkLogger()
    logger.add_log("INFO", "NetWatch dimulai")
    
    start_time = datetime.datetime.now()
    
    # Dapatkan informasi jaringan
    print(f"\n{Colors.BOLD}[*] Mengumpulkan informasi jaringan...{Colors.END}")
    local_ip, subnet_mask, prefix_length = get_local_ip()
    gateway = get_gateway()
    hostname = socket.gethostname()
    
    print(f"  IP Lokal    : {local_ip}")
    print(f"  Subnet Mask : {subnet_mask}")
    print(f"  Gateway     : {gateway}")
    print(f"  Hostname    : {hostname}")
    
    logger.add_log("INFO", f"IP Lokal: {local_ip}, Gateway: {gateway}")
    
    # Cek gateway
    print(f"\n{Colors.BOLD}[*] Memeriksa gateway...{Colors.END}")
    gw_success, gw_latency, _ = ping(gateway, count=2, timeout=3)
    gateway_status = gw_success
    if gw_success:
        print(f"  {Colors.GREEN}Gateway {gateway} terjangkau ({gw_latency}ms){Colors.END}")
        logger.add_log("OK", f"Gateway {gateway} terjangkau ({gw_latency}ms)")
    else:
        print(f"  {Colors.RED}Gateway {gateway} tidak terjangkau{Colors.END}")
        logger.add_log("WARNING", f"Gateway {gateway} tidak terjangkau")
    
    # Scan jaringan
    print(f"\n{Colors.BOLD}[*] Memindai perangkat di jaringan...{Colors.END}")
    devices = scan_network(local_ip, prefix_length)
    total_devices = len(devices)
    total_scanned = min(254, 2 ** (32 - prefix_length) - 2)
    print(f"\n{Colors.GREEN}[+] Ditemukan {total_devices} perangkat aktif dari {total_scanned} IP{Colors.END}")
    logger.add_log("OK", f"Ditemukan {total_devices} perangkat aktif")
    
    # Scan port untuk setiap perangkat (maks 5 perangkat untuk efisiensi)
    print(f"\n{Colors.BOLD}[*] Memindai port pada perangkat...{Colors.END}")
    for dev in devices[:5]:
        print(f"  Memindai {dev['ip']}...")
        ports = scan_common_ports(dev['ip'])
        dev['ports'] = ports
        if ports:
            port_list = ", ".join([f"{p['service']}({p['port']})" for p in ports])
            print(f"    {Colors.GREEN}Port terbuka: {port_list}{Colors.END}")
    
    # Cek koneksi internet
    print(f"\n{Colors.BOLD}[*] Memeriksa koneksi internet...{Colors.END}")
    internet_checks = check_internet()
    internet_status = any(c['success'] for c in internet_checks)
    internet_latency = ""
    for c in internet_checks:
        if c['success'] and c['latency']:
            internet_latency = f"Latency: {c['latency']:.1f}ms"
            break
    
    if internet_status:
        logger.add_log("OK", "Koneksi internet aktif")
    else:
        logger.add_log("ERROR", "Koneksi internet terputus")
    
    # Cek DNS
    print(f"\n{Colors.BOLD}[*] Memeriksa resolusi DNS...{Colors.END}")
    dns_checks = check_dns()
    dns_status = any(c['success'] for c in dns_checks)
    if dns_status:
        logger.add_log("OK", "Resolusi DNS berfungsi")
    else:
        logger.add_log("ERROR", "Resolusi DNS gagal")
    
    # Traceroute
    print(f"\n{Colors.BOLD}[*] Melakukan traceroute...{Colors.END}")
    trace_hops = traceroute("8.8.8.8")
    logger.add_log("INFO", f"Traceroute selesai ({len(trace_hops)} hop)")
    
    # Hitung durasi
    end_time = datetime.datetime.now()
    scan_duration = (end_time - start_time).total_seconds()
    
    # Kumpulkan data untuk HTML
    print(f"\n{Colors.BOLD}[*] Membuat laporan HTML...{Colors.END}")
    
    data = {
        "timestamp": get_timestamp(),
        "local_ip": local_ip,
        "subnet_mask": subnet_mask,
        "gateway": gateway,
        "gateway_status": gateway_status,
        "hostname": hostname,
        "total_devices": total_devices,
        "total_scanned": total_scanned,
        "internet_status": internet_status,
        "internet_latency": internet_latency,
        "internet_checks": internet_checks,
        "dns_checks": dns_checks,
        "traceroute": trace_hops,
        "devices": devices,
        "logs": logger.get_logs(100),
        "total_logs": len(logger.logs),
        "scan_duration": f"{scan_duration:.1f}",
        "system_info": {
            "os": f"{platform.system()} {platform.release()}",
            "hostname": hostname,
            "python": sys.version.split()[0]
        }
    }
    
    # Generate HTML
    html_content = generate_html(data)
    
    # Simpan ke file
    base = get_base_path()
    output_file = os.path.join(base, REPORT_FILENAME)
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print(f"\n{Colors.GREEN}{Colors.BOLD}")
    print("╔══════════════════════════════════════════╗")
    print("║         Laporan Berhasil Dibuat!         ║")
    print("╚══════════════════════════════════════════╝" + Colors.END)
    print(f"  File: {Colors.BOLD}{output_file}{Colors.END}")
    print(f"  Waktu: {get_timestamp()}")
    print(f"  Durasi: {scan_duration:.1f} detik")
    print(f"  Perangkat ditemukan: {total_devices}")
    print(f"  Koneksi Internet: {'Aktif' if internet_status else 'Terputus'}")
    print(f"{Colors.YELLOW}Buka file {output_file} di browser untuk melihat laporan.{Colors.END}")
    print(f"{Colors.YELLOW}Tekan Ctrl+C untuk menghentikan, atau jalankan ulang untuk update.{Colors.END}")
    
    logger.add_log("OK", f"Laporan berhasil dibuat: {REPORT_FILENAME}")


def show_menu():
    """Menampilkan menu pilihan mode"""
    print(f"""
{Colors.HEADER}{Colors.BOLD}
╔══════════════════════════════════════════╗
║           NetWatch v1.0                  ║
║     Alat Monitoring Jaringan LAN         ║
╚══════════════════════════════════════════╝{Colors.END}
    """)
    print(f"  {Colors.BOLD}Pilih mode:{Colors.END}")
    print(f"  {Colors.GREEN}[1]{Colors.END} Buka laporan HTML")
    print(f"  {Colors.GREEN}[2]{Colors.END} Jalankan di terminal (tanpa membuka HTML)")
    print(f"  {Colors.GREEN}[3]{Colors.END} Keluar")

    try:
        choice = input(f"  {Colors.BOLD}Pilihan [1]: {Colors.END}").strip()
        if choice == "" or choice == "1":
            return "open"
        elif choice == "2":
            return "scan_exe"
        elif choice == "3":
            return "exit"
        else:
            print(f"  {Colors.RED}Pilihan tidak valid! Menggunakan opsi 1. {Colors.END}")
            return "open"
    except KeyboardInterrupt:
        return "exit"


def get_base_path():
    """Mendapatkan path folder tempat script/EXE berada"""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

def open_html():
    """Membuka file HTML di browser default"""
    base = get_base_path()
    html_file = os.path.join(base, REPORT_FILENAME)
    print(f"\n{Colors.BLUE}[*] Mencari file: {html_file}{Colors.END}")
    if os.path.exists(html_file):
        print(f"{Colors.GREEN}[+] File ditemukan, membuka browser...{Colors.END}")
        try:
            # Coba webbrowser dulu
            url = f"file:///{html_file.replace(os.sep, '/')}"
            webbrowser.open(url)
            print(f"{Colors.GREEN}[+] Browser dibuka!{Colors.END}")
        except Exception as e1:
            print(f"{Colors.YELLOW}[!] webbrowser gagal: {e1}{Colors.END}")
            try:
                # Fallback ke os.startfile
                os.startfile(html_file)
                print(f"{Colors.GREEN}[+] Browser dibuka!{Colors.END}")
            except Exception as e2:
                print(f"{Colors.RED}[!] Gagal buka browser: {e2}{Colors.END}")
                print(f"{Colors.YELLOW}  Buka manual: {html_file}{Colors.END}")
    else:
        print(f"\n{Colors.RED}[!] File {html_file} tidak ditemukan.{Colors.END}")
        print(f"  Jalankan mode [1] terlebih dahulu untuk membuat laporan.{Colors.END}")


if __name__ == "__main__":
    if getattr(sys, 'frozen', False):
        main()
        print()
        open_html()
    else:
        while True:
            try:
                mode = show_menu()
                if mode == "scan_html":
                    main()
                    print()
                    open_html()
                    if getattr(sys, 'frozen', False):
                        break
                elif mode == "scan_exe":
                    main()
                    print()
                    if not getattr(sys, 'frozen', False):
                        input(f"\n  {Colors.YELLOW}Tekan Enter untuk kembali ke menu...{Colors.END}")
                    else:
                        break
                elif mode == "open":
                    open_html()
                    if getattr(sys, 'frozen', False):
                        break
                else:
                    print(f"\n{Colors.BOLD}Terima kasih telah menggunakan NetWatch!{Colors.END}")
                    break
            except KeyboardInterrupt:
                print(f"\n\n{Colors.BOLD}Terima kasih telah menggunakan NetWatch!{Colors.END}")
                break
            except Exception as e:
                print(f"\n{Colors.RED}[!] Error: {e}{Colors.END}")
                input(f"\n  {Colors.YELLOW}Tekan Enter untuk kembali ke menu...{Colors.END}")
