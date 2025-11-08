"""
ACCURATE ONLINE OS DEMO
Author: Ian Carter Kulani
Version: 0000
"""

import socket
import threading
import time
import requests
import json
import subprocess
import os
from datetime import datetime, timedelta
import scapy.all as scapy
from scapy.all import IP, TCP, UDP, ICMP, ARP, Ether
import logging
from typing import Dict, List, Set, Tuple, Optional, Any, Callable
import sys
import random
import platform
import psutil
import getpass
import uuid
import hashlib
import base64
import zipfile
import tarfile
import io
import re
import csv
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, quote, unquote
import dns.resolver
import ssl
import http.client
import ftplib
import paramiko
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import queue
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
import asyncio
import aiohttp
import asyncssh
import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import jwt
import qrcode
from PIL import Image, ImageDraw, ImageFont
import speedtest
import geoip2.database
import whois
import shodan
import virustotal_python
import nmap
import pyfiglet
from colorama import Fore, Back, Style, init
import readline
import glob
import tempfile
import secrets
import string
import sqlite3
from pathlib import Path
import ipaddress
import statistics
from collections import defaultdict, deque
import calendar
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import matplotlib.pyplot as plt
import numpy as np

# Initialize colorama
init(autoreset=True)

# Enhanced Configuration
CONFIG_FILE = "cyber_security_config.json"
KEY_FILE = "encryption.key"
DATABASE_FILE = "network_data.db"
REPORT_DIR = "reports"

class DatabaseManager:
    """Manage SQLite database for storing network data and threats"""
    
    def __init__(self):
        self.db_file = DATABASE_FILE
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # IP monitoring table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS monitored_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                threat_level INTEGER DEFAULT 0,
                last_scan TIMESTAMP
            )
        ''')
        
        # Threat detection table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolved BOOLEAN DEFAULT 0
            )
        ''')
        
        # Command history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS command_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                command TEXT NOT NULL,
                source TEXT DEFAULT 'local',
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN DEFAULT 1
            )
        ''')
        
        # Network scan results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                open_ports TEXT,
                services TEXT,
                os_info TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Report history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_type TEXT NOT NULL,
                period TEXT NOT NULL,
                file_path TEXT,
                generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def log_command(self, command: str, source: str = 'local', success: bool = True):
        """Log command to database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO command_history (command, source, success) VALUES (?, ?, ?)',
            (command, source, success)
        )
        conn.commit()
        conn.close()
    
    def get_command_history(self, limit: int = 50) -> List[Tuple]:
        """Get command history from database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'SELECT command, source, timestamp, success FROM command_history ORDER BY timestamp DESC LIMIT ?',
            (limit,)
        )
        results = cursor.fetchall()
        conn.close()
        return results
    
    def log_threat(self, ip_address: str, threat_type: str, severity: str, description: str = ""):
        """Log threat detection to database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO threat_logs (ip_address, threat_type, severity, description) VALUES (?, ?, ?, ?)',
            (ip_address, threat_type, severity, description)
        )
        conn.commit()
        conn.close()
    
    def get_recent_threats(self, limit: int = 20) -> List[Tuple]:
        """Get recent threats from database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'SELECT ip_address, threat_type, severity, timestamp FROM threat_logs ORDER BY timestamp DESC LIMIT ?',
            (limit,)
        )
        results = cursor.fetchall()
        conn.close()
        return results

class NetworkTrafficQueue:
    """Manage network traffic and control collisions"""
    
    def __init__(self, max_size=100):
        self.queue = queue.Queue(maxsize=max_size)
        self.active_operations = set()
        self.lock = threading.Lock()
        self.operation_counter = 0
        
    def add_operation(self, operation_id, operation_data):
        """Add operation to queue"""
        try:
            with self.lock:
                if operation_id not in self.active_operations:
                    self.queue.put((operation_id, operation_data), timeout=5)
                    self.active_operations.add(operation_id)
                    self.operation_counter += 1
                    return True
                return False
        except queue.Full:
            return False
            
    def complete_operation(self, operation_id):
        """Mark operation as completed"""
        with self.lock:
            self.active_operations.discard(operation_id)
            
    def get_next_operation(self):
        """Get next operation from queue"""
        try:
            return self.queue.get(timeout=1)
        except queue.Empty:
            return None
            
    def get_queue_status(self):
        """Get current queue status"""
        with self.lock:
            return {
                'queue_size': self.queue.qsize(),
                'active_operations': len(self.active_operations),
                'total_operations': self.operation_counter
            }

class ColorManager:
    """Manage terminal colors and themes"""
    
    THEMES = {
        'default': {
            'primary': Fore.GREEN,
            'secondary': Fore.CYAN,
            'warning': Fore.YELLOW,
            'error': Fore.RED,
            'success': Fore.GREEN,
            'info': Fore.BLUE,
            'highlight': Fore.MAGENTA
        },
        'red': {
            'primary': Fore.RED,
            'secondary': Fore.LIGHTRED_EX,
            'warning': Fore.YELLOW,
            'error': Fore.LIGHTRED_EX,
            'success': Fore.GREEN,
            'info': Fore.CYAN,
            'highlight': Fore.MAGENTA
        },
        'blue': {
            'primary': Fore.BLUE,
            'secondary': Fore.LIGHTBLUE_EX,
            'warning': Fore.YELLOW,
            'error': Fore.RED,
            'success': Fore.GREEN,
            'info': Fore.CYAN,
            'highlight': Fore.MAGENTA
        },
        'orange': {
            'primary': Fore.YELLOW,
            'secondary': Fore.LIGHTYELLOW_EX,
            'warning': Fore.LIGHTRED_EX,
            'error': Fore.RED,
            'success': Fore.GREEN,
            'info': Fore.CYAN,
            'highlight': Fore.MAGENTA
        },
        'purple': {
            'primary': Fore.MAGENTA,
            'secondary': Fore.LIGHTMAGENTA_EX,
            'warning': Fore.YELLOW,
            'error': Fore.RED,
            'success': Fore.GREEN,
            'info': Fore.CYAN,
            'highlight': Fore.BLUE
        }
    }
    
    def __init__(self):
        self.current_theme = 'default'
    
    def set_theme(self, theme_name: str):
        if theme_name in self.THEMES:
            self.current_theme = theme_name
            return f"Theme changed to {theme_name}"
        return f"Theme {theme_name} not found"
    
    def get_color(self, color_type: str) -> str:
        return self.THEMES[self.current_theme].get(color_type, Fore.WHITE)
    
    def colorize(self, text: str, color_type: str) -> str:
        return f"{self.get_color(color_type)}{text}{Style.RESET_ALL}"

class EncryptionManager:
    """Handle encryption and decryption of sensitive data"""
    
    def __init__(self):
        self.key = self.load_or_create_key()
        self.fernet = Fernet(self.key)
    
    def load_or_create_key(self) -> bytes:
        if os.path.exists(KEY_FILE):
            with open(KEY_FILE, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(KEY_FILE, 'wb') as f:
                f.write(key)
            return key
    
    def encrypt(self, data: str) -> str:
        encrypted = self.fernet.encrypt(data.encode())
        return base64.urlsafe_b64encode(encrypted).decode()
    
    def decrypt(self, encrypted_data: str) -> str:
        decoded = base64.urlsafe_b64decode(encrypted_data.encode())
        return self.fernet.decrypt(decoded).decode()
    
    def hash_data(self, data: str) -> str:
        return hashlib.sha256(data.encode()).hexdigest()

class ThreatIntelligence:
    """Advanced threat intelligence and analysis"""
    
    def __init__(self):
        self.threat_database = {}
        self.suspicious_patterns = [
            r"\b(?:malware|virus|trojan|ransomware|spyware)\b",
            r"\b(?:exploit|vulnerability|attack|breach)\b",
            r"\b(?:phishing|spoofing|hijacking)\b",
            r"\b(?:botnet|zombie|command.control)\b",
            r"\b(?:scanning|probing|reconnaissance)\b"
        ]
        
    def analyze_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Analyze IP reputation using multiple sources"""
        analysis = {
            'ip': ip,
            'risk_score': 0,
            'threat_indicators': [],
            'reputation': 'Unknown',
            'details': {}
        }
        
        try:
            # Check if IP is private
            if ipaddress.ip_address(ip).is_private:
                analysis['threat_indicators'].append('Private IP address')
                analysis['risk_score'] += 10
                
            # Check for suspicious patterns in recent activity
            recent_scans = self.get_recent_scan_activity(ip)
            if recent_scans > 10:
                analysis['threat_indicators'].append(f'High scan activity: {recent_scans} scans')
                analysis['risk_score'] += 30
                
            # Analyze port patterns
            port_analysis = self.analyze_port_patterns(ip)
            if port_analysis['suspicious']:
                analysis['threat_indicators'].extend(port_analysis['indicators'])
                analysis['risk_score'] += port_analysis['risk_score']
                
            # Determine reputation based on risk score
            if analysis['risk_score'] >= 70:
                analysis['reputation'] = 'High Risk'
            elif analysis['risk_score'] >= 40:
                analysis['reputation'] = 'Medium Risk'
            elif analysis['risk_score'] >= 20:
                analysis['reputation'] = 'Low Risk'
            else:
                analysis['reputation'] = 'Clean'
                
        except Exception as e:
            analysis['error'] = str(e)
            
        return analysis
    
    def get_recent_scan_activity(self, ip: str) -> int:
        """Get recent scan activity for IP"""
        # This would typically query a database
        # For now, return a simulated value
        return random.randint(0, 20)
    
    def analyze_port_patterns(self, ip: str) -> Dict[str, Any]:
        """Analyze port patterns for suspicious activity"""
        analysis = {
            'suspicious': False,
            'indicators': [],
            'risk_score': 0
        }
        
        # Common suspicious port patterns
        suspicious_ports = {
            22: 'SSH brute force',
            23: 'Telnet attacks',
            135: 'RPC exploitation',
            139: 'NetBIOS attacks',
            445: 'SMB attacks',
            1433: 'SQL Server attacks',
            3389: 'RDP attacks'
        }
        
        # Simulate port analysis
        open_ports = self.get_open_ports(ip)
        for port in open_ports:
            if port in suspicious_ports:
                analysis['indicators'].append(f'Suspicious port {port} open: {suspicious_ports[port]}')
                analysis['risk_score'] += 10
                analysis['suspicious'] = True
                
        return analysis
    
    def get_open_ports(self, ip: str) -> List[int]:
        """Get open ports for IP (simulated)"""
        # In a real implementation, this would query scan results
        return random.sample(range(1, 65535), random.randint(0, 10))

class NetworkScanner:
    """Comprehensive network scanning capabilities"""
    
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.scan_results = {}
    
    def comprehensive_scan(self, target: str) -> Dict[str, Any]:
        """Perform comprehensive network scan"""
        try:
            scan_data = {}
            
            # Host discovery
            scan_data['host_discovery'] = self.nm.scan(hosts=target, arguments='-sn')
            
            # Port scanning
            scan_data['port_scan'] = self.nm.scan(hosts=target, arguments='-sS -sV -sC -O -A')
            
            # Vulnerability scanning
            scan_data['vuln_scan'] = self.nm.scan(hosts=target, arguments='--script vuln')
            
            return scan_data
        except Exception as e:
            return {'error': str(e)}
    
    def stealth_scan(self, target: str, ports: str = '1-1000') -> Dict[str, Any]:
        """Perform stealth scan"""
        try:
            return self.nm.scan(hosts=target, ports=ports, arguments='-sS -T2')
        except Exception as e:
            return {'error': str(e)}

class CurlManager:
    """Handle all curl-like functionality"""
    
    def __init__(self):
        self.session = requests.Session()
        self.history = []
    
    def execute_curl_command(self, command_parts: List[str]) -> Dict[str, Any]:
        """Execute curl-like commands with extensive options"""
        try:
            url = None
            method = 'GET'
            headers = {}
            data = None
            files = {}
            params = {}
            output_file = None
            verbose = False
            follow_redirects = True
            timeout = 30
            verify_ssl = True
            
            i = 0
            while i < len(command_parts):
                part = command_parts[i]
                
                if part.startswith('http'):
                    url = part
                elif part == '-X':
                    method = command_parts[i + 1].upper()
                    i += 1
                elif part == '-H':
                    header = command_parts[i + 1]
                    key, value = header.split(':', 1)
                    headers[key.strip()] = value.strip()
                    i += 1
                elif part == '-d':
                    data = command_parts[i + 1]
                    i += 1
                elif part == '-F':
                    form_data = command_parts[i + 1]
                    if '=@' in form_data:
                        key, filepath = form_data.split('=@', 1)
                        files[key] = open(filepath, 'rb')
                    else:
                        key, value = form_data.split('=', 1)
                        if not data:
                            data = {}
                        data[key] = value
                    i += 1
                elif part == '-o':
                    output_file = command_parts[i + 1]
                    i += 1
                elif part == '-O':
                    output_file = os.path.basename(url) if url else 'output'
                elif part == '-s':
                    verbose = False
                elif part == '-v':
                    verbose = True
                elif part == '-k':
                    verify_ssl = False
                elif part == '-L':
                    follow_redirects = True
                elif part == '--compressed':
                    headers['Accept-Encoding'] = 'gzip, deflate'
                elif part == '-u':
                    auth = command_parts[i + 1]
                    username, password = auth.split(':', 1)
                    self.session.auth = (username, password)
                    i += 1
                elif part == '--cookie':
                    cookie = command_parts[i + 1]
                    headers['Cookie'] = cookie
                    i += 1
                elif part == '-b':
                    cookie_file = command_parts[i + 1]
                    with open(cookie_file, 'r') as f:
                        headers['Cookie'] = f.read().strip()
                    i += 1
                elif part == '--connect-timeout':
                    timeout = int(command_parts[i + 1])
                    i += 1
                elif part == '--max-time':
                    timeout = int(command_parts[i + 1])
                    i += 1
                elif part == '--retry':
                    retries = int(command_parts[i + 1])
                    i += 1
                elif part == '--interface':
                    interface = command_parts[i + 1]
                    i += 1
                elif part == '-w':
                    output_format = command_parts[i + 1]
                    i += 1
                elif part == '--trace':
                    trace_file = command_parts[i + 1]
                    i += 1
                elif part == '--limit-rate':
                    rate_limit = command_parts[i + 1]
                    i += 1
                elif part == '--cookie-jar':
                    cookie_jar = command_parts[i + 1]
                    i += 1
                
                i += 1
            
            if not url:
                return {'error': 'No URL provided'}
            
            # Execute request
            response = self.session.request(
                method=method,
                url=url,
                headers=headers,
                data=data,
                files=files,
                params=params,
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=follow_redirects
            )
            
            result = {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content': response.text,
                'url': response.url,
                'history': [str(r.url) for r in response.history]
            }
            
            if output_file:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(response.text)
                result['saved_to'] = output_file
            
            # Add to history
            self.history.append({
                'timestamp': datetime.now().isoformat(),
                'command': ' '.join(command_parts),
                'status_code': response.status_code,
                'url': url
            })
            
            return result
            
        except Exception as e:
            return {'error': str(e)}

class AdvancedPingManager:
    """Advanced ping functionality"""
    
    def __init__(self):
        self.ping_history = {}
        
    def simple_ping(self, ip: str) -> str:
        """Simple ping that works reliably"""
        try:
            if os.name == 'nt':  # Windows
                cmd = ['ping', '-n', '4', ip]
            else:  # Linux/Mac
                cmd = ['ping', '-c', '4', ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.stdout
        except subprocess.TimeoutExpired:
            return f"Ping timeout for {ip}"
        except Exception as e:
            return f"Ping error: {str(e)}"

class AdvancedPortScanner:
    """Advanced port scanning"""
    
    def __init__(self):
        self.scan_results = {}
        self.nm = nmap.PortScanner()
    
    def quick_scan(self, target: str, ports: str = "1-1000") -> Dict[str, Any]:
        """Quick port scan"""
        try:
            print(f"🔍 Starting quick scan of {target} on ports {ports}...")
            
            scan_result = self.nm.scan(target, ports, arguments='-T4')
            
            open_ports = []
            if target in scan_result['scan']:
                for port, port_info in scan_result['scan'][target]['tcp'].items():
                    if port_info['state'] == 'open':
                        open_ports.append(port)
            
            return {
                'target': target,
                'scan_type': 'quick',
                'ports_scanned': ports,
                'open_ports': sorted(open_ports),
                'scan_duration': scan_result['nmap']['scanstats']['elapsed'],
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {'error': f'Quick scan error: {str(e)}'}
    
    def deep_scan(self, target: str, ports: str = "1-65535") -> Dict[str, Any]:
        """Deep port scan with service detection"""
        try:
            print(f"🔍 Starting deep scan of {target} on ports {ports}...")
            
            scan_result = self.nm.scan(target, ports, arguments='-sS -sV -T4')
            
            open_ports = []
            if target in scan_result['scan']:
                for port, port_info in scan_result['scan'][target]['tcp'].items():
                    if port_info['state'] == 'open':
                        open_ports.append({
                            'port': port,
                            'service': port_info.get('name', 'unknown'),
                            'version': port_info.get('version', ''),
                            'product': port_info.get('product', '')
                        })
            
            return {
                'target': target,
                'scan_type': 'deep',
                'ports_scanned': ports,
                'open_ports': open_ports,
                'scan_duration': scan_result['nmap']['scanstats']['elapsed'],
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {'error': f'Deep scan error: {str(e)}'}

class ReportGenerator:
    """Generate comprehensive security reports"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.report_dir = REPORT_DIR
        os.makedirs(self.report_dir, exist_ok=True)
    
    def generate_daily_report(self) -> str:
        """Generate daily security report"""
        try:
            # Get data for report
            threats = self.db_manager.get_recent_threats(50)
            commands = self.db_manager.get_command_history(100)
            
            # Create report content
            report_content = {
                'report_type': 'daily',
                'generated_at': datetime.now().isoformat(),
                'period': 'daily',
                'threat_summary': {
                    'total_threats': len(threats),
                    'high_severity': len([t for t in threats if t[2] == 'high']),
                    'medium_severity': len([t for t in threats if t[2] == 'medium']),
                    'low_severity': len([t for t in threats if t[2] == 'low'])
                },
                'recent_threats': threats[:10],
                'command_activity': len(commands),
                'system_health': self.get_system_health()
            }
            
            # Save report to file
            filename = f"daily_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            filepath = os.path.join(self.report_dir, filename)
            
            with open(filepath, 'w') as f:
                json.dump(report_content, f, indent=2)
            
            # Log report generation
            self.db_manager.log_command(f"generate_daily_report", 'system', True)
            
            return f"Daily report generated: {filepath}"
            
        except Exception as e:
            return f"Error generating daily report: {str(e)}"
    
    def generate_weekly_report(self) -> str:
        """Generate weekly security report"""
        try:
            # Calculate date range for weekly report
            end_date = datetime.now()
            start_date = end_date - timedelta(days=7)
            
            # Get data for report (in a real implementation, this would query by date)
            threats = self.db_manager.get_recent_threats(200)
            commands = self.db_manager.get_command_history(500)
            
            # Create report content
            report_content = {
                'report_type': 'weekly',
                'generated_at': datetime.now().isoformat(),
                'period': f"weekly_{start_date.strftime('%Y%m%d')}_to_{end_date.strftime('%Y%m%d')}",
                'threat_summary': {
                    'total_threats': len(threats),
                    'high_severity': len([t for t in threats if t[2] == 'high']),
                    'medium_severity': len([t for t in threats if t[2] == 'medium']),
                    'low_severity': len([t for t in threats if t[2] == 'low'])
                },
                'top_threat_ips': self.get_top_threat_ips(threats),
                'command_activity': len(commands),
                'system_health': self.get_system_health(),
                'recommendations': self.generate_recommendations(threats)
            }
            
            # Save report to file
            filename = f"weekly_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            filepath = os.path.join(self.report_dir, filename)
            
            with open(filepath, 'w') as f:
                json.dump(report_content, f, indent=2)
            
            # Log report generation
            self.db_manager.log_command(f"generate_weekly_report", 'system', True)
            
            return f"Weekly report generated: {filepath}"
            
        except Exception as e:
            return f"Error generating weekly report: {str(e)}"
    
    def generate_monthly_report(self) -> str:
        """Generate monthly security report"""
        try:
            # Get data for report
            threats = self.db_manager.get_recent_threats(1000)
            commands = self.db_manager.get_command_history(2000)
            
            # Create comprehensive report content
            report_content = {
                'report_type': 'monthly',
                'generated_at': datetime.now().isoformat(),
                'period': 'monthly',
                'executive_summary': self.generate_executive_summary(threats, commands),
                'threat_analysis': {
                    'total_threats': len(threats),
                    'threat_trends': self.analyze_threat_trends(threats),
                    'top_threat_types': self.get_top_threat_types(threats),
                    'risk_assessment': self.assess_overall_risk(threats)
                },
                'system_performance': {
                    'command_volume': len(commands),
                    'success_rate': self.calculate_success_rate(commands),
                    'busiest_periods': self.identify_busy_periods(commands)
                },
                'security_posture': self.assess_security_posture(threats),
                'action_plan': self.create_action_plan(threats)
            }
            
            # Save report to file
            filename = f"monthly_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            filepath = os.path.join(self.report_dir, filename)
            
            with open(filepath, 'w') as f:
                json.dump(report_content, f, indent=2)
            
            # Also generate PDF version
            pdf_filepath = self.generate_pdf_report(report_content, 'monthly')
            
            # Log report generation
            self.db_manager.log_command(f"generate_monthly_report", 'system', True)
            
            return f"Monthly report generated: {filepath}" + (f", PDF: {pdf_filepath}" if pdf_filepath else "")
            
        except Exception as e:
            return f"Error generating monthly report: {str(e)}"
    
    def get_system_health(self) -> Dict[str, Any]:
        """Get system health metrics"""
        try:
            cpu_usage = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            return {
                'cpu_usage_percent': cpu_usage,
                'memory_usage_percent': memory.percent,
                'disk_usage_percent': disk.percent,
                'active_processes': len(psutil.pids()),
                'network_connections': len(psutil.net_connections())
            }
        except Exception as e:
            return {'error': str(e)}
    
    def get_top_threat_ips(self, threats: List[Tuple]) -> List[Dict[str, Any]]:
        """Get top IPs by threat count"""
        ip_counts = {}
        for threat in threats:
            ip = threat[0]
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        return [{'ip': ip, 'threat_count': count} for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]]
    
    def generate_recommendations(self, threats: List[Tuple]) -> List[str]:
        """Generate security recommendations based on threats"""
        recommendations = []
        
        high_severity_count = len([t for t in threats if t[2] == 'high'])
        if high_severity_count > 10:
            recommendations.append("Implement immediate threat containment measures for high-severity threats")
        
        unique_ips = len(set(t[0] for t in threats))
        if unique_ips > 50:
            recommendations.append("Consider implementing network segmentation and access controls")
        
        scan_threats = len([t for t in threats if 'scan' in t[1].lower()])
        if scan_threats > 20:
            recommendations.append("Enhance network monitoring for port scanning activities")
        
        return recommendations
    
    def generate_executive_summary(self, threats: List[Tuple], commands: List[Tuple]) -> Dict[str, Any]:
        """Generate executive summary for monthly report"""
        total_threats = len(threats)
        high_severity = len([t for t in threats if t[2] == 'high'])
        successful_commands = len([c for c in commands if c[3]])
        
        return {
            'total_threats': total_threats,
            'high_severity_threats': high_severity,
            'threat_resolution_rate': (total_threats - high_severity) / total_threats * 100 if total_threats > 0 else 100,
            'command_success_rate': successful_commands / len(commands) * 100 if commands else 100,
            'overall_risk_level': 'High' if high_severity > 20 else 'Medium' if high_severity > 5 else 'Low'
        }
    
    def analyze_threat_trends(self, threats: List[Tuple]) -> Dict[str, Any]:
        """Analyze threat trends over time"""
        # This would typically analyze trends across the month
        # For now, return basic analysis
        return {
            'trend': 'stable',
            'peak_threat_period': 'unknown',
            'most_common_threat_type': 'Port Scanning'
        }
    
    def get_top_threat_types(self, threats: List[Tuple]) -> List[Dict[str, Any]]:
        """Get top threat types by count"""
        type_counts = {}
        for threat in threats:
            threat_type = threat[1]
            type_counts[threat_type] = type_counts.get(threat_type, 0) + 1
        
        return [{'threat_type': ttype, 'count': count} for ttype, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:5]]
    
    def assess_overall_risk(self, threats: List[Tuple]) -> str:
        """Assess overall risk level"""
        high_severity = len([t for t in threats if t[2] == 'high'])
        
        if high_severity > 20:
            return 'Critical'
        elif high_severity > 10:
            return 'High'
        elif high_severity > 5:
            return 'Medium'
        else:
            return 'Low'
    
    def calculate_success_rate(self, commands: List[Tuple]) -> float:
        """Calculate command success rate"""
        successful = len([c for c in commands if c[3]])
        return (successful / len(commands)) * 100 if commands else 100
    
    def identify_busy_periods(self, commands: List[Tuple]) -> List[Dict[str, Any]]:
        """Identify busiest periods for commands"""
        # This would typically analyze timestamps
        # For now, return placeholder
        return [{'period': 'Morning', 'command_count': len(commands) // 3}]
    
    def assess_security_posture(self, threats: List[Tuple]) -> Dict[str, Any]:
        """Assess overall security posture"""
        high_severity = len([t for t in threats if t[2] == 'high'])
        unique_ips = len(set(t[0] for t in threats))
        
        return {
            'posture_score': max(0, 100 - (high_severity * 2 + unique_ips)),
            'strengths': ['Active monitoring', 'Threat logging', 'Regular reporting'],
            'weaknesses': ['High severity threats present' if high_severity > 0 else 'None identified'],
            'improvement_areas': ['Threat response time', 'Preventive measures']
        }
    
    def create_action_plan(self, threats: List[Tuple]) -> List[Dict[str, Any]]:
        """Create action plan for security improvements"""
        high_severity = len([t for t in threats if t[2] == 'high'])
        
        actions = []
        
        if high_severity > 10:
            actions.append({
                'priority': 'High',
                'action': 'Implement immediate threat containment',
                'timeline': 'Immediate'
            })
        
        actions.extend([
            {
                'priority': 'Medium',
                'action': 'Enhance network monitoring rules',
                'timeline': '2 weeks'
            },
            {
                'priority': 'Low',
                'action': 'Review and update security policies',
                'timeline': '1 month'
            }
        ])
        
        return actions
    
    def generate_pdf_report(self, report_content: Dict[str, Any], report_type: str) -> Optional[str]:
        """Generate PDF version of the report"""
        try:
            filename = f"{report_type}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            filepath = os.path.join(self.report_dir, filename)
            
            doc = SimpleDocTemplate(filepath, pagesize=letter)
            styles = getSampleStyleSheet()
            story = []
            
            # Title
            title = Paragraph(f"Security {report_type.capitalize()} Report", styles['Title'])
            story.append(title)
            story.append(Spacer(1, 12))
            
            # Executive Summary
            story.append(Paragraph("Executive Summary", styles['Heading2']))
            exec_summary = report_content.get('executive_summary', {})
            summary_text = f"""
            Total Threats: {exec_summary.get('total_threats', 0)}<br/>
            High Severity Threats: {exec_summary.get('high_severity_threats', 0)}<br/>
            Overall Risk Level: {exec_summary.get('overall_risk_level', 'Unknown')}<br/>
            Command Success Rate: {exec_summary.get('command_success_rate', 0):.1f}%<br/>
            """
            story.append(Paragraph(summary_text, styles['Normal']))
            story.append(Spacer(1, 12))
            
            # Threat Analysis
            story.append(Paragraph("Threat Analysis", styles['Heading2']))
            threat_data = [
                ['Metric', 'Value'],
                ['Total Threats', str(report_content.get('threat_analysis', {}).get('total_threats', 0))],
                ['Risk Assessment', report_content.get('threat_analysis', {}).get('risk_assessment', 'Unknown')],
                ['Trend', report_content.get('threat_analysis', {}).get('trends', {}).get('trend', 'Unknown')]
            ]
            
            threat_table = Table(threat_data)
            threat_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 14),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(threat_table)
            story.append(Spacer(1, 12))
            
            doc.build(story)
            return filepath
            
        except Exception as e:
            logging.error(f"PDF generation failed: {e}")
            return None

class AdvancedTelegramBotHandler:
    """Enhanced Telegram bot handler with fast command execution"""
    
    def __init__(self, monitor):
        self.monitor = monitor
        self.last_update_id = 0
        self.command_queue = NetworkTrafficQueue(max_size=50)
        self.command_handlers = self.setup_command_handlers()
        self.results_cache = {}
        self.cache_timeout = 300  # 5 minutes
        
    def setup_command_handlers(self) -> Dict[str, callable]:
        """Setup comprehensive command handlers"""
        return {
            '/start': self.handle_start,
            '/help': self.handle_help,
            '/ping_ip': self.handle_ping_ip,
            '/start_monitoring_ip': self.handle_start_monitoring_ip,
            '/stop': self.handle_stop,
            '/history': self.handle_history,
            '/add_ip': self.handle_add_ip,
            '/remove_ip': self.handle_remove_ip,
            '/clear': self.handle_clear,
            '/tracert_ip': self.handle_tracert_ip,
            '/traceroute_ip': self.handle_traceroute_ip,
            '/scan_ip': self.handle_scan_ip,
            '/deep_scan_ip': self.handle_deep_scan_ip,
            '/analyze_ip': self.handle_analyze_ip,
            '/exit': self.handle_exit,
            '/reboot_system': self.handle_reboot_system,
            '/status': self.handle_status,
            '/config_telegram_token': self.handle_config_telegram_token,
            '/config_telegram_chat_id': self.handle_config_telegram_chat_id,
            '/export_data': self.handle_export_data,
            '/generate_daily_report': self.handle_generate_daily_report,
            '/generate_weekly_report': self.handle_generate_weekly_report,
            '/generate_monthly_report': self.handle_generate_monthly_report,
            '/curl': self.handle_curl
        }
    
    def send_telegram_message(self, message: str, parse_mode: str = 'HTML') -> bool:
        """Send message to Telegram with enhanced formatting"""
        if not self.monitor.telegram_token or not self.monitor.telegram_chat_id:
            logging.error("Telegram token or chat ID not configured")
            return False
            
        try:
            url = f"https://api.telegram.org/bot{self.monitor.telegram_token}/sendMessage"
            
            # Split long messages
            if len(message) > 4096:
                messages = [message[i:i+4096] for i in range(0, len(message), 4096)]
                for msg in messages:
                    payload = {
                        'chat_id': self.monitor.telegram_chat_id,
                        'text': msg,
                        'parse_mode': parse_mode,
                        'disable_web_page_preview': True
                    }
                    response = requests.post(url, json=payload, timeout=30)
                    if response.status_code != 200:
                        return False
                    time.sleep(0.5)  # Rate limiting
                return True
            else:
                payload = {
                    'chat_id': self.monitor.telegram_chat_id,
                    'text': message,
                    'parse_mode': parse_mode,
                    'disable_web_page_preview': True
                }
                response = requests.post(url, json=payload, timeout=30)
                return response.status_code == 200
                
        except Exception as e:
            logging.error(f"Telegram send error: {e}")
            return False
    
    def handle_start(self, args: List[str]) -> str:
        """Handle /start command"""
        return """
🚀 <b>accurateOS Demo</b> 🚀

Welcome! I'm your cybersecurity OS assistant. I can help you with:

🔍 <b>Network Scanning & Monitoring</b>
/ping_ip [IP] - Ping IP address
/start_monitoring_ip [IP] - Start monitoring IP for threats
/stop - Stop all monitoring
/scan_ip [IP] - Quick port scan
/deep_scan_ip [IP] - Deep port scan (1-65535)
/analyze_ip [IP] - Comprehensive IP analysis

🌍 <b>Network Diagnostics</b>
/tracert_ip [IP] - Traceroute (Windows)
/traceroute_ip [IP] - Traceroute (Linux/Mac)

📊 <b>Management Commands</b>
/add_ip [IP] - Add IP to monitoring list
/remove_ip [IP] - Remove IP from monitoring
/history - View command history
/status - System status
/clear - Clear command history

📡 <b>HTTP Tools</b>
/curl [options] [URL] - Execute HTTP requests

📈 <b>Reporting</b>
/generate_daily_report - Generate daily security report
/generate_weekly_report - Generate weekly security report
/generate_monthly_report - Generate monthly security report
/export_data - Export collected data

⚙️ <b>Configuration</b>
/config_telegram_token [token] - Set Telegram token
/config_telegram_chat_id [id] - Set Telegram chat ID

🔧 <b>System Commands</b>
/reboot_system - Reboot the system
/exit - Exit the application

❓ <b>Help</b>
/help - Detailed help

Type /help for detailed command usage!
        """
    
    def handle_help(self, args: List[str]) -> str:
        """Show comprehensive help"""
        help_text = """
🔒 <b>Advanced Cybersecurity Monitoring Tool - Command Reference</b> 🔒

<b>🌐 Network Monitoring Commands:</b>
<code>/ping_ip 8.8.8.8</code> - Ping IP address
<code>/start_monitoring_ip 192.168.1.1</code> - Start monitoring IP for threats
<code>/stop</code> - Stop all monitoring
<code>/scan_ip 192.168.1.1</code> - Quick port scan (1-1000)
<code>/deep_scan_ip 192.168.1.1</code> - Deep port scan (1-65535)
<code>/analyze_ip 8.8.8.8</code> - Comprehensive IP threat analysis

<b>🛣️ Network Diagnostic Commands:</b>
<code>/tracert_ip google.com</code> - Traceroute (Windows)
<code>/traceroute_ip google.com</code> - Traceroute (Linux/Mac)

<b>📊 Management Commands:</b>
<code>/add_ip 192.168.1.1</code> - Add IP to monitoring
<code>/remove_ip 192.168.1.1</code> - Remove IP from monitoring
<code>/history</code> - View command history
<code>/status</code> - System status
<code>/clear</code> - Clear command history

<b>📡 CURL Commands (Full HTTP Support):</b>
<code>/curl GET https://api.example.com/data</code>
<code>/curl POST https://api.example.com -d "key=value"</code>
<code>/curl -X PUT https://api.com -d '{"data":"value"}'</code>
<code>/curl -X DELETE https://api.com/resource</code>
<code>/curl -O https://example.com/file.zip</code> - Download with original name
<code>/curl -o myfile.zip https://example.com/file.zip</code> - Download with custom name
<code>/curl -v https://example.com</code> - Verbose output
<code>/curl -s https://example.com</code> - Silent mode
<code>/curl -w "%{time_total}\n" -o /dev/null -s https://example.com</code> - Measure time
<code>/curl --retry 3 https://example.com</code> - Retry failed requests
<code>/curl --limit-rate 100k https://example.com</code> - Limit download speed
<code>/curl --compressed https://example.com</code> - Use gzip compression
<code>/curl --cookie "name=value" https://example.com</code> - Send cookies
<code>/curl --cookie-jar cookies.txt https://example.com</code> - Save cookies

<b>📈 Reporting Commands:</b>
<code>/generate_daily_report</code> - Generate daily security report
<code>/generate_weekly_report</code> - Generate weekly security report
<code>/generate_monthly_report</code> - Generate monthly security report
<code>/export_data</code> - Export collected data

<b>⚙️ Configuration Commands:</b>
<code>/config_telegram_token YOUR_BOT_TOKEN</code> - Set Telegram token
<code>/config_telegram_chat_id YOUR_CHAT_ID</code> - Set Telegram chat ID

<b>🔧 System Commands:</b>
<code>/reboot_system</code> - Reboot the system (use with caution)
<code>/exit</code> - Exit the application

<b>⚡ Performance Features:</b>
• Fast command execution with queue management
• Real-time threat monitoring
• Comprehensive reporting
• Encrypted configuration storage
• Database-backed command history

Type any command to get started! 🚀
        """
        return help_text
    
    def handle_ping_ip(self, args: List[str]) -> str:
        """Handle ping command"""
        if not args:
            return "❌ <b>Usage:</b> <code>/ping_ip [IP_ADDRESS]</code>\n\nExample: <code>/ping_ip 8.8.8.8</code>"
        
        ip = args[0]
        operation_id = f"ping_{ip}_{int(time.time())}"
        
        # Add to queue
        if not self.command_queue.add_operation(operation_id, {'type': 'ping', 'ip': ip}):
            return "⚠️ <b>Queue busy</b>\nPlease try again in a moment..."
        
        try:
            # Execute ping
            result = self.monitor.simple_ping(ip)
            
            # Format result for Telegram
            if "Ping error" in result:
                response = f"❌ <b>Ping Failed</b>\n\n<code>{result}</code>"
            else:
                # Extract relevant information from ping output
                lines = result.split('\n')
                summary = [line for line in lines if 'packets' in line.lower() or 'time' in line.lower()]
                
                response = f"🏓 <b>Ping Results for {ip}</b>\n\n"
                response += f"<code>{result[-1000:]}</code>"  # Last 1000 chars
                
            self.command_queue.complete_operation(operation_id)
            return response
            
        except Exception as e:
            self.command_queue.complete_operation(operation_id)
            return f"❌ <b>Ping Error</b>\n\n<code>{str(e)}</code>"
    
    def handle_start_monitoring_ip(self, args: List[str]) -> str:
        """Handle start monitoring IP command"""
        if not args:
            return "❌ <b>Usage:</b> <code>/start_monitoring_ip [IP_ADDRESS]</code>\n\nExample: <code>/start_monitoring_ip 192.168.1.1</code>"
        
        ip = args[0]
        
        # Validate IP address
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return f"❌ <b>Invalid IP address:</b> <code>{ip}</code>"
        
        # Add to monitoring
        self.monitor.monitored_ips.add(ip)
        self.monitor.save_config()
        
        # Log the command
        self.monitor.db_manager.log_command(f"start_monitoring_ip {ip}", 'telegram', True)
        
        return f"✅ <b>Started monitoring IP:</b> <code>{ip}</code>\n\n🔍 Now actively monitoring for threats and suspicious activity."
    
    def handle_stop(self, args: List[str]) -> str:
        """Handle stop monitoring command"""
        if not self.monitor.monitored_ips:
            return "⚠️ <b>No IPs are currently being monitored</b>"
        
        monitored_ips = list(self.monitor.monitored_ips)
        self.monitor.monitored_ips.clear()
        self.monitor.save_config()
        
        # Log the command
        self.monitor.db_manager.log_command("stop_monitoring", 'telegram', True)
        
        return f"🛑 <b>Stopped monitoring all IPs</b>\n\nStopped monitoring: {', '.join(monitored_ips)}"
    
    def handle_history(self, args: List[str]) -> str:
        """Handle command history"""
        try:
            history = self.monitor.db_manager.get_command_history(20)
            
            if not history:
                return "📝 <b>Command History</b>\n\nNo commands recorded yet."
            
            response = "📝 <b>Command History (Last 20 commands)</b>\n\n"
            for i, (command, source, timestamp, success) in enumerate(history, 1):
                status = "✅" if success else "❌"
                response += f"{i}. {status} <code>{command}</code>\n   Source: {source} | {timestamp}\n\n"
            
            return response
            
        except Exception as e:
            return f"❌ <b>History Error</b>\n\n<code>{str(e)}</code>"
    
    def handle_add_ip(self, args: List[str]) -> str:
        """Handle add IP command"""
        if not args:
            return "❌ <b>Usage:</b> <code>/add_ip [IP_ADDRESS]</code>\n\nExample: <code>/add_ip 192.168.1.1</code>"
        
        ip = args[0]
        
        # Validate IP address
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return f"❌ <b>Invalid IP address:</b> <code>{ip}</code>"
        
        # Add to monitoring list
        self.monitor.monitored_ips.add(ip)
        self.monitor.save_config()
        
        # Log the command
        self.monitor.db_manager.log_command(f"add_ip {ip}", 'telegram', True)
        
        return f"✅ <b>Added IP to monitoring:</b> <code>{ip}</code>\n\nUse /start_monitoring_ip to begin active monitoring."
    
    def handle_remove_ip(self, args: List[str]) -> str:
        """Handle remove IP command"""
        if not args:
            return "❌ <b>Usage:</b> <code>/remove_ip [IP_ADDRESS]</code>\n\nExample: <code>/remove_ip 192.168.1.1</code>"
        
        ip = args[0]
        
        if ip in self.monitor.monitored_ips:
            self.monitor.monitored_ips.remove(ip)
            self.monitor.save_config()
            
            # Log the command
            self.monitor.db_manager.log_command(f"remove_ip {ip}", 'telegram', True)
            
            return f"✅ <b>Removed IP from monitoring:</b> <code>{ip}</code>"
        else:
            return f"❌ <b>IP not found in monitoring list:</b> <code>{ip}</code>"
    
    def handle_clear(self, args: List[str]) -> str:
        """Handle clear command"""
        # Clear command history from database
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM command_history')
        conn.commit()
        conn.close()
        
        # Clear local history
        self.monitor.command_history.clear()
        
        return "✅ <b>Command History Cleared</b>\n\nAll command history has been cleared successfully."
    
    def handle_tracert_ip(self, args: List[str]) -> str:
        """Handle tracert command (Windows)"""
        if not args:
            return "❌ <b>Usage:</b> <code>/tracert_ip [HOSTNAME/IP]</code>\n\nExample: <code>/tracert_ip google.com</code>"
        
        target = args[0]
        operation_id = f"tracert_{target}_{int(time.time())}"
        
        if not self.command_queue.add_operation(operation_id, {'type': 'tracert', 'target': target}):
            return "⚠️ <b>Queue busy</b>\nPlease try again in a moment..."
        
        try:
            # Use tracert for Windows
            cmd = ['tracert', target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode != 0:
                response = f"❌ <b>Tracert Failed</b>\n\n<code>{result.stderr}</code>"
            else:
                response = f"🛣️ <b>Tracert to {target}</b>\n\n"
                response += f"<code>{result.stdout[-1500:]}</code>"  # Last 1500 chars
            
            self.command_queue.complete_operation(operation_id)
            return response
            
        except Exception as e:
            self.command_queue.complete_operation(operation_id)
            return f"❌ <b>Tracert Error</b>\n\n<code>{str(e)}</code>"
    
    def handle_traceroute_ip(self, args: List[str]) -> str:
        """Handle traceroute command (Linux/Mac)"""
        if not args:
            return "❌ <b>Usage:</b> <code>/traceroute_ip [HOSTNAME/IP]</code>\n\nExample: <code>/traceroute_ip google.com</code>"
        
        target = args[0]
        operation_id = f"traceroute_{target}_{int(time.time())}"
        
        if not self.command_queue.add_operation(operation_id, {'type': 'traceroute', 'target': target}):
            return "⚠️ <b>Queue busy</b>\nPlease try again in a moment..."
        
        try:
            # Use traceroute for Linux/Mac
            cmd = ['traceroute', target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode != 0:
                response = f"❌ <b>Traceroute Failed</b>\n\n<code>{result.stderr}</code>"
            else:
                response = f"🛣️ <b>Traceroute to {target}</b>\n\n"
                response += f"<code>{result.stdout[-1500:]}</code>"  # Last 1500 chars
            
            self.command_queue.complete_operation(operation_id)
            return response
            
        except Exception as e:
            self.command_queue.complete_operation(operation_id)
            return f"❌ <b>Traceroute Error</b>\n\n<code>{str(e)}</code>"
    
    def handle_scan_ip(self, args: List[str]) -> str:
        """Handle quick port scan"""
        if not args:
            return "❌ <b>Usage:</b> <code>/scan_ip [IP_ADDRESS]</code>\n\nExample: <code>/scan_ip 192.168.1.1</code>"
        
        ip = args[0]
        operation_id = f"scan_{ip}_{int(time.time())}"
        
        if not self.command_queue.add_operation(operation_id, {'type': 'scan', 'ip': ip}):
            return "⚠️ <b>Queue busy</b>\nPlease try again in a moment..."
        
        try:
            self.send_telegram_message(f"🔍 <b>Starting quick scan of {ip}...</b>")
            result = self.monitor.port_scanner.quick_scan(ip)
            
            if 'error' in result:
                response = f"❌ <b>Scan Error</b>\n\n<code>{result['error']}</code>"
            else:
                open_ports = result.get('open_ports', [])
                response = f"🔍 <b>Quick Scan Results for {ip}</b>\n\n"
                response += f"📊 <b>Ports Scanned:</b> {result.get('ports_scanned', 'N/A')}\n"
                response += f"⏱️ <b>Duration:</b> {result.get('scan_duration', 'N/A')}s\n"
                response += f"🟢 <b>Open Ports:</b> {len(open_ports)}\n\n"
                
                if open_ports:
                    response += "<b>Open Ports:</b>\n"
                    response += "<code>" + ", ".join(map(str, open_ports)) + "</code>"
                else:
                    response += "🔒 <b>No open ports found</b>"
            
            self.command_queue.complete_operation(operation_id)
            return response
            
        except Exception as e:
            self.command_queue.complete_operation(operation_id)
            return f"❌ <b>Scan Error</b>\n\n<code>{str(e)}</code>"
    
    def handle_deep_scan_ip(self, args: List[str]) -> str:
        """Handle deep port scan"""
        if not args:
            return "❌ <b>Usage:</b> <code>/deep_scan_ip [IP_ADDRESS]</code>\n\nExample: <code>/deep_scan_ip 192.168.1.1</code>"
        
        ip = args[0]
        operation_id = f"deep_scan_{ip}_{int(time.time())}"
        
        if not self.command_queue.add_operation(operation_id, {'type': 'deep_scan', 'ip': ip}):
            return "⚠️ <b>Queue busy</b>\nPlease try again in a moment..."
        
        try:
            self.send_telegram_message(f"🔍 <b>Starting deep scan of {ip}...</b>\nThis may take a few minutes.")
            result = self.monitor.port_scanner.deep_scan(ip)
            
            if 'error' in result:
                response = f"❌ <b>Deep Scan Error</b>\n\n<code>{result['error']}</code>"
            else:
                open_ports = result.get('open_ports', [])
                response = f"🔍 <b>Deep Scan Results for {ip}</b>\n\n"
                response += f"📊 <b>Ports Scanned:</b> {result.get('ports_scanned', 'N/A')}\n"
                response += f"⏱️ <b>Duration:</b> {result.get('scan_duration', 'N/A')}s\n"
                response += f"🟢 <b>Open Ports:</b> {len(open_ports)}\n\n"
                
                if open_ports:
                    response += "<b>Open Ports with Services:</b>\n"
                    for port_info in open_ports[:10]:  # Limit to first 10
                        response += f"• Port {port_info['port']}: {port_info['service']} {port_info.get('version', '')}\n"
                    
                    if len(open_ports) > 10:
                        response += f"\n... and {len(open_ports) - 10} more ports"
                else:
                    response += "🔒 <b>No open ports found</b>"
            
            self.command_queue.complete_operation(operation_id)
            return response
            
        except Exception as e:
            self.command_queue.complete_operation(operation_id)
            return f"❌ <b>Deep Scan Error</b>\n\n<code>{str(e)}</code>"
    
    def handle_analyze_ip(self, args: List[str]) -> str:
        """Handle IP analysis command"""
        if not args:
            return "❌ <b>Usage:</b> <code>/analyze_ip [IP_ADDRESS]</code>\n\nExample: <code>/analyze_ip 8.8.8.8</code>"
        
        ip = args[0]
        operation_id = f"analyze_{ip}_{int(time.time())}"
        
        if not self.command_queue.add_operation(operation_id, {'type': 'analyze', 'ip': ip}):
            return "⚠️ <b>Queue busy</b>\nPlease try again in a moment..."
        
        try:
            self.send_telegram_message(f"🔍 <b>Starting comprehensive analysis of {ip}...</b>")
            
            # Perform threat analysis
            analysis = self.monitor.threat_intelligence.analyze_ip_reputation(ip)
            
            response = f"🔍 <b>Threat Analysis for {ip}</b>\n\n"
            response += f"📊 <b>Risk Score:</b> {analysis.get('risk_score', 0)}/100\n"
            response += f"🛡️ <b>Reputation:</b> {analysis.get('reputation', 'Unknown')}\n\n"
            
            threat_indicators = analysis.get('threat_indicators', [])
            if threat_indicators:
                response += "🚨 <b>Threat Indicators:</b>\n"
                for indicator in threat_indicators[:5]:  # Limit to 5 indicators
                    response += f"• {indicator}\n"
            else:
                response += "✅ <b>No significant threats detected</b>\n"
            
            # Add location information
            location_info = self.monitor.advanced_ip_location(ip)
            try:
                location_data = json.loads(location_info)
                response += f"\n🌍 <b>Location:</b> {location_data.get('city', 'N/A')}, {location_data.get('country', 'N/A')}\n"
                response += f"🏢 <b>ISP:</b> {location_data.get('isp', 'N/A')}\n"
            except:
                pass
            
            self.command_queue.complete_operation(operation_id)
            return response
            
        except Exception as e:
            self.command_queue.complete_operation(operation_id)
            return f"❌ <b>Analysis Error</b>\n\n<code>{str(e)}</code>"
    
    def handle_exit(self, args: List[str]) -> str:
        """Handle exit command"""
        return "🛑 <b>Exit Command Received</b>\n\nUse this command in the local terminal to exit the application."
    
    def handle_reboot_system(self, args: List[str]) -> str:
        """Handle reboot system command"""
        return "⚠️ <b>Reboot System</b>\n\nThis command would reboot the system. Use with extreme caution!\n\nFor safety, this command is disabled in the Telegram interface."
    
    def handle_status(self, args: List[str]) -> str:
        """Handle status command"""
        queue_status = self.command_queue.get_queue_status()
        system_info = self.monitor.get_detailed_system_info()
        
        response = "📊 <b>System Status</b>\n\n"
        response += f"✅ <b>Bot Status:</b> Online and Active\n"
        response += f"📡 <b>Telegram Connected:</b> {'Yes' if self.monitor.telegram_token and self.monitor.telegram_chat_id else 'No'}\n"
        response += f"🔍 <b>IPs Being Monitored:</b> {len(self.monitor.monitored_ips)}\n"
        response += f"🔄 <b>Queue Status:</b> {queue_status['queue_size']} pending, {queue_status['active_operations']} active\n"
        response += f"💻 <b>CPU Usage:</b> {system_info.get('resources', {}).get('cpu_usage', 'N/A')}%\n"
        response += f"🧠 <b>Memory Used:</b> {system_info.get('resources', {}).get('memory_used', 0) / (1024**3):.2f} GB\n"
        response += f"🌐 <b>Active Connections:</b> {system_info.get('network', {}).get('connections', 'N/A')}\n\n"
        response += "🚀 <b>All systems operational</b>"
        
        return response
    
    def handle_config_telegram_token(self, args: List[str]) -> str:
        """Handle Telegram token configuration"""
        if not args:
            return "❌ <b>Usage:</b> <code>/config_telegram_token [YOUR_BOT_TOKEN]</code>\n\nExample: <code>/config_telegram_token 1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZ</code>"
        
        token = args[0]
        self.monitor.telegram_token = token
        self.monitor.save_config()
        
        # Test the token
        test_result = self.send_telegram_message("✅ <b>Telegram token configured successfully!</b>\n\nBot is now ready to receive commands.")
        
        if test_result:
            return f"✅ <b>Telegram Token Configured</b>\n\nToken has been set and verified successfully!\n\nBot is now ready to receive commands."
        else:
            return "❌ <b>Token Configuration Failed</b>\n\nThe token was saved but could not be verified. Please check your token and try again."
    
    def handle_config_telegram_chat_id(self, args: List[str]) -> str:
        """Handle Telegram chat ID configuration"""
        if not args:
            return "❌ <b>Usage:</b> <code>/config_telegram_chat_id [YOUR_CHAT_ID]</code>\n\nExample: <code>/config_telegram_chat_id 123456789</code>"
        
        chat_id = args[0]
        self.monitor.telegram_chat_id = chat_id
        self.monitor.save_config()
        
        # Test the chat ID
        test_result = self.send_telegram_message("✅ <b>Telegram chat ID configured successfully!</b>\n\nThis chat is now registered for commands.")
        
        if test_result:
            return f"✅ <b>Telegram Chat ID Configured</b>\n\nChat ID has been set and verified successfully!\n\nThis chat will now receive all bot responses."
        else:
            return "❌ <b>Chat ID Configuration Failed</b>\n\nThe chat ID was saved but could not be verified. Please check your chat ID and try again."
    
    def handle_export_data(self, args: List[str]) -> str:
        """Handle data export"""
        operation_id = f"export_data_{int(time.time())}"
        
        if not self.command_queue.add_operation(operation_id, {'type': 'export_data'}):
            return "⚠️ <b>Queue busy</b>\nPlease try again in a moment..."
        
        try:
            # Collect data for export
            export_data = {
                'timestamp': datetime.now().isoformat(),
                'system_info': self.monitor.get_detailed_system_info(),
                'monitored_ips': list(self.monitor.monitored_ips),
                'network_stats': {
                    'io_counters': psutil.net_io_counters()._asdict(),
                    'connections': len(psutil.net_connections())
                },
                'command_history': self.monitor.db_manager.get_command_history(100),
                'recent_threats': self.monitor.db_manager.get_recent_threats(50),
                'queue_status': self.command_queue.get_queue_status()
            }
            
            # Create export file
            filename = f"export_{int(time.time())}.json"
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            self.command_queue.complete_operation(operation_id)
            return f"✅ <b>Data Export Completed</b>\n\nData has been exported to: <code>{filename}</code>\n\nExported information:\n• System information\n• Monitored IPs\n• Network statistics\n• Command history\n• Recent threats\n• Queue status"

        except Exception as e:
            self.command_queue.complete_operation(operation_id)
            return f"❌ <b>Export Error</b>\n\n<code>{str(e)}</code>"
    
    def handle_generate_daily_report(self, args: List[str]) -> str:
        """Handle daily report generation"""
        operation_id = f"daily_report_{int(time.time())}"
        
        if not self.command_queue.add_operation(operation_id, {'type': 'daily_report'}):
            return "⚠️ <b>Queue busy</b>\nPlease try again in a moment..."
        
        try:
            result = self.monitor.report_generator.generate_daily_report()
            self.command_queue.complete_operation(operation_id)
            
            if "Error" in result:
                return f"❌ <b>Daily Report Error</b>\n\n<code>{result}</code>"
            else:
                return f"📊 <b>Daily Report Generated</b>\n\n{result}"
                
        except Exception as e:
            self.command_queue.complete_operation(operation_id)
            return f"❌ <b>Daily Report Error</b>\n\n<code>{str(e)}</code>"
    
    def handle_generate_weekly_report(self, args: List[str]) -> str:
        """Handle weekly report generation"""
        operation_id = f"weekly_report_{int(time.time())}"
        
        if not self.command_queue.add_operation(operation_id, {'type': 'weekly_report'}):
            return "⚠️ <b>Queue busy</b>\nPlease try again in a moment..."
        
        try:
            result = self.monitor.report_generator.generate_weekly_report()
            self.command_queue.complete_operation(operation_id)
            
            if "Error" in result:
                return f"❌ <b>Weekly Report Error</b>\n\n<code>{result}</code>"
            else:
                return f"📊 <b>Weekly Report Generated</b>\n\n{result}"
                
        except Exception as e:
            self.command_queue.complete_operation(operation_id)
            return f"❌ <b>Weekly Report Error</b>\n\n<code>{str(e)}</code>"
    
    def handle_generate_monthly_report(self, args: List[str]) -> str:
        """Handle monthly report generation"""
        operation_id = f"monthly_report_{int(time.time())}"
        
        if not self.command_queue.add_operation(operation_id, {'type': 'monthly_report'}):
            return "⚠️ <b>Queue busy</b>\nPlease try again in a moment..."
        
        try:
            result = self.monitor.report_generator.generate_monthly_report()
            self.command_queue.complete_operation(operation_id)
            
            if "Error" in result:
                return f"❌ <b>Monthly Report Error</b>\n\n<code>{result}</code>"
            else:
                return f"📊 <b>Monthly Report Generated</b>\n\n{result}"
                
        except Exception as e:
            self.command_queue.complete_operation(operation_id)
            return f"❌ <b>Monthly Report Error</b>\n\n<code>{str(e)}</code>"
    
    def handle_curl(self, args: List[str]) -> str:
        """Handle curl commands"""
        if not args:
            return "❌ <b>Usage:</b> <code>/curl [OPTIONS] [URL]</code>\n\nExamples:\n<code>/curl GET https://httpbin.org/json</code>\n<code>/curl -X POST https://httpbin.org/post -d 'test=data'</code>\n<code>/curl -H 'Authorization: Bearer token' https://api.example.com</code>"
        
        operation_id = f"curl_{int(time.time())}"
        
        if not self.command_queue.add_operation(operation_id, {'type': 'curl', 'args': args}):
            return "⚠️ <b>Queue busy</b>\nPlease try again in a moment..."
        
        try:
            result = self.monitor.execute_curl(args)
            
            if 'error' in result:
                response = f"❌ <b>CURL Error</b>\n\n<code>{result['error']}</code>"
            else:
                response = f"📡 <b>CURL Request Completed</b>\n\n"
                response += f"<b>URL:</b> <code>{result.get('url', 'N/A')}</code>\n"
                response += f"<b>Status Code:</b> {result.get('status_code', 'N/A')}\n"
                response += f"<b>Response Size:</b> {len(result.get('content', ''))} bytes\n\n"
                
                # Show headers
                headers = result.get('headers', {})
                if headers:
                    response += "<b>Response Headers:</b>\n"
                    for key, value in list(headers.items())[:5]:  # First 5 headers
                        response += f"<code>{key}: {value}</code>\n"
                
                # Show content preview
                content = result.get('content', '')
                if content:
                    preview = content[:500] + "..." if len(content) > 500 else content
                    response += f"\n<b>Content Preview:</b>\n<code>{preview}</code>"
            
            self.command_queue.complete_operation(operation_id)
            return response
            
        except Exception as e:
            self.command_queue.complete_operation(operation_id)
            return f"❌ <b>CURL Error</b>\n\n<code>{str(e)}</code>"
    
    def process_telegram_commands(self):
        """Process incoming Telegram commands with enhanced error handling"""
        if not self.monitor.telegram_token:
            logging.warning("Telegram token not configured")
            return
            
        try:
            url = f"https://api.telegram.org/bot{self.monitor.telegram_token}/getUpdates"
            params = {
                'offset': self.last_update_id + 1, 
                'timeout': 10,
                'allowed_updates': ['message']
            }
            response = requests.get(url, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                if data['ok'] and 'result' in data:
                    for update in data['result']:
                        self.last_update_id = update['update_id']
                        if 'message' in update and 'text' in update['message']:
                            self.process_message(update['message'])
            elif response.status_code == 401:
                logging.error("Invalid Telegram bot token")
            elif response.status_code == 409:
                logging.error("Another instance is already getting updates")
                
        except requests.exceptions.Timeout:
            logging.debug("Telegram update timeout")
        except requests.exceptions.ConnectionError:
            logging.error("Telegram connection error")
        except Exception as e:
            logging.error(f"Telegram update error: {e}")

    def process_message(self, message):
        """Process individual Telegram message with fast execution"""
        text = message['text']
        chat_id = message['chat']['id']
        
        # Update chat ID if not set
        if not self.monitor.telegram_chat_id:
            self.monitor.telegram_chat_id = chat_id
            self.monitor.save_config()
            logging.info(f"Telegram chat ID set to: {chat_id}")
        
        # Log command
        self.monitor.db_manager.log_command(text, 'telegram', True)
        logging.info(f"Telegram command received: {text}")
        
        # Parse command
        parts = text.split()
        command = parts[0]
        args = parts[1:] if len(parts) > 1 else []
        
        # Handle command
        if command in self.command_handlers:
            try:
                # Execute command in thread for faster response
                def execute_command():
                    try:
                        response = self.command_handlers[command](args)
                        self.send_telegram_message(response)
                    except Exception as e:
                        error_msg = f"❌ <b>Error executing command:</b>\n\n<code>{str(e)}</code>"
                        self.send_telegram_message(error_msg)
                
                # Start command execution in separate thread
                thread = threading.Thread(target=execute_command, daemon=True)
                thread.start()
                
                # Send immediate acknowledgment for longer operations
                if command not in ['/start', '/help', '/status', '/history']:  # Don't send ack for these
                    ack_msg = f"⚡ <b>Command received:</b> <code>{command}</code>\n\n🔄 Processing..."
                    self.send_telegram_message(ack_msg)
                
            except Exception as e:
                error_msg = f"❌ <b>Command execution failed:</b>\n\n<code>{str(e)}</code>"
                self.send_telegram_message(error_msg)
        else:
            self.send_telegram_message(
                "❌ <b>Unknown command</b>\n\n"
                "Type /help to see available commands.\n"
                "Use /start to see the main menu."
            )

class AdvancedCybersecurityMonitor:
    def __init__(self):
        self.monitored_ips = set()
        self.monitoring_active = False
        self.command_history = []
        self.telegram_token = None
        self.telegram_chat_id = None
        self.telegram_bot = None
        self.logs = []
        self.threat_alerts = []
        self.color_manager = ColorManager()
        self.encryption_manager = EncryptionManager()
        self.network_scanner = NetworkScanner()
        self.curl_manager = CurlManager()
        self.ping_manager = AdvancedPingManager()
        self.port_scanner = AdvancedPortScanner()
        self.threat_intelligence = ThreatIntelligence()
        self.db_manager = DatabaseManager()
        self.report_generator = ReportGenerator(self.db_manager)
        self.setup_logging()
        self.load_config()
        
        # Network traffic management
        self.traffic_queue = NetworkTrafficQueue(max_size=100)
        
        # Start monitoring thread
        self.monitoring_thread = None
        self.should_monitor = False
        
    def setup_logging(self):
        """Setup comprehensive logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(module)s - %(message)s',
            handlers=[
                logging.FileHandler('cyber_security_advanced.log'),
                logging.StreamHandler(sys.stdout),
                logging.handlers.RotatingFileHandler(
                    'cyber_security_rotating.log',
                    maxBytes=10*1024*1024,  # 10MB
                    backupCount=5
                )
            ]
        )
        
        # Create logger for security events
        self.security_logger = logging.getLogger('security')
        security_handler = logging.FileHandler('security_events.log')
        security_handler.setFormatter(logging.Formatter(
            '%(asctime)s - SECURITY - %(levelname)s - %(message)s'
        ))
        self.security_logger.addHandler(security_handler)
        
    def load_config(self):
        """Load configuration with encryption"""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    encrypted_config = json.load(f)
                    
                    # Decrypt sensitive fields
                    config = {}
                    for key, value in encrypted_config.items():
                        if key in ['telegram_token', 'telegram_chat_id', 'api_keys']:
                            try:
                                config[key] = self.encryption_manager.decrypt(value)
                            except:
                                config[key] = value
                        else:
                            config[key] = value
                    
                    self.telegram_token = config.get('telegram_token')
                    self.telegram_chat_id = config.get('telegram_chat_id')
                    self.monitored_ips = set(config.get('monitored_ips', []))
                    self.api_keys = config.get('api_keys', {})
                    
        except Exception as e:
            logging.error(f"Error loading config: {e}")
            self.api_keys = {}
            
    def save_config(self):
        """Save configuration with encryption"""
        try:
            config = {
                'telegram_token': self.encryption_manager.encrypt(self.telegram_token) if self.telegram_token else None,
                'telegram_chat_id': self.encryption_manager.encrypt(self.telegram_chat_id) if self.telegram_chat_id else None,
                'monitored_ips': list(self.monitored_ips),
                'api_keys': {k: self.encryption_manager.encrypt(v) for k, v in self.api_keys.items()}
            }
            
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
                
        except Exception as e:
            logging.error(f"Error saving config: {e}")

    # Enhanced methods for Telegram integration
    def simple_ping(self, ip: str) -> str:
        """Simple ping that works reliably"""
        return self.ping_manager.simple_ping(ip)
    
    def advanced_ip_location(self, ip: str) -> str:
        """Get IP location information"""
        try:
            # Use ip-api.com for reliable location data
            url = f"http://ip-api.com/json/{ip}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data['status'] == 'success':
                    return json.dumps({
                        'ip': ip,
                        'country': data.get('country', 'N/A'),
                        'region': data.get('regionName', 'N/A'),
                        'city': data.get('city', 'N/A'),
                        'isp': data.get('isp', 'N/A'),
                        'org': data.get('org', 'N/A'),
                        'lat': data.get('lat', 'N/A'),
                        'lon': data.get('lon', 'N/A'),
                        'timezone': data.get('timezone', 'N/A')
                    }, indent=2)
                else:
                    return f"Location error: {data.get('message', 'Unknown error')}"
            else:
                return f"Location error: HTTP {response.status_code}"
                
        except Exception as e:
            return f"Location error: {str(e)}"
    
    def execute_curl(self, args: List[str]) -> Dict[str, Any]:
        """Execute curl command"""
        return self.curl_manager.execute_curl_command(args)
    
    def network_speed_test(self) -> Dict[str, Any]:
        """Perform network speed test"""
        try:
            st = speedtest.Speedtest()
            st.get_best_server()
            
            download_speed = st.download() / 1_000_000  # Mbps
            upload_speed = st.upload() / 1_000_000  # Mbps
            ping = st.results.ping
            
            return {
                'download_mbps': round(download_speed, 2),
                'upload_mbps': round(upload_speed, 2),
                'ping_ms': round(ping, 2),
                'server': st.results.server,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def whois_lookup(self, domain: str) -> Dict[str, Any]:
        """Perform WHOIS lookup"""
        try:
            w = whois.whois(domain)
            return {
                'domain': domain,
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'name_servers': w.name_servers,
                'status': w.status,
                'emails': w.emails
            }
        except Exception as e:
            return {'error': str(e)}
    
    def dns_lookup(self, domain: str, record_type: str = 'A') -> Dict[str, Any]:
        """Perform DNS lookup"""
        try:
            answers = dns.resolver.resolve(domain, record_type)
            return {
                'domain': domain,
                'record_type': record_type,
                'results': [str(r) for r in answers],
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def comprehensive_port_scan(self, ip: str, ports: str = "1-1000") -> Dict[str, Any]:
        """Perform comprehensive port scan"""
        try:
            open_ports = []
            if '-' in ports:
                start_port, end_port = map(int, ports.split('-'))
                port_range = range(start_port, end_port + 1)
            else:
                port_range = [int(port.strip()) for port in ports.split(',')]
            
            # Limit for performance
            port_range = list(port_range)[:100]
            
            def scan_port(port):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((ip, port))
                    sock.close()
                    return port if result == 0 else None
                except:
                    return None
            
            # Use thread pool for faster scanning
            with ThreadPoolExecutor(max_workers=20) as executor:
                results = executor.map(scan_port, port_range)
                open_ports = [port for port in results if port is not None]
            
            return {
                'target': ip,
                'ports_scanned': len(port_range),
                'open_ports': open_ports,
                'scan_timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def get_detailed_system_info(self) -> Dict[str, Any]:
        """Get detailed system information"""
        try:
            system_info = {
                'platform': {
                    'system': platform.system(),
                    'release': platform.release(),
                    'version': platform.version(),
                    'machine': platform.machine(),
                    'processor': platform.processor()
                },
                'resources': {
                    'cpu_cores': psutil.cpu_count(),
                    'cpu_usage': psutil.cpu_percent(interval=1),
                    'memory_total': psutil.virtual_memory().total,
                    'memory_available': psutil.virtual_memory().available,
                    'memory_used': psutil.virtual_memory().used,
                    'disk_usage': psutil.disk_usage('/')._asdict()
                },
                'network': {
                    'hostname': socket.gethostname(),
                    'local_ip': socket.gethostbyname(socket.gethostname()),
                    'connections': len(psutil.net_connections()),
                    'io_counters': psutil.net_io_counters()._asdict()
                },
                'users': {
                    'current_user': getpass.getuser(),
                    'boot_time': psutil.boot_time(),
                    'users': [u._asdict() for u in psutil.users()]
                }
            }
            return system_info
        except Exception as e:
            return {'error': str(e)}
    
    def start_monitoring(self):
        """Start monitoring IPs for threats"""
        if self.monitoring_active:
            return "Monitoring is already active"
        
        self.should_monitor = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_worker, daemon=True)
        self.monitoring_thread.start()
        self.monitoring_active = True
        return "Monitoring started"
    
    def stop_monitoring(self):
        """Stop monitoring IPs"""
        self.should_monitor = False
        self.monitoring_active = False
        return "Monitoring stopped"
    
    def _monitoring_worker(self):
        """Worker thread for monitoring IPs"""
        while self.should_monitor:
            try:
                for ip in list(self.monitored_ips):
                    # Perform basic threat checks
                    self._check_ip_threats(ip)
                
                # Sleep before next check
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                logging.error(f"Monitoring error: {e}")
                time.sleep(30)
    
    def _check_ip_threats(self, ip: str):
        """Check for threats on a specific IP"""
        try:
            # Perform quick port scan to check for suspicious activity
            scan_result = self.port_scanner.quick_scan(ip)
            
            if 'error' not in scan_result:
                open_ports = scan_result.get('open_ports', [])
                
                # Check for suspicious ports
                suspicious_ports = [22, 23, 135, 139, 445, 1433, 3389]  # Common attack vectors
                found_suspicious = [port for port in open_ports if port in suspicious_ports]
                
                if found_suspicious:
                    threat_msg = f"Suspicious ports open on {ip}: {found_suspicious}"
                    self.db_manager.log_threat(ip, 'Suspicious Ports', 'medium', threat_msg)
                    
                    # Send Telegram alert if configured
                    if self.telegram_token and self.telegram_chat_id:
                        telegram_handler = AdvancedTelegramBotHandler(self)
                        alert_msg = f"🚨 <b>Threat Detected</b>\n\nIP: <code>{ip}</code>\nThreat: Suspicious ports open\nPorts: {found_suspicious}"
                        telegram_handler.send_telegram_message(alert_msg)
                        
        except Exception as e:
            logging.error(f"Threat check error for {ip}: {e}")

def main():
    """Main function with enhanced Telegram integration"""
    monitor = AdvancedCybersecurityMonitor()
    telegram_handler = AdvancedTelegramBotHandler(monitor)
    
    def print_colored(text, color_type='primary'):
        color = monitor.color_manager.get_color(color_type)
        print(f"{color}{text}{Style.RESET_ALL}")
    
    def print_banner():
        banner = pyfiglet.figlet_format("CYBER SECURITY", font="slant")
        colored_banner = monitor.color_manager.colorize(banner, 'primary')
        
        info_text = """
        🛡️  ================================================================
        🛡️           accurateOS Demo
        🛡️  ================================================================
        🛡️    
        🛡️   Telegram Bot: ACTIVE
        🛡️   Version:0000| Enhanced Security Edition
        🛡️   Database: Ready
        🛡️   Threat Intelligence: Active
        🛡️   
        🛡️  ================================================================
        """
        print_colored(banner + info_text, 'primary')
    
    def setup_telegram_config():
        """Setup Telegram configuration"""
        if not monitor.telegram_token:
            print_colored("\n🔧 Telegram Bot Setup", 'highlight')
            print_colored("To use Telegram commands, you need to:", 'info')
            print_colored("1. Create a bot with @BotFather on Telegram", 'info')
            print_colored("2. Get your bot token", 'info')
            print_colored("3. Start a chat with your bot and send /start", 'info')
            print_colored("4. Get your chat ID", 'info')
            
            token = input("Enter your Telegram bot token (or press Enter to skip): ").strip()
            if token:
                monitor.telegram_token = token
                print_colored("✅ Token saved. Now start a chat with your bot and send any message.", 'success')
                input("Press Enter after you've sent a message to your bot...")
                
                # Try to get chat ID automatically
                try:
                    url = f"https://api.telegram.org/bot{token}/getUpdates"
                    response = requests.get(url, timeout=10)
                    if response.status_code == 200:
                        data = response.json()
                        if data['ok'] and data['result']:
                            chat_id = data['result'][-1]['message']['chat']['id']
                            monitor.telegram_chat_id = chat_id
                            print_colored(f"✅ Chat ID automatically detected: {chat_id}", 'success')
                        else:
                            chat_id = input("Enter your chat ID: ").strip()
                            monitor.telegram_chat_id = chat_id
                except:
                    chat_id = input("Enter your chat ID: ").strip()
                    monitor.telegram_chat_id = chat_id
                
                monitor.save_config()
                print_colored("✅ Telegram configuration completed!", 'success')
                print_colored("🤖 You can now use all commands via Telegram!", 'highlight')
            else:
                print_colored("⚠️ Telegram features disabled. You can configure later.", 'warning')
    
    # Start Telegram command processor in separate thread
    def telegram_command_processor():
        while True:
            try:
                telegram_handler.process_telegram_commands()
                time.sleep(2)  # Process every 2 seconds for fast response
            except Exception as e:
                logging.error(f"Telegram processor error: {e}")
                time.sleep(10)
    
    telegram_thread = threading.Thread(target=telegram_command_processor, daemon=True)
    telegram_thread.start()
    
    # Start queue monitor
    def queue_monitor():
        while True:
            try:
                status = telegram_handler.command_queue.get_queue_status()
                if status['queue_size'] > 0 or status['active_operations'] > 0:
                    logging.debug(f"Queue status: {status}")
                time.sleep(10)
            except Exception as e:
                logging.error(f"Queue monitor error: {e}")
                time.sleep(30)
    
    queue_thread = threading.Thread(target=queue_monitor, daemon=True)
    queue_thread.start()
    
    # Start threat monitoring if IPs are configured
    if monitor.monitored_ips:
        monitor.start_monitoring()
        print_colored(f"✅ Started monitoring {len(monitor.monitored_ips)} IPs", 'success')
    
    print_banner()
    setup_telegram_config()
    
    if monitor.telegram_token and monitor.telegram_chat_id:
        print_colored("✅ Telegram bot is ACTIVE and listening for commands", 'success')
        print_colored("📱 Open Telegram and send /start to your bot", 'info')
        print_colored("⚡ Commands will be executed instantly via Telegram", 'highlight')
        
        # Test connection
        test_result = telegram_handler.send_telegram_message(
            "🔗 <b>Accurate Online OS Demo- Connection Established</b>\n\n"
            "✅ <b>Bot is online and ready!</b>\n"
            "🚀 Type /help to see all available commands\n"
            "⚡ Commands execute instantly with queue management\n"
            "🔍 Threat monitoring is active\n"
            "📊 Reporting system is ready"
        )
        
        if test_result:
            print_colored("✅ Test message sent to Telegram successfully", 'success')
        else:
            print_colored("❌ Failed to send test message to Telegram", 'error')
    else:
        print_colored("ℹ️  Telegram features are disabled", 'info')
        print_colored("💡 You can configure Telegram later using the config command", 'info')
    
    print_colored("\n💻 Local terminal commands are also available", 'info')
    print_colored("📋 Type 'help' for local command list", 'info')
    
    # Local command interface
    def handle_local_command(command: str, args: List[str]) -> str:
        """Handle local terminal commands"""
        if command == 'help':
            return """
Local Commands:
- ping [ip] - Ping IP address
- start_monitoring [ip] - Start monitoring IP for threats
- stop_monitoring - Stop all monitoring
- add_ip [ip] - Add IP to monitoring list
- remove_ip [ip] - Remove IP from monitoring list
- list_ips - List monitored IPs
- scan [ip] - Quick port scan
- deep_scan [ip] - Deep port scan (1-65535)
- analyze [ip] - Analyze IP for threats
- tracert [ip] - Traceroute (Windows)
- traceroute [ip] - Traceroute (Linux/Mac)
- status - System status
- history - Command history
- generate_daily_report - Generate daily security report
- generate_weekly_report - Generate weekly security report
- generate_monthly_report - Generate monthly security report
- config - Configure Telegram settings
- clear - Clear screen
- exit - Exit program

All commands are also available via Telegram!
            """
        elif command == 'ping' and args:
            return monitor.simple_ping(args[0])
        elif command == 'start_monitoring' and args:
            monitor.monitored_ips.add(args[0])
            monitor.save_config()
            monitor.start_monitoring()
            return f"Started monitoring {args[0]}"
        elif command == 'stop_monitoring':
            return monitor.stop_monitoring()
        elif command == 'add_ip' and args:
            monitor.monitored_ips.add(args[0])
            monitor.save_config()
            return f"Added {args[0]} to monitoring list"
        elif command == 'remove_ip' and args:
            if args[0] in monitor.monitored_ips:
                monitor.monitored_ips.remove(args[0])
                monitor.save_config()
                return f"Removed {args[0]} from monitoring list"
            else:
                return f"IP {args[0]} not found in monitoring list"
        elif command == 'list_ips':
            return f"Monitored IPs: {', '.join(monitor.monitored_ips) if monitor.monitored_ips else 'None'}"
        elif command == 'scan' and args:
            result = monitor.port_scanner.quick_scan(args[0])
            return json.dumps(result, indent=2)
        elif command == 'deep_scan' and args:
            result = monitor.port_scanner.deep_scan(args[0])
            return json.dumps(result, indent=2)
        elif command == 'analyze' and args:
            result = monitor.threat_intelligence.analyze_ip_reputation(args[0])
            return json.dumps(result, indent=2)
        elif command == 'tracert' and args:
            # Windows tracert
            cmd = ['tracert', args[0]]
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.stdout
        elif command == 'traceroute' and args:
            # Linux/Mac traceroute
            cmd = ['traceroute', args[0]]
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.stdout
        elif command == 'status':
            system_info = monitor.get_detailed_system_info()
            return json.dumps(system_info, indent=2)
        elif command == 'history':
            history = monitor.db_manager.get_command_history(20)
            return "\n".join([f"{cmd} ({src}) - {ts}" for cmd, src, ts, success in history])
        elif command == 'generate_daily_report':
            return monitor.report_generator.generate_daily_report()
        elif command == 'generate_weekly_report':
            return monitor.report_generator.generate_weekly_report()
        elif command == 'generate_monthly_report':
            return monitor.report_generator.generate_monthly_report()
        elif command == 'config':
            setup_telegram_config()
            return "Configuration updated"
        elif command == 'clear':
            os.system('cls' if os.name == 'nt' else 'clear')
            print_banner()
            return ""
        else:
            return f"Unknown command: {command}. Type 'help' for available commands."
    
    # Main command loop
    while True:
        try:
            prompt = f"{monitor.color_manager.get_color('primary')}accurateOS> {Style.RESET_ALL}"
            user_input = input(prompt).strip()
            
            if not user_input:
                continue
                
            parts = user_input.split()
            command = parts[0].lower()
            args = parts[1:]
            
            if command == 'exit':
                print_colored("👋 Exiting Accurate Online OS Demo...", 'warning')
                monitor.stop_monitoring()
                break
            else:
                result = handle_local_command(command, args)
                if result:
                    print_colored(result, 'info')
                    
                # Log the command
                monitor.db_manager.log_command(user_input, 'local', True)
                
        except KeyboardInterrupt:
            print_colored("\n👋 Exiting Accurate Online OS Demo...", 'warning')
            monitor.stop_monitoring()
            break
        except Exception as e:
            print_colored(f"❌ Error: {e}", 'error')
            monitor.db_manager.log_command(user_input, 'local', False)

if __name__ == "__main__":
    # Check and install required packages
    required_packages = [
        'scapy', 'requests', 'psutil', 'colorama', 'pyfiglet', 
        'speedtest-cli', 'python-whois', 'dnspython', 'qrcode',
        'pillow', 'cryptography', 'pyjwt', 'paramiko', 'nmap',
        'asyncssh', 'aiohttp', 'reportlab', 'matplotlib'
    ]
    
    print("🔍 Checking required packages...")
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            print(f"📦 Installing {package}...")
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
    
    print("🚀 Starting Accurate Online OS Demo...")
    main()