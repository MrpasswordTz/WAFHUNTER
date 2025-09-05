#!/usr/bin/env python3
"""
WAFHUNTER - Enhanced Detection Modules
Advanced WAF detection with multiple techniques and professional features
"""

import os
import sys
import socket
import re
import json
import time
import random
import hashlib
import base64
from datetime import datetime
from urllib.parse import urlparse, urljoin
from colorama import Fore, Style, init
import ssl
import urllib.parse
import requests
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import argparse
from typing import Dict, List, Tuple, Optional, Any
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict
from pathlib import Path

# Initialize colorama
init(autoreset=True)

# Import our enhanced signatures
from waf_signatures import WAF_SIGNATURES, ADVANCED_PATTERNS, BYPASS_TECHNIQUES

@dataclass
class WAFDetectionResult:
    """Data class for WAF detection results"""
    host: str
    waf_detected: bool
    waf_name: str = "Unknown"
    waf_version: str = "Unknown"
    confidence: float = 0.0
    detection_method: str = "Unknown"
    response_code: int = 0
    response_time: float = 0.0
    headers: Dict[str, str] = None
    bypass_techniques: List[str] = None
    additional_info: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.headers is None:
            self.headers = {}
        if self.bypass_techniques is None:
            self.bypass_techniques = []
        if self.additional_info is None:
            self.additional_info = {}

class WAFHunterLogger:
    """Professional logging system for WAFHUNTER"""
    
    def __init__(self, log_level=logging.INFO, log_file=None):
        self.logger = logging.getLogger('WAFHUNTER')
        self.logger.setLevel(log_level)
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # File handler
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            file_formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
            )
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)
    
    def info(self, message):
        self.logger.info(message)
    
    def warning(self, message):
        self.logger.warning(message)
    
    def error(self, message):
        self.logger.error(message)
    
    def debug(self, message):
        self.logger.debug(message)

class WAFDetector:
    """Advanced WAF detection engine"""
    
    def __init__(self, logger=None, timeout=10, max_retries=3):
        self.logger = logger or WAFHunterLogger()
        self.timeout = timeout
        self.max_retries = max_retries
        self.session = self._create_session()
        
    def _create_session(self):
        """Create a configured requests session"""
        session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Set default headers
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        
        return session
    
    def detect_waf(self, host: str, port: int = 80, protocol: str = 'http', 
                   path: str = '/', method: str = 'GET', 
                   stealth: bool = False) -> WAFDetectionResult:
        """
        Detect WAF using multiple techniques
        """
        start_time = time.time()
        result = WAFDetectionResult(host=host, waf_detected=False)
        
        try:
            # Build URL
            if port == 80 and protocol == 'http':
                url = f"http://{host}{path}"
            elif port == 443 and protocol == 'https':
                url = f"https://{host}{path}"
            else:
                url = f"{protocol}://{host}:{port}{path}"
            
            self.logger.info(f"Scanning {url}")
            
            # Perform detection
            detection_result = self._perform_detection(url, method, stealth)
            
            # Update result
            result.waf_detected = detection_result['waf_detected']
            result.waf_name = detection_result['waf_name']
            result.waf_version = detection_result['waf_version']
            result.confidence = detection_result['confidence']
            result.detection_method = detection_result['detection_method']
            result.response_code = detection_result['response_code']
            result.response_time = time.time() - start_time
            result.headers = detection_result['headers']
            result.bypass_techniques = detection_result['bypass_techniques']
            result.additional_info = detection_result['additional_info']
            
        except Exception as e:
            self.logger.error(f"Error detecting WAF for {host}: {e}")
            result.waf_detected = False
            result.waf_name = "Error"
            result.additional_info = {'error': str(e)}
        
        return result
    
    def _perform_detection(self, url: str, method: str, stealth: bool) -> Dict:
        """Perform WAF detection using multiple techniques"""
        detection_result = {
            'waf_detected': False,
            'waf_name': 'Unknown',
            'waf_version': 'Unknown',
            'confidence': 0.0,
            'detection_method': 'Unknown',
            'response_code': 0,
            'headers': {},
            'bypass_techniques': [],
            'additional_info': {}
        }
        
        try:
            # Make request
            response = self.session.request(method, url, timeout=self.timeout)
            detection_result['response_code'] = response.status_code
            detection_result['headers'] = dict(response.headers)
            
            # Analyze response
            response_text = response.text
            response_headers = response.headers
            
            # Method 1: Header analysis
            header_result = self._analyze_headers(response_headers)
            if header_result['waf_detected']:
                detection_result.update(header_result)
                detection_result['detection_method'] = 'Header Analysis'
                return detection_result
            
            # Method 2: Response content analysis
            content_result = self._analyze_content(response_text, response_headers)
            if content_result['waf_detected']:
                detection_result.update(content_result)
                detection_result['detection_method'] = 'Content Analysis'
                return detection_result
            
            # Method 3: Response code analysis
            code_result = self._analyze_response_code(response.status_code, response_headers)
            if code_result['waf_detected']:
                detection_result.update(code_result)
                detection_result['detection_method'] = 'Response Code Analysis'
                return detection_result
            
            # Method 4: Advanced techniques (if not in stealth mode)
            if not stealth:
                advanced_result = self._advanced_detection(url, method)
                if advanced_result['waf_detected']:
                    detection_result.update(advanced_result)
                    detection_result['detection_method'] = 'Advanced Detection'
                    return detection_result
            
        except Exception as e:
            self.logger.error(f"Error in detection: {e}")
            detection_result['additional_info']['error'] = str(e)
        
        return detection_result
    
    def _analyze_headers(self, headers: Dict[str, str]) -> Dict:
        """Analyze response headers for WAF signatures"""
        result = {
            'waf_detected': False,
            'waf_name': 'Unknown',
            'waf_version': 'Unknown',
            'confidence': 0.0,
            'bypass_techniques': []
        }
        
        # Convert headers to lowercase for case-insensitive matching
        headers_lower = {k.lower(): v for k, v in headers.items()}
        headers_str = ' '.join([f"{k}: {v}" for k, v in headers_lower.items()])
        
        # Check against WAF signatures
        for waf_name, waf_data in WAF_SIGNATURES.items():
            for pattern in waf_data['patterns']:
                if re.search(pattern, headers_str, re.IGNORECASE):
                    result['waf_detected'] = True
                    result['waf_name'] = waf_name
                    result['confidence'] = 0.8
                    result['bypass_techniques'] = waf_data.get('bypass_techniques', [])
                    
                    # Try to extract version
                    for version_pattern in waf_data.get('version_patterns', []):
                        version_match = re.search(version_pattern, headers_str, re.IGNORECASE)
                        if version_match:
                            result['waf_version'] = version_match.group(1)
                            result['confidence'] = 0.9
                            break
                    
                    return result
        
        return result
    
    def _analyze_content(self, content: str, headers: Dict[str, str]) -> Dict:
        """Analyze response content for WAF signatures"""
        result = {
            'waf_detected': False,
            'waf_name': 'Unknown',
            'waf_version': 'Unknown',
            'confidence': 0.0,
            'bypass_techniques': []
        }
        
        # Combine headers and content for analysis
        full_text = ' '.join([f"{k}: {v}" for k, v in headers.items()]) + ' ' + content
        
        # Check against WAF signatures
        for waf_name, waf_data in WAF_SIGNATURES.items():
            for pattern in waf_data['patterns']:
                if re.search(pattern, full_text, re.IGNORECASE):
                    result['waf_detected'] = True
                    result['waf_name'] = waf_name
                    result['confidence'] = 0.7
                    result['bypass_techniques'] = waf_data.get('bypass_techniques', [])
                    
                    # Try to extract version
                    for version_pattern in waf_data.get('version_patterns', []):
                        version_match = re.search(version_pattern, full_text, re.IGNORECASE)
                        if version_match:
                            result['waf_version'] = version_match.group(1)
                            result['confidence'] = 0.8
                            break
                    
                    return result
        
        return result
    
    def _analyze_response_code(self, status_code: int, headers: Dict[str, str]) -> Dict:
        """Analyze response code for WAF indicators"""
        result = {
            'waf_detected': False,
            'waf_name': 'Unknown',
            'waf_version': 'Unknown',
            'confidence': 0.0,
            'bypass_techniques': []
        }
        
        # Check for blocked response codes
        if status_code in ADVANCED_PATTERNS['response_codes']['blocked']:
            result['waf_detected'] = True
            result['waf_name'] = 'Generic WAF'
            result['confidence'] = 0.6
            result['bypass_techniques'] = BYPASS_TECHNIQUES['general']
        
        return result
    
    def _advanced_detection(self, url: str, method: str) -> Dict:
        """Perform advanced WAF detection techniques"""
        result = {
            'waf_detected': False,
            'waf_name': 'Unknown',
            'waf_version': 'Unknown',
            'confidence': 0.0,
            'bypass_techniques': []
        }
        
        try:
            # Test with malicious payloads
            malicious_payloads = [
                "' OR '1'='1",
                "<script>alert('xss')</script>",
                "../../../etc/passwd",
                "UNION SELECT * FROM users",
                "<?php system($_GET['cmd']); ?>"
            ]
            
            for payload in malicious_payloads:
                test_url = f"{url}?test={urllib.parse.quote(payload)}"
                response = self.session.get(test_url, timeout=self.timeout)
                
                # Check for WAF blocking patterns
                if response.status_code in ADVANCED_PATTERNS['response_codes']['blocked']:
                    result['waf_detected'] = True
                    result['waf_name'] = 'Generic WAF (Payload Detection)'
                    result['confidence'] = 0.7
                    result['bypass_techniques'] = BYPASS_TECHNIQUES['evasion']
                    break
                
                # Check content for blocking messages
                for pattern in ADVANCED_PATTERNS['content_patterns']['block_pages']:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        result['waf_detected'] = True
                        result['waf_name'] = 'Generic WAF (Content Analysis)'
                        result['confidence'] = 0.8
                        result['bypass_techniques'] = BYPASS_TECHNIQUES['evasion']
                        break
                
                if result['waf_detected']:
                    break
        
        except Exception as e:
            self.logger.debug(f"Advanced detection error: {e}")
        
        return result

class WAFHunterScanner:
    """Main scanner class for WAFHUNTER"""
    
    def __init__(self, logger=None, max_workers=5, stealth=False):
        self.logger = logger or WAFHunterLogger()
        self.max_workers = max_workers
        self.stealth = stealth
        self.detector = WAFDetector(logger=self.logger)
        self.results = []
    
    def scan_hosts(self, hosts: List[str], port: int = 80, protocol: str = 'http', 
                   path: str = '/', method: str = 'GET') -> List[WAFDetectionResult]:
        """Scan multiple hosts for WAF detection"""
        self.logger.info(f"Starting scan for {len(hosts)} hosts")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_host = {
                executor.submit(
                    self.detector.detect_waf, 
                    host, port, protocol, path, method, self.stealth
                ): host for host in hosts
            }
            
            for future in as_completed(future_to_host):
                host = future_to_host[future]
                try:
                    result = future.result()
                    self.results.append(result)
                    self._print_result(result)
                except Exception as e:
                    self.logger.error(f"Error scanning {host}: {e}")
                    error_result = WAFDetectionResult(
                        host=host, 
                        waf_detected=False, 
                        waf_name="Error",
                        additional_info={'error': str(e)}
                    )
                    self.results.append(error_result)
        
        return self.results
    
    def _print_result(self, result: WAFDetectionResult):
        """Print detection result with color coding"""
        if result.waf_detected:
            print(f"{Fore.GREEN}[+] {result.host} - {Fore.YELLOW}{result.waf_name}{Fore.RESET}")
            if result.waf_version != "Unknown":
                print(f"    Version: {Fore.CYAN}{result.waf_version}{Fore.RESET}")
            print(f"    Confidence: {Fore.CYAN}{result.confidence:.2f}{Fore.RESET}")
            print(f"    Method: {Fore.CYAN}{result.detection_method}{Fore.RESET}")
            if result.bypass_techniques:
                print(f"    Bypass Techniques: {Fore.MAGENTA}{', '.join(result.bypass_techniques[:3])}{Fore.RESET}")
        else:
            print(f"{Fore.RED}[-] {result.host} - No WAF detected{Fore.RESET}")
    
    def generate_report(self, output_format: str = 'json', output_file: str = None) -> str:
        """Generate detection report in specified format"""
        if not self.results:
            return "No results to report"
        
        if output_format.lower() == 'json':
            report_data = {
                'scan_info': {
                    'timestamp': datetime.now().isoformat(),
                    'total_hosts': len(self.results),
                    'waf_detected': sum(1 for r in self.results if r.waf_detected),
                    'stealth_mode': self.stealth
                },
                'results': [asdict(result) for result in self.results]
            }
            report = json.dumps(report_data, indent=2)
        
        elif output_format.lower() == 'xml':
            root = ET.Element('wafhunter_report')
            root.set('timestamp', datetime.now().isoformat())
            root.set('total_hosts', str(len(self.results)))
            root.set('waf_detected', str(sum(1 for r in self.results if r.waf_detected)))
            
            for result in self.results:
                host_elem = ET.SubElement(root, 'host')
                host_elem.set('name', result.host)
                host_elem.set('waf_detected', str(result.waf_detected).lower())
                host_elem.set('waf_name', result.waf_name)
                host_elem.set('waf_version', result.waf_version)
                host_elem.set('confidence', str(result.confidence))
                host_elem.set('detection_method', result.detection_method)
            
            report = ET.tostring(root, encoding='unicode')
        
        elif output_format.lower() == 'html':
            report = self._generate_html_report()
        
        else:
            report = self._generate_text_report()
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report)
            self.logger.info(f"Report saved to {output_file}")
        
        return report
    
    def _generate_html_report(self) -> str:
        """Generate HTML report"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>WAFHUNTER Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .result {{ margin: 10px 0; padding: 10px; border-left: 4px solid #ccc; }}
                .waf-detected {{ border-left-color: #4CAF50; }}
                .no-waf {{ border-left-color: #f44336; }}
                .waf-name {{ font-weight: bold; color: #2196F3; }}
                .confidence {{ color: #FF9800; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>WAFHUNTER Report</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>Total Hosts: {len(self.results)}</p>
                <p>WAF Detected: {sum(1 for r in self.results if r.waf_detected)}</p>
            </div>
        """
        
        for result in self.results:
            css_class = "waf-detected" if result.waf_detected else "no-waf"
            html += f"""
            <div class="result {css_class}">
                <h3>{result.host}</h3>
                <p><span class="waf-name">WAF:</span> {result.waf_name}</p>
                <p><span class="confidence">Confidence:</span> {result.confidence:.2f}</p>
                <p>Method: {result.detection_method}</p>
            </div>
            """
        
        html += "</body></html>"
        return html
    
    def _generate_text_report(self) -> str:
        """Generate text report"""
        report = f"WAFHUNTER Report\n"
        report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"Total Hosts: {len(self.results)}\n"
        report += f"WAF Detected: {sum(1 for r in self.results if r.waf_detected)}\n\n"
        
        for result in self.results:
            report += f"Host: {result.host}\n"
            report += f"  WAF Detected: {result.waf_detected}\n"
            report += f"  WAF Name: {result.waf_name}\n"
            report += f"  Version: {result.waf_version}\n"
            report += f"  Confidence: {result.confidence:.2f}\n"
            report += f"  Method: {result.detection_method}\n"
            if result.bypass_techniques:
                report += f"  Bypass Techniques: {', '.join(result.bypass_techniques)}\n"
            report += "\n"
        
        return report

# Banner
BANNER = f"""
{Fore.GREEN}
 ╔══════════════════════════════════════════════════════════════════════════════════════╗
 ║                                                                                      ║
 ║                                                                                      ║
 ║       ██╗    ██╗ █████╗ ███████╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗  ║
 ║       ██║    ██║██╔══██╗██╔════╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗ ║
 ║       ██║ █╗ ██║███████║█████╗  ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝ ║  
 ║       ██║███╗██║██╔══██║██╔══╝  ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗ ║
 ║       ╚███╔███╔╝██║  ██║██║     ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║ ║
 ║        ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝ ║
 ║                                                                                      ║
 ║  Advanced Web Application Firewall Detection Tool                                    ║
 ║  Version: 3.0 | Professional Edition                                                 ║
 ║  Author: MrpasswordTz | Country: Tanzania                                            ║
 ║                                                                                      ║
 ╚══════════════════════════════════════════════════════════════════════════════════════╝
{Fore.RESET}
"""

# Example usage
EXAMPLE_USAGE = f"""
{Fore.CYAN}Examples:{Fore.RESET}

{Fore.YELLOW}Basic WAF Detection:{Fore.RESET}
  python3 wafhunter.py example.com

{Fore.YELLOW}Multiple Hosts:{Fore.RESET}
  python3 wafhunter.py example.com target.com victim.com

{Fore.YELLOW}Custom Port and Protocol:{Fore.RESET}
  python3 wafhunter.py example.com --port 8080 --protocol https

{Fore.YELLOW}Stealth Mode:{Fore.RESET}
  python3 wafhunter.py example.com --stealth

{Fore.YELLOW}Generate Report:{Fore.RESET}
  python3 wafhunter.py example.com --report json --output report.json

{Fore.YELLOW}High Concurrency:{Fore.RESET}
  python3 wafhunter.py example.com --concurrency 20

{Fore.YELLOW}Custom Path:{Fore.RESET}
  python3 wafhunter.py example.com --path /admin/login

{Fore.YELLOW}Verbose Logging:{Fore.RESET}
  python3 wafhunter.py example.com --verbose --log-file wafhunter.log
"""