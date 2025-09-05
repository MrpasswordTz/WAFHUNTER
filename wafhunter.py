#!/usr/bin/env python3
"""
WAFHUNTER - Advanced Web Application Firewall Detection Tool
Professional Edition for Penetration Testers and Security Professionals

Author: MrpasswordTz
Country: Tanzania
Version: 3.0
"""

import argparse
import sys
import os
import logging
from pathlib import Path
from colorama import Fore, Style, init
from modules import WAFHunterScanner, WAFHunterLogger, BANNER, EXAMPLE_USAGE

# Initialize colorama
init(autoreset=True)

def create_parser():
    """Create command line argument parser"""
    parser = argparse.ArgumentParser(
        description='WAFHUNTER - Advanced Web Application Firewall Detection Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EXAMPLE_USAGE
    )
    
    # Required arguments
    parser.add_argument(
        'hosts',
        nargs='+',
        help='Hostnames or IP addresses to scan (space-separated)'
    )
    
    # Connection options
    parser.add_argument(
        '--port',
        type=int,
        default=80,
        help='Port to connect to (default: 80)'
    )
    
    parser.add_argument(
        '--protocol',
        choices=['http', 'https'],
        default='http',
        help='Protocol to use (default: http)'
    )
    
    parser.add_argument(
        '--path',
        default='/',
        help='Path to request (default: /)'
    )
    
    parser.add_argument(
        '--method',
        default='GET',
        choices=['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS'],
        help='HTTP method to use (default: GET)'
    )
    
    # Scanning options
    parser.add_argument(
        '--concurrency',
        type=int,
        default=5,
        help='Number of concurrent threads (default: 5)'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=10,
        help='Request timeout in seconds (default: 10)'
    )
    
    parser.add_argument(
        '--stealth',
        action='store_true',
        help='Enable stealth mode (reduces detection risk)'
    )
    
    # Output options
    parser.add_argument(
        '--report',
        choices=['json', 'xml', 'html', 'text'],
        help='Generate report in specified format'
    )
    
    parser.add_argument(
        '--output',
        help='Output file for report (default: stdout)'
    )
    
    # Logging options
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    parser.add_argument(
        '--log-file',
        help='Log file path (default: wafhunter.log)'
    )
    
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Suppress output except errors'
    )
    
    # Advanced options
    parser.add_argument(
        '--user-agent',
        help='Custom User-Agent string'
    )
    
    parser.add_argument(
        '--headers',
        help='Custom headers in JSON format'
    )
    
    parser.add_argument(
        '--proxy',
        help='Proxy URL (e.g., http://proxy:8080)'
    )
    
    parser.add_argument(
        '--retries',
        type=int,
        default=3,
        help='Number of retries for failed requests (default: 3)'
    )
    
    # Configuration
    parser.add_argument(
        '--config',
        help='Configuration file path'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='WAFHUNTER 3.0 Professional Edition'
    )
    
    return parser

def load_config(config_file):
    """Load configuration from file"""
    import json
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"{Fore.RED}Error loading config file: {e}{Fore.RESET}")
        return {}

def setup_logging(args):
    """Setup logging configuration"""
    log_level = 'DEBUG' if args.verbose else 'INFO'
    log_file = args.log_file or 'wafhunter.log'
    
    logger = WAFHunterLogger(
        log_level=getattr(logging, log_level.upper()),
        log_file=log_file
    )
    
    return logger

def validate_hosts(hosts):
    """Validate host inputs"""
    import re
    valid_hosts = []
    
    for host in hosts:
        # Remove protocol if present
        if '://' in host:
            host = host.split('://', 1)[1]
        
        # Remove port if present
        if ':' in host:
            host = host.split(':')[0]
        
        # Basic validation
        if re.match(r'^[a-zA-Z0-9.-]+$', host) or re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host):
            valid_hosts.append(host)
        else:
            print(f"{Fore.YELLOW}Warning: Invalid host format: {host}{Fore.RESET}")
    
    return valid_hosts

def main():
    """Main function"""
    parser = create_parser()
    args = parser.parse_args()
    
    # Show banner unless quiet mode
    if not args.quiet:
        print(BANNER)
    
    # Load configuration if provided
    config = {}
    if args.config:
        config = load_config(args.config)
    
    # Setup logging
    logger = setup_logging(args)
    
    # Validate hosts
    hosts = validate_hosts(args.hosts)
    if not hosts:
        print(f"{Fore.RED}Error: No valid hosts provided{Fore.RESET}")
        sys.exit(1)
    
    # Create scanner
    scanner = WAFHunterScanner(
        logger=logger,
        max_workers=args.concurrency,
        stealth=args.stealth
    )
    
    # Configure detector
    scanner.detector.timeout = args.timeout
    scanner.detector.max_retries = args.retries
    
    # Set custom User-Agent
    if args.user_agent:
        scanner.detector.session.headers['User-Agent'] = args.user_agent
    
    # Set custom headers
    if args.headers:
        import json
        try:
            custom_headers = json.loads(args.headers)
            scanner.detector.session.headers.update(custom_headers)
        except json.JSONDecodeError:
            print(f"{Fore.RED}Error: Invalid JSON format for headers{Fore.RESET}")
            sys.exit(1)
    
    # Set proxy
    if args.proxy:
        scanner.detector.session.proxies = {
            'http': args.proxy,
            'https': args.proxy
        }
    
    # Start scanning
    try:
        if not args.quiet:
            print(f"{Fore.CYAN}[*] Starting scan for {len(hosts)} hosts...{Fore.RESET}")
            if args.stealth:
                print(f"{Fore.YELLOW}[*] Stealth mode enabled{Fore.RESET}")
        
        results = scanner.scan_hosts(
            hosts=hosts,
            port=args.port,
            protocol=args.protocol,
            path=args.path,
            method=args.method
        )
        
        # Generate report if requested
        if args.report:
            if not args.quiet:
                print(f"\n{Fore.CYAN}[*] Generating {args.report.upper()} report...{Fore.RESET}")
            
            report = scanner.generate_report(
                output_format=args.report,
                output_file=args.output
            )
            
            if not args.output:
                print(report)
        
        # Summary
        if not args.quiet:
            waf_detected = sum(1 for r in results if r.waf_detected)
            print(f"\n{Fore.GREEN}[*] Scan completed!{Fore.RESET}")
            print(f"{Fore.CYAN}[*] Total hosts: {len(results)}{Fore.RESET}")
            print(f"{Fore.CYAN}[*] WAF detected: {waf_detected}{Fore.RESET}")
            print(f"{Fore.CYAN}[*] No WAF: {len(results) - waf_detected}{Fore.RESET}")
    
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Scan interrupted by user{Fore.RESET}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        print(f"{Fore.RED}Error: {e}{Fore.RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()