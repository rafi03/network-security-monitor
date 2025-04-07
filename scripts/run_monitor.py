#!/usr/bin/env python3
"""
Network Security Monitoring Tool

A Python-based network security monitoring tool that can detect suspicious activity,
visualize network traffic patterns, and generate security reports.
"""

import os
import sys
import argparse
import time
from datetime import datetime
from colorama import Fore, Style, init

# Add the parent directory to the path so we can import the package
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from netsecmonitor.utils.logger import setup_logging
from netsecmonitor.port_scanner import PortScanner, run_port_scanner
from netsecmonitor.traffic_analyzer import TrafficAnalyzer, run_traffic_analyzer
from netsecmonitor.intrusion_detection import IntrusionDetectionSystem, run_ids
from netsecmonitor.visualization import NetworkVisualizer, run_visualizer
from netsecmonitor.reporting import SecurityReporter, run_reporter
from netsecmonitor.config import DEFAULT_PORT_RANGES, REPORT_FORMAT

# Initialize colorama
init(autoreset=True)

def parse_args():
    """
    Parse command line arguments.
    
    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(description='Network Security Monitoring Tool')
    
    # General options
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-o', '--output-dir', type=str, help='Output directory for reports and visualizations')
    
    # Module selection
    module_group = parser.add_argument_group('Modules')
    module_group.add_argument('--no-scan', action='store_true', help='Disable port scanning')
    module_group.add_argument('--no-traffic', action='store_true', help='Disable traffic analysis')
    module_group.add_argument('--no-ids', action='store_true', help='Disable intrusion detection')
    module_group.add_argument('--no-visualize', action='store_true', help='Disable visualization')
    module_group.add_argument('--no-report', action='store_true', help='Disable report generation')
    
    # Port scanner options
    scan_group = parser.add_argument_group('Port Scanner')
    scan_group.add_argument('-t', '--target', type=str, help='Target IP address or hostname to scan')
    scan_group.add_argument('-p', '--port-range', type=str, default='common',
                           choices=['common', 'full', 'extended', 'custom'],
                           help='Port range to scan')
    scan_group.add_argument('--ports', type=str, help='Custom ports to scan (e.g. "22,80,443" or "1-1000")')
    scan_group.add_argument('--timeout', type=float, default=1.0, help='Timeout for port scanning (seconds)')
    scan_group.add_argument('--workers', type=int, default=100, help='Number of workers for port scanning')
    
    # Traffic analyzer options
    traffic_group = parser.add_argument_group('Traffic Analyzer')
    traffic_group.add_argument('-i', '--interface', type=str, help='Network interface to capture traffic on')
    traffic_group.add_argument('--list-interfaces', action='store_true', help='List available network interfaces')
    traffic_group.add_argument('-c', '--count', type=int, default=1000, help='Number of packets to capture')
    traffic_group.add_argument('--capture-timeout', type=int, default=60, help='Timeout for packet capture (seconds)')
    
    # Report options
    report_group = parser.add_argument_group('Report')
    report_group.add_argument('--report-format', type=str, default=REPORT_FORMAT,
                             choices=['txt', 'json', 'csv'],
                             help='Report format')
    
    return parser.parse_args()

def main():
    """Main function to run the network security monitoring tool."""
    # Parse command line arguments
    args = parse_args()
    
    # Set up logging
    log_level = 'DEBUG' if args.verbose else 'INFO'
    setup_logging(log_level=log_level)
    
    
    print(Fore.CYAN + "Network Security Monitoring Tool v0.1.0" + Style.RESET_ALL)
    print(Fore.CYAN + "=" * 60 + Style.RESET_ALL)
    print()
    
    # Initialize components
    port_scanner = None
    traffic_analyzer = None
    ids = None
    visualization_paths = []
    
    # Show start time
    start_time = time.time()
    print(f"[*] Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Run port scanner if enabled
    if not args.no_scan and args.target:
        print(f"\n{Fore.CYAN}[+] Running Port Scanner...{Style.RESET_ALL}")
        port_scanner = PortScanner(timeout=args.timeout)
        port_scanner.scan_target(args.target, ports=args.port_range, max_workers=args.workers)
    
    # Run traffic analyzer if enabled
    if not args.no_traffic:
        print(f"\n{Fore.CYAN}[+] Running Traffic Analyzer...{Style.RESET_ALL}")
        traffic_analyzer = TrafficAnalyzer()
        
        # List interfaces if requested
        if args.list_interfaces:
            interfaces = traffic_analyzer.get_available_interfaces()
            print(f"\n{Fore.CYAN}[*] Available network interfaces:{Style.RESET_ALL}")
            for i, iface in enumerate(interfaces, 1):
                print(f"    {i}. {iface}")
            return
        
        # Capture traffic
        traffic_analyzer.capture_traffic(
            interface=args.interface,
            count=args.count,
            timeout=args.capture_timeout
        )
    
    # Run intrusion detection if enabled
    if not args.no_ids and traffic_analyzer:
        print(f"\n{Fore.CYAN}[+] Running Intrusion Detection...{Style.RESET_ALL}")
        ids = IntrusionDetectionSystem()
        ids.process_packets(traffic_analyzer.get_packets())
    
    # Run visualizer if enabled
    if not args.no_visualize and traffic_analyzer:
        print(f"\n{Fore.CYAN}[+] Generating Visualizations...{Style.RESET_ALL}")
        visualizer = NetworkVisualizer()
        traffic_stats = traffic_analyzer.get_stats()
        ids_alerts = ids.get_alerts() if ids else []
        visualization_paths = visualizer.create_dashboard(traffic_stats, ids_alerts)
        
        if visualization_paths:
            print(f"\n{Fore.CYAN}[*] Generated {len(visualization_paths)} visualizations{Style.RESET_ALL}")
    
    # Generate report if enabled
    if not args.no_report:
        print(f"\n{Fore.CYAN}[+] Generating Security Report...{Style.RESET_ALL}")
        reporter = SecurityReporter(format=args.report_format)
        
        port_scan_results = port_scanner.get_results() if port_scanner else None
        traffic_stats = traffic_analyzer.get_stats() if traffic_analyzer else None
        ids_alerts = ids.get_alerts() if ids else None
        
        report_path = reporter.generate_report(
            port_scan_results=port_scan_results,
            traffic_stats=traffic_stats,
            ids_alerts=ids_alerts,
            visualization_paths=visualization_paths
        )
        
        print(f"\n{Fore.GREEN}[*] Security report generated: {report_path}{Style.RESET_ALL}")
    
    # Show completion and elapsed time
    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"\n{Fore.CYAN}[*] Completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Elapsed time: {elapsed_time:.2f} seconds{Style.RESET_ALL}")
    print(f"\n{Fore.GREEN}[*] Network Security Monitoring completed successfully!{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Monitoring interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)
