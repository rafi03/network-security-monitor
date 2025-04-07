import os
import json
import csv
import logging
from datetime import datetime
from tabulate import tabulate

from netsecmonitor.config import REPORTS_DIR, REPORT_FORMAT, REPORT_PREFIX

# Set up logging
logger = logging.getLogger(__name__)

class SecurityReporter:
    """
    A class for generating security reports based on the monitoring results.
    """
    
    def __init__(self, output_dir=REPORTS_DIR, format=REPORT_FORMAT):
        """
        Initialize the security reporter.
        
        Args:
            output_dir (str): Directory to save reports
            format (str): Report format (txt, json, csv)
        """
        self.output_dir = output_dir
        self.format = format.lower()
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
    
    def generate_report(self, port_scan_results=None, traffic_stats=None, ids_alerts=None, visualization_paths=None):
        """
        Generate a comprehensive security report.
        
        Args:
            port_scan_results (dict): Results from port scanning
            traffic_stats (dict): Traffic analysis statistics
            ids_alerts (list): Intrusion detection alerts
            visualization_paths (list): Paths to visualization files
            
        Returns:
            str: Path to the generated report
        """
        # Create report filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{REPORT_PREFIX}{timestamp}.{self.format}"
        filepath = os.path.join(self.output_dir, filename)
        
        # Generate report based on format
        if self.format == 'json':
            self._generate_json_report(filepath, port_scan_results, traffic_stats, ids_alerts, visualization_paths)
        elif self.format == 'csv':
            self._generate_csv_report(filepath, port_scan_results, traffic_stats, ids_alerts, visualization_paths)
        else:  # Default to txt
            self._generate_txt_report(filepath, port_scan_results, traffic_stats, ids_alerts, visualization_paths)
        
        print(f"[*] Security report generated: {filepath}")
        return filepath
    
    def _generate_txt_report(self, filepath, port_scan_results, traffic_stats, ids_alerts, visualization_paths):
        """
        Generate a text-based security report.
        
        Args:
            filepath (str): Path to save the report
            port_scan_results (dict): Results from port scanning
            traffic_stats (dict): Traffic analysis statistics
            ids_alerts (list): Intrusion detection alerts
            visualization_paths (list): Paths to visualization files
        """
        with open(filepath, 'w') as f:
            # Header
            f.write("=" * 80 + "\n")
            f.write("NETWORK SECURITY MONITORING REPORT\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Executive Summary
            f.write("EXECUTIVE SUMMARY\n")
            f.write("-" * 80 + "\n")
            
            # Calculate some summary statistics
            num_open_ports = 0
            if port_scan_results and 'open_ports' in port_scan_results:
                num_open_ports = len(port_scan_results['open_ports'])
            
            num_packets = 0
            if traffic_stats and 'total_packets' in traffic_stats:
                num_packets = traffic_stats['total_packets']
            
            num_alerts = 0
            if ids_alerts:
                num_alerts = len(ids_alerts)
            
            f.write(f"- Scanned host: {port_scan_results.get('target', 'N/A') if port_scan_results else 'N/A'}\n")
            f.write(f"- Open ports found: {num_open_ports}\n")
            f.write(f"- Packets analyzed: {num_packets}\n")
            f.write(f"- Security alerts: {num_alerts}\n\n")
            
            # Port Scan Results
            if port_scan_results:
                f.write("PORT SCAN RESULTS\n")
                f.write("-" * 80 + "\n")
                f.write(f"Target: {port_scan_results.get('target', 'N/A')}")
                if 'ip_address' in port_scan_results:
                    f.write(f" ({port_scan_results['ip_address']})")
                f.write("\n")
                
                if 'hostname' in port_scan_results:
                    f.write(f"Hostname: {port_scan_results['hostname']}\n")
                
                if 'domain_info' in port_scan_results:
                    domain = port_scan_results['domain_info']
                    f.write("Domain Information:\n")
                    f.write(f"  - Registrar: {domain.get('registrar', 'Unknown')}\n")
                    f.write(f"  - Creation Date: {domain.get('creation_date', 'Unknown')}\n")
                    f.write(f"  - Expiration Date: {domain.get('expiration_date', 'Unknown')}\n")
                
                f.write(f"Scan Duration: {port_scan_results.get('scan_duration', 'N/A')} seconds\n")
                f.write(f"Scan Time: {port_scan_results.get('timestamp', 'N/A')}\n\n")
                
                if 'open_ports' in port_scan_results and port_scan_results['open_ports']:
                    f.write("Open Ports:\n")
                    
                    # Create a table of open ports
                    headers = ["Port", "Service", "State"]
                    rows = [[p['port'], p['service'], p['state']] for p in port_scan_results['open_ports']]
                    
                    f.write(tabulate(rows, headers=headers, tablefmt="simple") + "\n\n")
                else:
                    f.write("No open ports found.\n\n")
            
            # Traffic Analysis
            if traffic_stats:
                f.write("TRAFFIC ANALYSIS\n")
                f.write("-" * 80 + "\n")
                f.write(f"Interface: {traffic_stats.get('interface', 'N/A')}\n")
                f.write(f"Duration: {traffic_stats.get('duration', 'N/A')} seconds\n")
                f.write(f"Total Packets: {traffic_stats.get('total_packets', 'N/A')}\n")
                f.write(f"Packets per Second: {traffic_stats.get('packets_per_second', 'N/A')}\n")
                f.write(f"Total Conversations: {traffic_stats.get('total_conversations', 'N/A')}\n\n")
                
                # Packet Types
                if 'packet_types' in traffic_stats and traffic_stats['packet_types']:
                    f.write("Packet Type Distribution:\n")
                    for ptype, count in traffic_stats['packet_types'].items():
                        percentage = (count / traffic_stats['total_packets']) * 100 if traffic_stats['total_packets'] > 0 else 0
                        f.write(f"  - {ptype}: {count} ({percentage:.1f}%)\n")
                    f.write("\n")
                
                # Top Source IPs
                if 'top_source_ips' in traffic_stats and traffic_stats['top_source_ips']:
                    f.write("Top Source IP Addresses:\n")
                    for ip, count in traffic_stats['top_source_ips'].items():
                        percentage = (count / traffic_stats['total_packets']) * 100 if traffic_stats['total_packets'] > 0 else 0
                        f.write(f"  - {ip}: {count} ({percentage:.1f}%)\n")
                    f.write("\n")
                
                # Top Destination IPs
                if 'top_destination_ips' in traffic_stats and traffic_stats['top_destination_ips']:
                    f.write("Top Destination IP Addresses:\n")
                    for ip, count in traffic_stats['top_destination_ips'].items():
                        percentage = (count / traffic_stats['total_packets']) * 100 if traffic_stats['total_packets'] > 0 else 0
                        f.write(f"  - {ip}: {count} ({percentage:.1f}%)\n")
                    f.write("\n")
                
                # Top Destination Ports
                if 'top_destination_ports' in traffic_stats and traffic_stats['top_destination_ports']:
                    f.write("Top Destination Ports:\n")
                    for port, count in traffic_stats['top_destination_ports'].items():
                        try:
                            import socket
                            service = socket.getservbyport(int(port))
                        except (socket.error, ValueError, OSError):
                            service = "unknown"
                        
                        percentage = (count / traffic_stats['total_packets']) * 100 if traffic_stats['total_packets'] > 0 else 0
                        f.write(f"  - {port} ({service}): {count} ({percentage:.1f}%)\n")
                    f.write("\n")
            
            # Security Alerts
            if ids_alerts:
                f.write("SECURITY ALERTS\n")
                f.write("-" * 80 + "\n")
                f.write(f"Total Alerts: {len(ids_alerts)}\n\n")
                
                # Count alerts by severity
                severity_counts = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
                for alert in ids_alerts:
                    severity = alert.get('severity', 'medium').lower()
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                
                f.write("Alert Severity Distribution:\n")
                for severity, count in severity_counts.items():
                    if count > 0:
                        f.write(f"  - {severity.capitalize()}: {count}\n")
                f.write("\n")
                
                # List all alerts
                f.write("Alert Details:\n\n")
                for i, alert in enumerate(ids_alerts, 1):
                    f.write(f"Alert #{i}:\n")
                    f.write(f"  - Time: {alert.get('timestamp', 'N/A')}\n")
                    f.write(f"  - Signature ID: {alert.get('signature_id', 'N/A')}\n")
                    f.write(f"  - Signature Name: {alert.get('signature_name', 'N/A')}\n")
                    f.write(f"  - Severity: {alert.get('severity', 'N/A').upper()}\n")
                    f.write(f"  - Source IP: {alert.get('source_ip', 'N/A')}\n")
                    f.write(f"  - Destination IP: {alert.get('destination_ip', 'N/A')}\n")
                    f.write(f"  - Details: {alert.get('details', 'N/A')}\n\n")
            
            # Visualizations
            if visualization_paths:
                f.write("VISUALIZATIONS\n")
                f.write("-" * 80 + "\n")
                f.write("The following visualization files were generated:\n\n")
                
                for path in visualization_paths:
                    f.write(f"- {os.path.basename(path)}\n")
                f.write("\n")
            
            # Recommendations
            f.write("RECOMMENDATIONS\n")
            f.write("-" * 80 + "\n")
            
            recommendations = []
            
            # Port-related recommendations
            if port_scan_results and 'open_ports' in port_scan_results and port_scan_results['open_ports']:
                # Check for commonly exploited services
                risky_services = {
                    21: "FTP",
                    23: "Telnet",
                    135: "MSRPC",
                    139: "NetBIOS",
                    445: "SMB",
                    3389: "RDP"
                }
                
                for port_info in port_scan_results['open_ports']:
                    port = port_info['port']
                    if port in risky_services:
                        recommendations.append(
                            f"Consider securing or disabling {risky_services[port]} service (port {port}) "
                            f"as it is commonly targeted by attackers."
                        )
            
            # Alert-related recommendations
            if ids_alerts:
                high_severity_alerts = [a for a in ids_alerts if a.get('severity') in ['high', 'critical']]
                if high_severity_alerts:
                    recommendations.append(
                        f"Investigate {len(high_severity_alerts)} high/critical severity alerts immediately."
                    )
                
                # Check for port scan alerts
                port_scan_alerts = [a for a in ids_alerts if 'port scan' in a.get('signature_name', '').lower()]
                if port_scan_alerts:
                    recommendations.append(
                        "Review firewall rules to limit port scanning exposure."
                    )
            
            # Traffic-related recommendations
            if traffic_stats:
                # Check for unusual protocols
                if 'protocols' in traffic_stats and traffic_stats['protocols']:
                    if 'ICMP' in traffic_stats['protocols'] and traffic_stats['protocols']['ICMP'] > 20:
                        recommendations.append(
                            "Investigate high ICMP traffic, which could indicate ping sweeps or network mapping."
                        )
            
            # Add default recommendations if none were generated
            if not recommendations:
                recommendations = [
                    "Regularly update and patch all systems and applications.",
                    "Implement network segmentation to limit lateral movement.",
                    "Enable logging and monitoring on critical systems.",
                    "Develop and test an incident response plan."
                ]
            
            # Write recommendations
            for i, rec in enumerate(recommendations, 1):
                f.write(f"{i}. {rec}\n")
            
            # Footer
            f.write("\n" + "=" * 80 + "\n")
            f.write("END OF REPORT\n")
            f.write("=" * 80 + "\n")
            
# Function to run the reporter from command line
def run_reporter(args, port_scanner, traffic_analyzer, ids, visualization_paths):
    """
    Run the security reporter with command line arguments.
    
    Args:
        args: Command line arguments
        port_scanner: PortScanner instance
        traffic_analyzer: TrafficAnalyzer instance
        ids: IntrusionDetectionSystem instance
        visualization_paths: List of visualization file paths
    """
    reporter = SecurityReporter(format=args.report_format)
    
    print("\n[*] Generating security report...")
    
    # Get data from various components
    port_scan_results = port_scanner.get_results() if port_scanner else None
    traffic_stats = traffic_analyzer.get_stats() if traffic_analyzer else None
    ids_alerts = ids.get_alerts() if ids else None
    
    # Generate report
    report_path = reporter.generate_report(
        port_scan_results=port_scan_results,
        traffic_stats=traffic_stats,
        ids_alerts=ids_alerts,
        visualization_paths=visualization_paths
    )
    
    print(f"[*] Security report generated: {report_path}")
    
    return report_path
