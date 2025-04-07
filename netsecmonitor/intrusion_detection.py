import time
import logging
import json
from collections import defaultdict, deque
from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP, DNS
from colorama import Fore, Style, init

from netsecmonitor.config import load_signatures

# Initialize colorama
init(autoreset=True)

# Set up logging
logger = logging.getLogger(__name__)

class IntrusionDetectionSystem:
    """
    A simple intrusion detection system based on signature detection.
    """
    
    def __init__(self):
        """Initialize the intrusion detection system."""
        self.signatures = load_signatures()
        self.alerts = []
        self.packet_buffer = deque(maxlen=1000)  # Store recent packets for analysis
        self.connection_attempts = defaultdict(list)  # Track connection attempts
        self.suspicious_ips = set()  # Track suspicious IPs
        
        # Create a lookup table for faster signature matching
        self.signature_lookup = {}
        for sig in self.signatures:
            sig_type = sig.get("detection", {}).get("type")
            if sig_type not in self.signature_lookup:
                self.signature_lookup[sig_type] = []
            self.signature_lookup[sig_type].append(sig)
    
    def process_packet(self, packet):
        """
        Process a packet for intrusion detection.
        
        Args:
            packet: The packet to process
        """
        # Add packet to buffer
        self.packet_buffer.append(packet)
        
        # Process packet for frequency-based detections
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Port scan detection (frequency-based)
            if TCP in packet:
                self._check_port_scan(src_ip, dst_ip, packet[TCP].dport)
            
            # Process for all signature types
            self._check_pattern_signatures(packet)
            self._check_anomaly_signatures(packet)
    
    def _check_port_scan(self, src_ip, dst_ip, dst_port):
        """
        Check for port scan activity.
        
        Args:
            src_ip (str): Source IP address
            dst_ip (str): Destination IP address
            dst_port (int): Destination port
        """
        # Record connection attempt
        key = f"{src_ip}:{dst_ip}"
        timestamp = time.time()
        self.connection_attempts[key].append((timestamp, dst_port))
        
        # Clean up old connection attempts (older than 5 minutes)
        self.connection_attempts[key] = [
            (ts, port) for ts, port in self.connection_attempts[key]
            if timestamp - ts < 300
        ]
        
        # Check for port scan signatures
        for sig in self.signature_lookup.get('frequency', []):
            if sig.get('detection', {}).get('ports') == "multiple":
                threshold = sig.get('detection', {}).get('threshold', 10)
                timeframe = sig.get('detection', {}).get('timeframe', 5)
                
                # Count unique ports in the timeframe
                recent_ports = set()
                for ts, port in self.connection_attempts[key]:
                    if timestamp - ts <= timeframe:
                        recent_ports.add(port)
                
                # Alert if threshold is reached
                if len(recent_ports) >= threshold:
                    alert = {
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "signature_id": sig.get('id'),
                        "signature_name": sig.get('name'),
                        "severity": sig.get('severity', 'medium'),
                        "source_ip": src_ip,
                        "destination_ip": dst_ip,
                        "details": f"Multiple port connection attempts ({len(recent_ports)} ports in {timeframe} seconds)"
                    }
                    
                    # Check if this is a new alert (avoid duplicates)
                    if not any(a['source_ip'] == src_ip and 
                              a['signature_id'] == sig.get('id') and 
                              time.time() - datetime.strptime(a['timestamp'], "%Y-%m-%d %H:%M:%S").timestamp() < 60
                              for a in self.alerts):
                        self.alerts.append(alert)
                        self._display_alert(alert)
                        self.suspicious_ips.add(src_ip)
    
    def _check_pattern_signatures(self, packet):
        """
        Check for pattern-based signatures.
        
        Args:
            packet: The packet to check
        """
        for sig in self.signature_lookup.get('pattern', []):
            detection = sig.get('detection', {})
            port = detection.get('port')
            protocol = detection.get('protocol', '').lower()
            pattern = detection.get('pattern')
            
            if not pattern:
                continue
                
            # Check if packet matches the signature criteria
            if (IP in packet and 
                ((protocol == 'tcp' and TCP in packet and port == packet[TCP].dport) or
                 (protocol == 'udp' and UDP in packet and port == packet[UDP].dport))):
                
                # Check for pattern in raw packet data
                if hasattr(packet, 'load') and pattern in str(packet.load):
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    
                    alert = {
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "signature_id": sig.get('id'),
                        "signature_name": sig.get('name'),
                        "severity": sig.get('severity', 'medium'),
                        "source_ip": src_ip,
                        "destination_ip": dst_ip,
                        "details": f"Pattern match: {pattern}"
                    }
                    
                    self.alerts.append(alert)
                    self._display_alert(alert)
                    self.suspicious_ips.add(src_ip)
    
    def _check_anomaly_signatures(self, packet):
        """
        Check for anomaly-based signatures.
        
        Args:
            packet: The packet to check
        """
        for sig in self.signature_lookup.get('anomaly', []):
            detection = sig.get('detection', {})
            port = detection.get('port')
            protocol = detection.get('protocol', '').lower()
            condition = detection.get('condition')
            threshold = detection.get('threshold', 100)
            
            # DNS tunneling detection (unusually long DNS queries)
            if (condition == 'unusual_length' and 
                protocol == 'udp' and 
                UDP in packet and 
                port == packet[UDP].dport and 
                DNS in packet):
                
                # Check for unusually long DNS query
                if len(packet) > threshold:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    
                    alert = {
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "signature_id": sig.get('id'),
                        "signature_name": sig.get('name'),
                        "severity": sig.get('severity', 'high'),
                        "source_ip": src_ip,
                        "destination_ip": dst_ip,
                        "details": f"Unusually large DNS packet: {len(packet)} bytes"
                    }
                    
                    self.alerts.append(alert)
                    self._display_alert(alert)
                    self.suspicious_ips.add(src_ip)
    
    def _display_alert(self, alert):
        """
        Display an alert in the console.
        
        Args:
            alert (dict): The alert to display
        """
        severity_color = {
            'low': Fore.YELLOW,
            'medium': Fore.YELLOW,
            'high': Fore.RED,
            'critical': Fore.RED + Style.BRIGHT
        }
        
        color = severity_color.get(alert['severity'].lower(), Fore.WHITE)
        
        print(f"\n{color}[!] ALERT: {alert['signature_name']} (ID: {alert['signature_id']}){Style.RESET_ALL}")
        print(f"{color}    Severity: {alert['severity'].upper()}{Style.RESET_ALL}")
        print(f"{color}    Time: {alert['timestamp']}{Style.RESET_ALL}")
        print(f"{color}    Source IP: {alert['source_ip']}{Style.RESET_ALL}")
        print(f"{color}    Destination IP: {alert['destination_ip']}{Style.RESET_ALL}")
        print(f"{color}    Details: {alert['details']}{Style.RESET_ALL}")
    
    def process_packets(self, packets):
        """
        Process multiple packets for intrusion detection.
        
        Args:
            packets (list): List of packets to process
        """
        for packet in packets:
            self.process_packet(packet)
    
    def get_alerts(self):
        """
        Get the alerts generated during monitoring.
        
        Returns:
            list: List of alerts
        """
        return self.alerts
    
    def get_suspicious_ips(self):
        """
        Get the list of suspicious IPs detected.
        
        Returns:
            set: Set of suspicious IP addresses
        """
        return self.suspicious_ips
    
    def reset(self):
        """Reset the intrusion detection system."""
        self.alerts = []
        self.packet_buffer.clear()
        self.connection_attempts.clear()
        self.suspicious_ips.clear()

# Run IDS from command line
def run_ids(args, traffic_analyzer):
    """
    Run the intrusion detection system with command line arguments.
    
    Args:
        args: Command line arguments
        traffic_analyzer: TrafficAnalyzer instance
    """
    ids = IntrusionDetectionSystem()
    
    print(f"\n{Fore.CYAN}[*] Starting Intrusion Detection System...{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Loaded {len(ids.signatures)} signatures{Style.RESET_ALL}")
    
    # Process packets captured by traffic analyzer
    packets = traffic_analyzer.get_packets()
    if packets:
        print(f"{Fore.CYAN}[*] Processing {len(packets)} packets...{Style.RESET_ALL}")
        ids.process_packets(packets)
        
        alerts = ids.get_alerts()
        if alerts:
            print(f"\n{Fore.CYAN}[*] Generated {len(alerts)} alerts{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.GREEN}[*] No alerts generated{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}[!] No packets to process{Style.RESET_ALL}")
    
    return ids
