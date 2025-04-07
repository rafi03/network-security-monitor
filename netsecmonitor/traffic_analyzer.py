import time
import logging
import socket
import netifaces
import pandas as pd
from collections import Counter, defaultdict
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, ARP

from netsecmonitor.config import PACKET_CAPTURE_COUNT, PACKET_CAPTURE_TIMEOUT

# Set up logging
logger = logging.getLogger(__name__)

class TrafficAnalyzer:
    """
    A network traffic analyzer that captures and analyzes packets.
    """
    
    def __init__(self):
        """Initialize the traffic analyzer."""
        self.packets = []
        self.start_time = None
        self.end_time = None
        self.stats = {}
        self.conversations = defaultdict(list)
        self.packet_types = Counter()
        self.source_ips = Counter()
        self.destination_ips = Counter()
        self.protocols = Counter()
        self.ports = Counter()
        
    def get_available_interfaces(self):
        """
        Get a list of available network interfaces.
        
        Returns:
            list: List of network interface names
        """
        interfaces = []
        
        for iface in netifaces.interfaces():
            # Skip loopback interfaces
            if iface.startswith("lo"):
                continue
                
            # Get interface addresses
            addresses = netifaces.ifaddresses(iface)
            
            # Check if the interface has an IPv4 address
            if netifaces.AF_INET in addresses:
                interfaces.append(iface)
        
        return interfaces
    
    def packet_callback(self, packet):
        """
        Process a captured packet.
        
        Args:
            packet: The captured packet
        """
        # Store the original packet
        self.packets.append(packet)
        
        # Extract basic information from the packet
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto
            
            # Update counters
            self.source_ips[src_ip] += 1
            self.destination_ips[dst_ip] += 1
            
            # Update conversation tracking
            conv_key = f"{src_ip}:{dst_ip}"
            self.conversations[conv_key].append(packet)
            
            # Analyze based on protocol
            if TCP in packet:
                self.packet_types["TCP"] += 1
                self.protocols["TCP"] += 1
                
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                
                # Track most common destination ports
                self.ports[dst_port] += 1
                
                # Identify common services
                if dst_port == 80 or dst_port == 443:
                    self.packet_types["HTTP/HTTPS"] += 1
                elif dst_port == 53:
                    self.packet_types["DNS"] += 1
                elif dst_port == 22:
                    self.packet_types["SSH"] += 1
                elif dst_port == 25 or dst_port == 587 or dst_port == 465:
                    self.packet_types["SMTP"] += 1
                
            elif UDP in packet:
                self.packet_types["UDP"] += 1
                self.protocols["UDP"] += 1
                
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                
                # Track most common destination ports
                self.ports[dst_port] += 1
                
                # DNS traffic analysis
                if DNS in packet:
                    self.packet_types["DNS"] += 1
                
            elif ICMP in packet:
                self.packet_types["ICMP"] += 1
                self.protocols["ICMP"] += 1
        
        elif ARP in packet:
            self.packet_types["ARP"] += 1
            self.protocols["ARP"] += 1
    
    def capture_traffic(self, interface=None, count=PACKET_CAPTURE_COUNT, timeout=PACKET_CAPTURE_TIMEOUT):
        """
        Capture network traffic.
        
        Args:
            interface (str): Network interface to capture traffic on
            count (int): Number of packets to capture
            timeout (int): Timeout for capturing packets in seconds
            
        Returns:
            dict: Traffic analysis results
        """
        # Reset statistics
        self.packets = []
        self.start_time = None
        self.end_time = None
        self.stats = {}
        self.conversations = defaultdict(list)
        self.packet_types = Counter()
        self.source_ips = Counter()
        self.destination_ips = Counter()
        self.protocols = Counter()
        self.ports = Counter()
        
        # Get available interfaces if none specified
        if interface is None:
            available_interfaces = self.get_available_interfaces()
            if not available_interfaces:
                logger.error("No available network interfaces found")
                return None
            interface = available_interfaces[0]
        
        print(f"[*] Starting packet capture on interface: {interface}")
        print(f"[*] Capturing {count} packets or until {timeout} seconds timeout...")
        
        # Record start time
        self.start_time = time.time()
        
        try:
            # Capture packets
            sniff(iface=interface, prn=self.packet_callback, count=count, timeout=timeout)
        except Exception as e:
            logger.error(f"Error during packet capture: {str(e)}")
            return None
        
        # Record end time
        self.end_time = time.time()
        
        # Calculate basic statistics
        self.stats = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "interface": interface,
            "duration": round(self.end_time - self.start_time, 2),
            "total_packets": len(self.packets),
            "packets_per_second": round(len(self.packets) / (self.end_time - self.start_time), 2) if self.end_time > self.start_time else 0,
            "packet_types": dict(self.packet_types),
            "protocols": dict(self.protocols),
            "top_source_ips": dict(self.source_ips.most_common(10)),
            "top_destination_ips": dict(self.destination_ips.most_common(10)),
            "top_destination_ports": dict(self.ports.most_common(10)),
            "total_conversations": len(self.conversations),
        }
        
        # Print summary
        print(f"\n[*] Packet capture completed in {self.stats['duration']} seconds")
        print(f"[*] Captured {self.stats['total_packets']} packets " +
              f"({self.stats['packets_per_second']} packets/sec)")
        
        print("\n[*] Packet Type Distribution:")
        for packet_type, count in self.packet_types.most_common():
            percentage = (count / self.stats['total_packets']) * 100 if self.stats['total_packets'] > 0 else 0
            print(f"    - {packet_type}: {count} ({percentage:.1f}%)")
        
        print("\n[*] Top Source IPs:")
        for ip, count in self.source_ips.most_common(5):
            percentage = (count / self.stats['total_packets']) * 100 if self.stats['total_packets'] > 0 else 0
            print(f"    - {ip}: {count} ({percentage:.1f}%)")
        
        print("\n[*] Top Destination IPs:")
        for ip, count in self.destination_ips.most_common(5):
            percentage = (count / self.stats['total_packets']) * 100 if self.stats['total_packets'] > 0 else 0
            print(f"    - {ip}: {count} ({percentage:.1f}%)")
        
        print("\n[*] Top Destination Ports:")
        for port, count in self.ports.most_common(5):
            try:
                service = socket.getservbyport(port)
            except (socket.error, OSError):
                service = "unknown"
            
            percentage = (count / self.stats['total_packets']) * 100 if self.stats['total_packets'] > 0 else 0
            print(f"    - {port} ({service}): {count} ({percentage:.1f}%)")
        
        return self.stats
    
    def create_conversation_dataframe(self):
        """
        Create a pandas DataFrame of network conversations.
        
        Returns:
            pandas.DataFrame: DataFrame of network conversations
        """
        conversation_data = []
        
        for conv_key, packets in self.conversations.items():
            src_ip, dst_ip = conv_key.split(":")
            
            # Count packets and bytes
            packet_count = len(packets)
            byte_count = sum(len(p) for p in packets)
            
            # Identify protocol (using the most common protocol for this conversation)
            protocols = Counter()
            for p in packets:
                if TCP in p:
                    protocols["TCP"] += 1
                elif UDP in p:
                    protocols["UDP"] += 1
                elif ICMP in p:
                    protocols["ICMP"] += 1
            
            protocol = protocols.most_common(1)[0][0] if protocols else "Unknown"
            
            # Extract ports (for TCP/UDP)
            src_ports = set()
            dst_ports = set()
            
            for p in packets:
                if TCP in p:
                    src_ports.add(p[TCP].sport)
                    dst_ports.add(p[TCP].dport)
                elif UDP in p:
                    src_ports.add(p[UDP].sport)
                    dst_ports.add(p[UDP].dport)
            
            src_ports_str = ", ".join(map(str, src_ports))
            dst_ports_str = ", ".join(map(str, dst_ports))
            
            # Calculate conversation duration
            if len(packets) >= 2:
                first_pkt_time = packets[0].time
                last_pkt_time = packets[-1].time
                duration = last_pkt_time - first_pkt_time
            else:
                duration = 0
            
            # Add to conversation data
            conversation_data.append({
                "Source IP": src_ip,
                "Destination IP": dst_ip,
                "Protocol": protocol,
                "Source Ports": src_ports_str,
                "Destination Ports": dst_ports_str,
                "Packets": packet_count,
                "Bytes": byte_count,
                "Duration": round(duration, 3),
                "Bytes/s": round(byte_count / duration if duration > 0 else 0, 2)
            })
        
        # Create DataFrame
        return pd.DataFrame(conversation_data)
    
    def get_packets(self):
        """
        Get the captured packets.
        
        Returns:
            list: Captured packets
        """
        return self.packets
    
    def get_stats(self):
        """
        Get traffic analysis statistics.
        
        Returns:
            dict: Traffic analysis statistics
        """
        return self.stats

# Function to run the traffic analyzer from command line
def run_traffic_analyzer(args):
    """
    Run the traffic analyzer with command line arguments.
    
    Args:
        args: Command line arguments
    """
    analyzer = TrafficAnalyzer()
    
    # Display available interfaces if requested
    if args.list_interfaces:
        interfaces = analyzer.get_available_interfaces()
        print("[*] Available network interfaces:")
        for i, iface in enumerate(interfaces):
            print(f"    {i+1}. {iface}")
        return
    
    # Capture traffic
    analyzer.capture_traffic(
        interface=args.interface,
        count=args.count,
        timeout=args.timeout
    )

# For testing purposes
if __name__ == "__main__":
    analyzer = TrafficAnalyzer()
    available_interfaces = analyzer.get_available_interfaces()
    
    if available_interfaces:
        print("Available interfaces:", available_interfaces)
        stats = analyzer.capture_traffic(interface=available_interfaces[0], count=100)
        print("\nFull statistics:", stats)
    else:
        print("No available interfaces found")
