import os
import logging
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend to avoid display issues
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from datetime import datetime
from collections import Counter

from netsecmonitor.config import CHARTS_DIR, DEFAULT_CHART_FORMAT

# Set up logging
logger = logging.getLogger(__name__)

class NetworkVisualizer:
    """
    A class for visualizing network traffic and security data.
    """
    
    def __init__(self, output_dir=CHARTS_DIR, format=DEFAULT_CHART_FORMAT):
        """
        Initialize the network visualizer.
        
        Args:
            output_dir (str): Directory to save visualizations
            format (str): Output format for visualizations (png, pdf)
        """
        self.output_dir = output_dir
        self.format = format
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Set matplotlib style
        plt.style.use('ggplot')
    
    def visualize_packet_types(self, packet_types):
        """
        Create a pie chart of packet types with improved layout.
        
        Args:
            packet_types (dict): Dictionary of packet types and counts
            
        Returns:
            str: Path to the saved visualization
        """
        # Filter out packet types with very small percentages (less than 1%)
        total = sum(packet_types.values())
        significant_types = {k: v for k, v in packet_types.items() 
                            if (v / total) * 100 >= 1.0}
        
        # If there are very small values, add them as "Other"
        other_count = sum(v for k, v in packet_types.items() 
                         if (v / total) * 100 < 1.0)
        
        if other_count > 0:
            significant_types["Other"] = other_count
        
        # Create a new figure with a larger size for better readability
        plt.figure(figsize=(12, 8))
        
        # Create pie chart with better spacing
        labels = significant_types.keys()
        sizes = significant_types.values()
        
        # Calculate percentages for labels
        pct_values = [100 * s / sum(sizes) for s in sizes]
        labels = [f"{l} ({p:.1f}%)" for l, p in zip(labels, pct_values)]
        
        # Explode the first slice slightly
        explode = [0.1 if i == 0 else 0 for i in range(len(significant_types))]
        
        # Create pie chart with better text positioning
        plt.pie(sizes, explode=explode, labels=None, autopct=None,
                shadow=True, startangle=90, colors=plt.cm.Paired.colors)
        
        # Add a legend instead of labels on the pie
        plt.legend(labels, loc="best", fontsize=12)
        
        # Equal aspect ratio ensures that pie is drawn as a circle
        plt.axis('equal')
        
        plt.title('Network Traffic by Packet Type', fontsize=16, pad=20)
        
        # Save the figure
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"packet_types_{timestamp}.{self.format}"
        filepath = os.path.join(self.output_dir, filename)
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        return filepath

    
    def visualize_top_ips(self, source_ips, destination_ips, top_n=10):
        """
        Create a bar chart of top source and destination IPs with improved layout.
        
        Args:
            source_ips (dict): Dictionary of source IPs and counts
            destination_ips (dict): Dictionary of destination IPs and counts
            top_n (int): Number of top IPs to display
            
        Returns:
            str: Path to the saved visualization
        """
        # Get top N source and destination IPs
        top_src = dict(Counter(source_ips).most_common(top_n))
        top_dst = dict(Counter(destination_ips).most_common(top_n))
        
        # Create figure with two subplots and more space
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10), dpi=100)
        fig.subplots_adjust(hspace=0.4)  # Add more space between subplots
        
        # Source IPs
        src_ips = list(top_src.keys())
        src_counts = list(top_src.values())
        
        # Truncate long IP addresses for better display
        src_ips_display = [ip if len(ip) < 15 else ip[:12] + '...' for ip in src_ips]
        
        bars1 = ax1.barh(src_ips_display, src_counts, color='skyblue')
        ax1.set_title('Top Source IPs', fontsize=14)
        ax1.set_xlabel('Packet Count', fontsize=12)
        ax1.tick_params(axis='y', labelsize=10)
        ax1.invert_yaxis()  # Invert y-axis to show highest at the top
        
        # Add count labels to the bars
        for i, bar in enumerate(bars1):
            width = bar.get_width()
            label_position = width + (width * 0.02)  # Position label slightly to the right
            ax1.text(label_position, bar.get_y() + bar.get_height()/2, 
                    f"{src_counts[i]} ({src_ips[i]})" if src_ips[i] != src_ips_display[i] else str(src_counts[i]),
                    va='center', fontsize=9)
        
        # Destination IPs
        dst_ips = list(top_dst.keys())
        dst_counts = list(top_dst.values())
        
        # Truncate long IP addresses for better display
        dst_ips_display = [ip if len(ip) < 15 else ip[:12] + '...' for ip in dst_ips]
        
        bars2 = ax2.barh(dst_ips_display, dst_counts, color='salmon')
        ax2.set_title('Top Destination IPs', fontsize=14)
        ax2.set_xlabel('Packet Count', fontsize=12)
        ax2.tick_params(axis='y', labelsize=10)
        ax2.invert_yaxis()  # Invert y-axis to show highest at the top
        
        # Add count labels to the bars
        for i, bar in enumerate(bars2):
            width = bar.get_width()
            label_position = width + (width * 0.02)  # Position label slightly to the right
            ax2.text(label_position, bar.get_y() + bar.get_height()/2, 
                    f"{dst_counts[i]} ({dst_ips[i]})" if dst_ips[i] != dst_ips_display[i] else str(dst_counts[i]),
                    va='center', fontsize=9)
        
        plt.tight_layout()
        
        # Save the figure
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"top_ips_{timestamp}.{self.format}"
        filepath = os.path.join(self.output_dir, filename)
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        return filepath
    
    def visualize_traffic_over_time(self, timestamps, packet_sizes):
        """
        Create a line chart of traffic volume over time.
        
        Args:
            timestamps (list): List of packet timestamps
            packet_sizes (list): List of packet sizes
            
        Returns:
            str: Path to the saved visualization
        """
        # Convert timestamps to datetime if they're not already
        if not isinstance(timestamps[0], datetime):
            timestamps = [datetime.fromtimestamp(ts) for ts in timestamps]
        
        # Create a DataFrame for easier handling
        df = pd.DataFrame({
            'timestamp': timestamps,
            'size': packet_sizes
        })
        
        # Resample to get traffic per second
        df.set_index('timestamp', inplace=True)
        traffic_per_second = df.resample('1S').sum()
        
        # Create the plot
        plt.figure(figsize=(12, 6))
        plt.plot(traffic_per_second.index, traffic_per_second['size'], 
                 marker='o', linestyle='-', markersize=3)
        
        plt.title('Network Traffic Volume Over Time')
        plt.xlabel('Time')
        plt.ylabel('Bytes per Second')
        plt.grid(True)
        
        # Format the x-axis to show time properly
        plt.gcf().autofmt_xdate()
        
        # Save the figure
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"traffic_over_time_{timestamp}.{self.format}"
        filepath = os.path.join(self.output_dir, filename)
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        return filepath
    
    def visualize_port_distribution(self, ports, top_n=10):
        """
        Create a bar chart of the most common destination ports with improved layout.
        
        Args:
            ports (dict): Dictionary of destination ports and counts
            top_n (int): Number of top ports to display
            
        Returns:
            str: Path to the saved visualization
        """
        # Get top N ports
        top_ports = dict(Counter(ports).most_common(top_n))
        
        # Try to resolve port names
        port_names = []
        for port in top_ports.keys():
            try:
                import socket
                service = socket.getservbyport(int(port))
                port_names.append(f"{port}\n({service})")
            except (socket.error, ValueError, OSError):
                port_names.append(str(port))
        
        # Create the plot
        plt.figure(figsize=(14, 7))
        bars = plt.bar(port_names, top_ports.values(), color='lightgreen', width=0.6)
        
        plt.title('Top Destination Ports', fontsize=16, pad=20)
        plt.xlabel('Port (Service)', fontsize=12)
        plt.ylabel('Packet Count', fontsize=12)
        
        # Add count labels above the bars
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                    str(int(height)), ha='center', va='bottom', fontsize=10)
        
        plt.xticks(rotation=0, fontsize=10)  # Horizontal labels with port services on next line
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        plt.tight_layout()
        
        # Save the figure
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"port_distribution_{timestamp}.{self.format}"
        filepath = os.path.join(self.output_dir, filename)
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        return filepath
    
    def visualize_protocol_distribution(self, protocols):
        """
        Create a pie chart of protocol distribution with improved layout.
        
        Args:
            protocols (dict): Dictionary of protocols and counts
            
        Returns:
            str: Path to the saved visualization
        """
        # Filter out protocols with very small percentages
        total = sum(protocols.values())
        significant_protocols = {k: v for k, v in protocols.items() 
                                if (v / total) * 100 >= 1.0}
        
        # If there are very small values, add them as "Other"
        other_count = sum(v for k, v in protocols.items() 
                         if (v / total) * 100 < 1.0)
        
        if other_count > 0:
            significant_protocols["Other"] = other_count
        
        # Create a new figure
        plt.figure(figsize=(12, 8))
        
        # Calculate percentages for labels
        sizes = list(significant_protocols.values())
        pct_values = [100 * s / sum(sizes) for s in sizes]
        labels = [f"{l} ({p:.1f}%)" for l, p in zip(significant_protocols.keys(), pct_values)]
        
        # Create pie chart with better text positioning
        plt.pie(sizes, labels=None, autopct=None,
                shadow=True, startangle=90, colors=plt.cm.Set3.colors)
        
        # Add a legend instead of labels on the pie
        plt.legend(labels, loc="best", fontsize=12)
        
        plt.axis('equal')
        plt.title('Network Traffic by Protocol', fontsize=16, pad=20)
        
        # Save the figure
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"protocol_distribution_{timestamp}.{self.format}"
        filepath = os.path.join(self.output_dir, filename)
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        return filepath
    
    def visualize_alerts(self, alerts):
        """
        Create visualizations of security alerts.
        
        Args:
            alerts (list): List of alert dictionaries
            
        Returns:
            str: Path to the saved visualization
        """
        if not alerts:
            logger.warning("No alerts to visualize")
            return None
        
        # Count alerts by type and severity
        alert_types = Counter([alert['signature_name'] for alert in alerts])
        alert_severities = Counter([alert['severity'] for alert in alerts])
        
        # Create a figure with two subplots
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
        
        # Alert Types
        ax1.bar(alert_types.keys(), alert_types.values(), color='lightcoral')
        ax1.set_title('Alerts by Type')
        ax1.set_ylabel('Count')
        ax1.tick_params(axis='x', rotation=45)
        
        # Alert Severities
        severity_order = ['low', 'medium', 'high', 'critical']
        severities = [s for s in severity_order if s in alert_severities]
        counts = [alert_severities[s] for s in severities]
        
        # Use different colors for different severities
        severity_colors = {
            'low': 'lightgreen',
            'medium': 'gold',
            'high': 'orange',
            'critical': 'red'
        }
        colors = [severity_colors[s] for s in severities]
        
        ax2.bar(severities, counts, color=colors)
        ax2.set_title('Alerts by Severity')
        ax2.set_ylabel('Count')
        
        plt.tight_layout()
        
        # Save the figure
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_alerts_{timestamp}.{self.format}"
        filepath = os.path.join(self.output_dir, filename)
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        # Create a timeline of alerts
        self._create_alert_timeline(alerts)
        
        return filepath
    
    def _create_alert_timeline(self, alerts):
        """
        Create a timeline visualization of alerts.
        
        Args:
            alerts (list): List of alert dictionaries
            
        Returns:
            str: Path to the saved visualization
        """
        # Convert alert timestamps to datetime
        for alert in alerts:
            alert['datetime'] = datetime.strptime(alert['timestamp'], "%Y-%m-%d %H:%M:%S")
        
        # Sort alerts by time
        alerts = sorted(alerts, key=lambda x: x['datetime'])
        
        # Create the plot
        plt.figure(figsize=(12, 6))
        
        # Define severity colors
        severity_colors = {
            'low': 'green',
            'medium': 'orange',
            'high': 'red',
            'critical': 'darkred'
        }
        
        # Plot each alert as a scatter point
        for severity in severity_colors:
            # Filter alerts by severity
            filtered_alerts = [a for a in alerts if a['severity'] == severity]
            
            if filtered_alerts:
                # Extract timestamps and y-positions (using index for y-position)
                timestamps = [a['datetime'] for a in filtered_alerts]
                # Use signature_id as y value
                y_values = np.ones(len(filtered_alerts))
                
                plt.scatter(timestamps, y_values, 
                          s=100, c=severity_colors[severity], 
                          alpha=0.7, label=severity.capitalize())
                
                # Add signature names as annotations
                for i, alert in enumerate(filtered_alerts):
                    plt.annotate(alert['signature_name'], 
                               (alert['datetime'], 1),
                               xytext=(0, 10), 
                               textcoords='offset points',
                               ha='center', 
                               rotation=45,
                               fontsize=8)
        
        plt.title('Security Alert Timeline')
        plt.xlabel('Time')
        plt.yticks([])  # Hide y-axis ticks
        plt.legend(title='Severity')
        plt.grid(True, axis='x')
        
        # Format the x-axis to show time properly
        plt.gcf().autofmt_xdate()
        
        # Save the figure
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"alert_timeline_{timestamp}.{self.format}"
        filepath = os.path.join(self.output_dir, filename)
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        return filepath
    
    def create_dashboard(self, traffic_stats, ids_alerts):
        """
        Create a comprehensive dashboard of network traffic and security visualizations.
        
        Args:
            traffic_stats (dict): Traffic analysis statistics
            ids_alerts (list): List of IDS alerts
            
        Returns:
            list: List of paths to the saved visualizations
        """
        visualization_paths = []
        
        # Visualize packet types
        if 'packet_types' in traffic_stats and traffic_stats['packet_types']:
            path = self.visualize_packet_types(traffic_stats['packet_types'])
            visualization_paths.append(path)
        
        # Visualize top IPs
        if ('top_source_ips' in traffic_stats and traffic_stats['top_source_ips'] and
            'top_destination_ips' in traffic_stats and traffic_stats['top_destination_ips']):
            path = self.visualize_top_ips(
                traffic_stats['top_source_ips'],
                traffic_stats['top_destination_ips']
            )
            visualization_paths.append(path)
        
        # Visualize port distribution
        if 'top_destination_ports' in traffic_stats and traffic_stats['top_destination_ports']:
            path = self.visualize_port_distribution(traffic_stats['top_destination_ports'])
            visualization_paths.append(path)
        
        # Visualize protocol distribution
        if 'protocols' in traffic_stats and traffic_stats['protocols']:
            path = self.visualize_protocol_distribution(traffic_stats['protocols'])
            visualization_paths.append(path)
        
        # Visualize security alerts
        if ids_alerts:
            path = self.visualize_alerts(ids_alerts)
            if path:
                visualization_paths.append(path)
        
        return visualization_paths

# Function to run the visualizer from command line
def run_visualizer(args, traffic_analyzer, ids):
    """
    Run the network visualizer with command line arguments.
    
    Args:
        args: Command line arguments
        traffic_analyzer: TrafficAnalyzer instance
        ids: IntrusionDetectionSystem instance
    """
    visualizer = NetworkVisualizer()
    
    print("\n[*] Generating visualizations...")
    
    # Get traffic stats and alerts
    traffic_stats = traffic_analyzer.get_stats()
    ids_alerts = ids.get_alerts() if ids else []
    
    # Create dashboard
    paths = visualizer.create_dashboard(traffic_stats, ids_alerts)
    
    if paths:
        print(f"[*] Created {len(paths)} visualizations:")
        for path in paths:
            print(f"    - {path}")
    else:
        print("[!] No visualizations created")
