import socket
import sys
import threading
import time
import logging
import concurrent.futures
from datetime import datetime
import whois
from tqdm import tqdm
from colorama import Fore, Style, init

from netsecmonitor.config import DEFAULT_PORT_RANGES, DEFAULT_SCAN_TIMEOUT

# Initialize colorama
init(autoreset=True)

# Set up logging
logger = logging.getLogger(__name__)

class PortScanner:
    """
    A port scanner that can scan hosts for open ports using TCP connect scans.
    """
    
    def __init__(self, timeout=DEFAULT_SCAN_TIMEOUT):
        """
        Initialize the port scanner.
        
        Args:
            timeout (float): Timeout for connection attempts in seconds
        """
        self.timeout = timeout
        self.open_ports = []
        self.scan_results = {}
        self.start_time = None
        self.end_time = None
        
    def scan_port(self, target_ip, port):
        """
        Scan a single port on the target IP.
        
        Args:
            target_ip (str): The target IP address to scan
            port (int): The port number to scan
            
        Returns:
            tuple: (port, is_open, service_name)
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        service_name = "unknown"
        
        try:
            # Attempt to connect to the port
            result = sock.connect_ex((target_ip, port))
            
            # If the connection was successful (return code 0), the port is open
            if result == 0:
                try:
                    # Try to get the service name
                    service_name = socket.getservbyport(port)
                except (socket.error, OSError):
                    pass
                
                return (port, True, service_name)
        except socket.error:
            pass
        finally:
            sock.close()
            
        return (port, False, service_name)
    
    def scan_target(self, target, ports="common", max_workers=100, show_progress=True):
        """
        Scan a target IP for open ports.
        
        Args:
            target (str): The target IP address or hostname to scan
            ports (str or list): Port range to scan ('common', 'full', 'extended' or a list of ports)
            max_workers (int): Maximum number of concurrent workers for scanning
            show_progress (bool): Whether to show a progress bar
            
        Returns:
            dict: Scan results
        """
        # Reset scan results
        self.open_ports = []
        self.scan_results = {
            "target": target,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "open_ports": [],
            "scan_duration": 0,
            "total_ports_scanned": 0
        }
        
        # Record start time
        self.start_time = time.time()
        
        # Resolve hostname to IP if needed
        try:
            target_ip = socket.gethostbyname(target)
            self.scan_results["ip_address"] = target_ip
            
            # Try to get domain information if target is a hostname
            if target != target_ip:
                self.scan_results["hostname"] = target
                try:
                    domain_info = whois.whois(target)
                    self.scan_results["domain_info"] = {
                        "registrar": getattr(domain_info, "registrar", "Unknown"),
                        "creation_date": getattr(domain_info, "creation_date", "Unknown"),
                        "expiration_date": getattr(domain_info, "expiration_date", "Unknown"),
                    }
                except Exception as e:
                    logger.warning(f"Could not get domain information: {str(e)}")
        except socket.gaierror:
            logger.error(f"Hostname resolution failed for {target}")
            return None
        
        # Determine which ports to scan
        if isinstance(ports, str):
            if ports.lower() in DEFAULT_PORT_RANGES:
                ports_to_scan = DEFAULT_PORT_RANGES[ports.lower()]
            else:
                logger.error(f"Unknown port range: {ports}")
                return None
        else:
            ports_to_scan = ports
        
        self.scan_results["total_ports_scanned"] = len(ports_to_scan)
        
        print(f"\n{Fore.CYAN}[*] Starting scan on host: {target} ({target_ip}){Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Time started: {self.scan_results['timestamp']}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Scanning {len(ports_to_scan)} ports...{Style.RESET_ALL}\n")
        
        # Use ThreadPoolExecutor for concurrent scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Create a dictionary of futures to port numbers
            future_to_port = {
                executor.submit(self.scan_port, target_ip, port): port 
                for port in ports_to_scan
            }
            
            # Process results as they complete
            if show_progress:
                futures = tqdm(
                    concurrent.futures.as_completed(future_to_port),
                    total=len(ports_to_scan),
                    desc="Scanning",
                    unit="port"
                )
            else:
                futures = concurrent.futures.as_completed(future_to_port)
                
            for future in futures:
                port, is_open, service_name = future.result()
                if is_open:
                    self.open_ports.append(port)
                    self.scan_results["open_ports"].append({
                        "port": port,
                        "service": service_name,
                        "state": "open"
                    })
        
        # Record end time and calculate duration
        self.end_time = time.time()
        self.scan_results["scan_duration"] = round(self.end_time - self.start_time, 2)
        
        # Print results
        if self.open_ports:
            print(f"\n{Fore.GREEN}[+] Open ports found:{Style.RESET_ALL}")
            for port_info in self.scan_results["open_ports"]:
                print(f"{Fore.GREEN}    [+] {port_info['port']}/tcp - {port_info['service']}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.YELLOW}[!] No open ports found{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}[*] Scan completed in {self.scan_results['scan_duration']} seconds{Style.RESET_ALL}")
        
        return self.scan_results
    
    def get_results(self):
        """
        Get the scan results.
        
        Returns:
            dict: Scan results
        """
        return self.scan_results

# Function to run the port scanner from command line
def run_port_scanner(args):
    """
    Run the port scanner with command line arguments.
    
    Args:
        args: Command line arguments
    """
    scanner = PortScanner(timeout=args.timeout)
    
    if args.port_range == "custom" and args.ports:
        # Parse custom port list
        try:
            custom_ports = []
            for port_spec in args.ports.split(","):
                if "-" in port_spec:
                    start, end = map(int, port_spec.split("-"))
                    custom_ports.extend(range(start, end + 1))
                else:
                    custom_ports.append(int(port_spec))
            ports = custom_ports
        except ValueError:
            print(f"{Fore.RED}[!] Invalid port specification{Style.RESET_ALL}")
            sys.exit(1)
    else:
        ports = args.port_range
    
    scanner.scan_target(args.target, ports=ports, max_workers=args.workers, show_progress=True)

# For testing purposes
if __name__ == "__main__":
    scanner = PortScanner()
    results = scanner.scan_target("scanme.nmap.org", ports="common")
    print(results)
