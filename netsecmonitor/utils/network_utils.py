import socket
import struct
import logging
import netifaces
import subprocess
import platform
from ipaddress import ip_network, IPv4Address

# Set up logging
logger = logging.getLogger(__name__)

def get_local_ip():
    """
    Get the local IP address.
    
    Returns:
        str: Local IP address
    """
    try:
        # Create a temporary socket to determine the local IP address
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        logger.error(f"Error getting local IP: {str(e)}")
        return "127.0.0.1"

def get_network_interfaces():
    """
    Get a list of network interfaces.
    
    Returns:
        list: List of network interfaces
    """
    try:
        interfaces = []
        for iface in netifaces.interfaces():
            # Skip loopback interfaces
            if iface.startswith("lo"):
                continue
            
            # Get interface addresses
            addresses = netifaces.ifaddresses(iface)
            
            # Only include interfaces with IPv4 addresses
            if netifaces.AF_INET in addresses:
                ip = addresses[netifaces.AF_INET][0]['addr']
                netmask = addresses[netifaces.AF_INET][0]['netmask']
                
                # Get MAC address if available
                mac = "Unknown"
                if netifaces.AF_LINK in addresses:
                    mac = addresses[netifaces.AF_LINK][0].get('addr', "Unknown")
                
                interfaces.append({
                    'name': iface,
                    'ip': ip,
                    'netmask': netmask,
                    'mac': mac
                })
        
        return interfaces
    except Exception as e:
        logger.error(f"Error getting network interfaces: {str(e)}")
        return []

def get_network_range(interface):
    """
    Get the network range for a given interface.
    
    Args:
        interface (dict): Network interface information
        
    Returns:
        str: Network range in CIDR notation
    """
    try:
        ip = interface['ip']
        netmask = interface['netmask']
        
        # Convert IP and netmask to integer
        ip_int = struct.unpack('!I', socket.inet_aton(ip))[0]
        netmask_int = struct.unpack('!I', socket.inet_aton(netmask))[0]
        
        # Calculate network address
        network_int = ip_int & netmask_int
        network = socket.inet_ntoa(struct.pack('!I', network_int))
        
        # Calculate CIDR prefix length
        cidr = bin(netmask_int).count('1')
        
        return f"{network}/{cidr}"
    except Exception as e:
        logger.error(f"Error calculating network range: {str(e)}")
        return None

def get_network_hosts(network_range, exclude_network_broadcast=True):
    """
    Get a list of all host IP addresses in a network range.
    
    Args:
        network_range (str): Network range in CIDR notation
        exclude_network_broadcast (bool): Whether to exclude network and broadcast addresses
        
    Returns:
        list: List of host IP addresses
    """
    try:
        network = ip_network(network_range)
        
        if exclude_network_broadcast and network.num_addresses > 2:
            # Exclude network address (first) and broadcast address (last)
            hosts = [str(ip) for ip in list(network.hosts())]
        else:
            hosts = [str(ip) for ip in network]
        
        return hosts
    except Exception as e:
        logger.error(f"Error getting network hosts: {str(e)}")
        return []

def is_host_up(ip, timeout=0.5):
    """
    Check if a host is up using ICMP ping.
    
    Args:
        ip (str): IP address to check
        timeout (float): Timeout in seconds
        
    Returns:
        bool: True if host is up, False otherwise
    """
    try:
        # Different ping commands based on platform
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
        
        # Construct ping command with timeout
        command = ['ping', param, '1', timeout_param, str(int(timeout * 1000)), ip]
        
        # Execute ping command
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout+1)
        
        # Check if ping was successful (return code 0)
        return result.returncode == 0
    except Exception as e:
        logger.debug(f"Error pinging {ip}: {str(e)}")
        return False

def arp_scan(interface):
    """
    Perform an ARP scan to discover hosts on the local network.
    
    Args:
        interface (dict): Network interface information
        
    Returns:
        list: List of discovered hosts (IP, MAC)
    """
    try:
        from scapy.all import ARP, Ether, srp
        
        # Get network range
        network_range = get_network_range(interface)
        if not network_range:
            return []
        
        # Get list of hosts in the network
        hosts = get_network_hosts(network_range)
        
        # Create ARP request packets for all hosts
        discovered_hosts = []
        
        # Send ARP request for each host
        for host in hosts:
            # Create ARP request packet
            arp = ARP(pdst=host)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            # Send packet and get response
            result = srp(packet, timeout=2, verbose=0, iface=interface['name'])
            
            # Process responses
            if result and result[0]:
                for sent, received in result[0]:
                    discovered_hosts.append({
                        'ip': received.psrc,
                        'mac': received.hwsrc
                    })
        
        return discovered_hosts
    except Exception as e:
        logger.error(f"Error performing ARP scan: {str(e)}")
        return []

def hostname_lookup(ip):
    """
    Lookup hostname for an IP address.
    
    Args:
        ip (str): IP address
        
    Returns:
        str: Hostname or None if not found
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.error):
        return None

def service_name_lookup(port, protocol='tcp'):
    """
    Lookup service name for a port number.
    
    Args:
        port (int): Port number
        protocol (str): Protocol ('tcp' or 'udp')
        
    Returns:
        str: Service name or None if not found
    """
    try:
        return socket.getservbyport(port, protocol)
    except (socket.error, OSError):
        return None

def get_default_gateway():
    """
    Get the default gateway IP address.
    
    Returns:
        str: Default gateway IP address or None if not found
    """
    try:
        gateways = netifaces.gateways()
        if 'default' in gateways and netifaces.AF_INET in gateways['default']:
            return gateways['default'][netifaces.AF_INET][0]
        return None
    except Exception as e:
        logger.error(f"Error getting default gateway: {str(e)}")
        return None

def is_private_ip(ip):
    """
    Check if an IP address is private.
    
    Args:
        ip (str): IP address
        
    Returns:
        bool: True if IP is private, False otherwise
    """
    try:
        return IPv4Address(ip).is_private
    except ValueError:
        return False
