import os
import json
import socket
import logging
from pathlib import Path

# Project paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
SIGNATURES_DIR = DATA_DIR / "signatures"
REPORTS_DIR = DATA_DIR / "reports"

# Create directories if they don't exist
for directory in [DATA_DIR, SIGNATURES_DIR, REPORTS_DIR]:
    directory.mkdir(exist_ok=True, parents=True)

# Default network interface
# This will be overridden by command-line arguments if provided
DEFAULT_INTERFACE = ""

# Default port scanning ranges
DEFAULT_PORT_RANGES = {
    "common": [21, 22, 23, 25, 53, 80, 110, 115, 135, 139, 143, 
              194, 443, 445, 1433, 3306, 3389, 5632, 5900, 8080],
    "full": range(1, 1025),
    "extended": range(1, 10000),
}

# Default scan timeout (in seconds)
DEFAULT_SCAN_TIMEOUT = 1.0

# Intrusion detection settings
IDS_SIGNATURE_FILE = SIGNATURES_DIR / "basic_signatures.json"

# Traffic analysis settings
PACKET_CAPTURE_COUNT = 1000  # Default number of packets to capture for analysis
PACKET_CAPTURE_TIMEOUT = 60  # Default timeout for packet capture (seconds)

# Reporting settings
REPORT_FORMAT = "txt"  # Options: txt, json, csv
REPORT_PREFIX = "security_report_"

# Visualization settings
DEFAULT_CHART_FORMAT = "png"  # Options: png, pdf
CHARTS_DIR = DATA_DIR / "charts"
CHARTS_DIR.mkdir(exist_ok=True)

# Logging configuration
LOG_LEVEL = logging.INFO
LOG_FILE = BASE_DIR / "netsecmonitor.log"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# Function to load signatures from the signature file
def load_signatures():
    """Load intrusion detection signatures from the signature file."""
    try:
        if not os.path.exists(IDS_SIGNATURE_FILE):
            # Create a default signature file if it doesn't exist
            default_signatures = {
                "signatures": [
                    {
                        "id": "SIG-001",
                        "name": "Port Scan Detection",
                        "description": "Detects rapid connection attempts to multiple ports",
                        "detection": {
                            "type": "frequency",
                            "threshold": 10,
                            "timeframe": 5,
                            "ports": "multiple"
                        },
                        "severity": "medium"
                    },
                    {
                        "id": "SIG-002",
                        "name": "SSH Brute Force Attempt",
                        "description": "Detects multiple failed SSH login attempts",
                        "detection": {
                            "type": "pattern",
                            "port": 22,
                            "protocol": "tcp",
                            "pattern": "Failed password",
                            "threshold": 5
                        },
                        "severity": "high"
                    },
                    {
                        "id": "SIG-003",
                        "name": "DNS Tunneling",
                        "description": "Detects potential DNS tunneling activity",
                        "detection": {
                            "type": "anomaly",
                            "port": 53,
                            "protocol": "udp",
                            "condition": "unusual_length",
                            "threshold": 100
                        },
                        "severity": "high"
                    }
                ]
            }
            with open(IDS_SIGNATURE_FILE, "w") as f:
                json.dump(default_signatures, f, indent=4)
            return default_signatures["signatures"]
        
        with open(IDS_SIGNATURE_FILE, "r") as f:
            return json.load(f)["signatures"]
    except Exception as e:
        logging.error(f"Error loading signatures: {str(e)}")
        return []

# Get local IP address
def get_local_ip():
    """Get the local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Doesn't need to be reachable
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

# Local IP address
LOCAL_IP = get_local_ip()
