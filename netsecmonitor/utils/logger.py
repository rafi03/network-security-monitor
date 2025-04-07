import os
import logging
import logging.handlers
from datetime import datetime

from netsecmonitor.config import LOG_LEVEL, LOG_FILE, LOG_FORMAT

def setup_logging(log_file=LOG_FILE, log_level=LOG_LEVEL, log_format=LOG_FORMAT):
    """
    Set up logging for the application.
    
    Args:
        log_file (str): Path to log file
        log_level (int): Logging level
        log_format (str): Logging format
    """
    # Create log directory if it doesn't exist
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # Set up root logger
    logger = logging.getLogger()
    logger.setLevel(log_level)
    
    # Clear any existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Create formatter
    formatter = logging.Formatter(log_format)
    
    # File handler (rotating file handler to prevent large log files)
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=10*1024*1024, backupCount=5
    )
    file_handler.setLevel(log_level)
    file_handler.setFormatter(formatter)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)  # Only warning and above to console
    console_handler.setFormatter(formatter)
    
    # Add handlers to logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    logging.info(f"Logging initialized at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
class Logger:
    """
    Custom logger class that wraps the standard logging module.
    """
    
    def __init__(self, name):
        """
        Initialize the logger.
        
        Args:
            name (str): Logger name
        """
        self.logger = logging.getLogger(name)
    
    def debug(self, message):
        """
        Log a debug message.
        
        Args:
            message (str): Message to log
        """
        self.logger.debug(message)
    
    def info(self, message):
        """
        Log an info message.
        
        Args:
            message (str): Message to log
        """
        self.logger.info(message)
    
    def warning(self, message):
        """
        Log a warning message.
        
        Args:
            message (str): Message to log
        """
        self.logger.warning(message)
    
    def error(self, message):
        """
        Log an error message.
        
        Args:
            message (str): Message to log
        """
        self.logger.error(message)
    
    def critical(self, message):
        """
        Log a critical message.
        
        Args:
            message (str): Message to log
        """
        self.logger.critical(message)
