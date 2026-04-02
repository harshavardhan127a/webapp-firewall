"""
Geo-blocking Module for WAF
Blocks or allows requests based on geographic location
Uses free IP geolocation data
"""
import os
import csv
import socket
import struct
import urllib.request
import gzip
import shutil
from typing import Optional, Set, Dict, Tuple
from dataclasses import dataclass


@dataclass
class GeoInfo:
    """Geographic information for an IP"""
    country_code: str
    country_name: str
    ip: str


class GeoBlocker:
    """
    IP-based geographic blocking
    
    Uses MaxMind's free GeoLite2 country database format or
    falls back to IP2Location LITE database
    """
    
    # Common country codes
    COUNTRIES = {
        'US': 'United States',
        'CN': 'China',
        'RU': 'Russia',
        'KP': 'North Korea',
        'IR': 'Iran',
        'DE': 'Germany',
        'FR': 'France',
        'GB': 'United Kingdom',
        'JP': 'Japan',
        'KR': 'South Korea',
        'IN': 'India',
        'BR': 'Brazil',
        'AU': 'Australia',
        'CA': 'Canada',
        'NL': 'Netherlands',
        'UA': 'Ukraine',
        'PL': 'Poland',
        'RO': 'Romania',
        'VN': 'Vietnam',
        'TH': 'Thailand',
    }
    
    def __init__(
        self,
        blocked_countries: Set[str] = None,
        allowed_countries: Set[str] = None,
        db_path: str = None
    ):
        """
        Initialize geo-blocker
        
        Args:
            blocked_countries: Set of country codes to block (blocklist mode)
            allowed_countries: Set of country codes to allow (allowlist mode)
            db_path: Path to IP geolocation database
            
        Note: If both blocked_countries and allowed_countries are set,
              allowlist mode takes precedence
        """
        self.blocked_countries = blocked_countries or set()
        self.allowed_countries = allowed_countries or set()
        self.db_path = db_path or os.path.join(
            os.path.dirname(__file__), '..', 'data', 'ip2country.csv'
        )
        
        # IP range cache (loaded from database)
        self._ip_ranges: list = []
        self._loaded = False
        
        # In-memory cache for recent lookups
        self._cache: Dict[str, GeoInfo] = {}
        self._cache_max_size = 10000
    
    def _ip_to_int(self, ip: str) -> int:
        """Convert IP address to integer"""
        try:
            return struct.unpack('!I', socket.inet_aton(ip))[0]
        except (socket.error, struct.error):
            return 0
    
    def _int_to_ip(self, ip_int: int) -> str:
        """Convert integer to IP address"""
        return socket.inet_ntoa(struct.pack('!I', ip_int))
    
    def load_database(self) -> bool:
        """
        Load IP geolocation database
        Returns True if successful
        """
        if self._loaded:
            return True
        
        if not os.path.exists(self.db_path):
            print(f"[GeoBlocker] Database not found: {self.db_path}")
            print("[GeoBlocker] Run download_geo_db() to download the database")
            return False
        
        try:
            with open(self.db_path, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                for row in reader:
                    if len(row) >= 3:
                        # Format: start_ip, end_ip, country_code
                        try:
                            start_ip = int(row[0])
                            end_ip = int(row[1])
                            country = row[2].upper()
                            self._ip_ranges.append((start_ip, end_ip, country))
                        except ValueError:
                            continue
            
            # Sort by start IP for binary search
            self._ip_ranges.sort(key=lambda x: x[0])
            self._loaded = True
            print(f"[GeoBlocker] Loaded {len(self._ip_ranges)} IP ranges")
            return True
            
        except Exception as e:
            print(f"[GeoBlocker] Error loading database: {e}")
            return False
    
    def _binary_search(self, ip_int: int) -> Optional[str]:
        """Binary search for IP in ranges"""
        left, right = 0, len(self._ip_ranges) - 1
        
        while left <= right:
            mid = (left + right) // 2
            start, end, country = self._ip_ranges[mid]
            
            if start <= ip_int <= end:
                return country
            elif ip_int < start:
                right = mid - 1
            else:
                left = mid + 1
        
        return None
    
    def get_country(self, ip: str) -> Optional[GeoInfo]:
        """
        Get country information for an IP address
        Returns None if IP cannot be geolocated
        """
        # Check cache first
        if ip in self._cache:
            return self._cache[ip]
        
        # Load database if not loaded
        if not self._loaded:
            if not self.load_database():
                return None
        
        # Convert IP to integer
        ip_int = self._ip_to_int(ip)
        if ip_int == 0:
            return None
        
        # Search for country
        country_code = self._binary_search(ip_int)
        
        if country_code:
            info = GeoInfo(
                country_code=country_code,
                country_name=self.COUNTRIES.get(country_code, country_code),
                ip=ip
            )
            
            # Cache result
            if len(self._cache) < self._cache_max_size:
                self._cache[ip] = info
            
            return info
        
        return None
    
    def is_blocked(self, ip: str) -> Tuple[bool, Optional[str]]:
        """
        Check if an IP should be blocked based on country
        Returns (is_blocked, reason)
        """
        # Skip private/local IPs
        if self._is_private_ip(ip):
            return False, None
        
        geo_info = self.get_country(ip)
        
        if geo_info is None:
            # Unknown country - default to allow
            return False, None
        
        country = geo_info.country_code
        
        # Allowlist mode (if set, only these countries are allowed)
        if self.allowed_countries:
            if country not in self.allowed_countries:
                return True, f"Country {country} ({geo_info.country_name}) not in allowlist"
            return False, None
        
        # Blocklist mode
        if country in self.blocked_countries:
            return True, f"Country {country} ({geo_info.country_name}) is blocked"
        
        return False, None
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/local"""
        try:
            ip_int = self._ip_to_int(ip)
            
            # 10.0.0.0/8
            if 167772160 <= ip_int <= 184549375:
                return True
            
            # 172.16.0.0/12
            if 2886729728 <= ip_int <= 2887778303:
                return True
            
            # 192.168.0.0/16
            if 3232235520 <= ip_int <= 3232301055:
                return True
            
            # 127.0.0.0/8 (loopback)
            if 2130706432 <= ip_int <= 2147483647:
                return True
            
            return False
        except (socket.error, struct.error, ValueError, TypeError):
            return False
    
    def add_blocked_country(self, country_code: str):
        """Add a country to the blocklist"""
        self.blocked_countries.add(country_code.upper())
    
    def remove_blocked_country(self, country_code: str):
        """Remove a country from the blocklist"""
        self.blocked_countries.discard(country_code.upper())
    
    def add_allowed_country(self, country_code: str):
        """Add a country to the allowlist"""
        self.allowed_countries.add(country_code.upper())
    
    def remove_allowed_country(self, country_code: str):
        """Remove a country from the allowlist"""
        self.allowed_countries.discard(country_code.upper())
    
    def get_stats(self) -> Dict:
        """Get geo-blocking statistics"""
        return {
            'database_loaded': self._loaded,
            'ip_ranges': len(self._ip_ranges),
            'cached_lookups': len(self._cache),
            'blocked_countries': list(self.blocked_countries),
            'allowed_countries': list(self.allowed_countries),
        }


def download_geo_db(output_path: str = None) -> bool:
    """
    Download free IP-to-country database
    Uses DB-IP Lite database (free for personal use)
    
    Args:
        output_path: Where to save the database
    
    Returns:
        True if successful
    """
    from datetime import datetime
    
    if output_path is None:
        output_path = os.path.join(
            os.path.dirname(__file__), '..', 'data', 'ip2country.csv'
        )
    
    # Create directory if needed
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # DB-IP Lite download URL (updated monthly)
    # This is a free database, requires attribution
    # Generate URL dynamically based on current year/month
    current_date = datetime.now()
    year_month = current_date.strftime("%Y-%m")
    url = f"https://download.db-ip.com/free/dbip-country-lite-{year_month}.csv.gz"
    
    print(f"[GeoBlocker] Downloading database from {url}")
    
    try:
        # Download
        temp_path = output_path + '.gz'
        urllib.request.urlretrieve(url, temp_path)
        
        # Decompress
        with gzip.open(temp_path, 'rb') as f_in:
            with open(output_path + '.raw', 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        
        # Convert to simpler format (IP int ranges)
        convert_dbip_to_simple(output_path + '.raw', output_path)
        
        # Cleanup
        os.remove(temp_path)
        os.remove(output_path + '.raw')
        
        print(f"[GeoBlocker] Database saved to {output_path}")
        return True
        
    except Exception as e:
        print(f"[GeoBlocker] Error downloading database: {e}")
        return False


def convert_dbip_to_simple(input_path: str, output_path: str):
    """Convert DB-IP CSV format to simple integer range format"""
    
    def ip_to_int(ip: str) -> int:
        try:
            return struct.unpack('!I', socket.inet_aton(ip))[0]
        except (socket.error, struct.error, OSError):
            return 0
    
    with open(input_path, 'r', encoding='utf-8') as f_in:
        with open(output_path, 'w', encoding='utf-8') as f_out:
            reader = csv.reader(f_in)
            writer = csv.writer(f_out)
            
            for row in reader:
                if len(row) >= 3:
                    start_ip = ip_to_int(row[0])
                    end_ip = ip_to_int(row[1])
                    country = row[2]
                    
                    if start_ip and end_ip:
                        writer.writerow([start_ip, end_ip, country])


def create_sample_db(output_path: str = None):
    """
    Create a sample database for testing
    Contains common IP ranges for major countries
    """
    if output_path is None:
        output_path = os.path.join(
            os.path.dirname(__file__), '..', 'data', 'ip2country.csv'
        )
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # Sample IP ranges (not comprehensive, for testing only)
    sample_ranges = [
        # US ranges
        (16777216, 16777471, 'US'),      # 1.0.0.0 - 1.0.0.255
        (1071071232, 1071071487, 'US'),  # 63.223.64.0 - 63.223.64.255
        
        # China ranges  
        (16785408, 16793599, 'CN'),      # 1.8.0.0 - 1.15.255.255
        (1881669632, 1881702399, 'CN'),  # 112.64.0.0 - 112.127.255.255
        
        # Russia ranges
        (83886080, 83951615, 'RU'),      # 5.0.0.0 - 5.0.255.255
        
        # Germany ranges
        (35684352, 35749887, 'DE'),      # 2.32.0.0 - 2.47.255.255
        
        # UK ranges
        (50331648, 50397183, 'GB'),      # 3.0.0.0 - 3.0.255.255
        
        # Japan ranges
        (203038720, 203235327, 'JP'),    # 12.22.128.0 - 12.25.127.255
        
        # Known bad ranges (example)
        (1, 255, 'XX'),  # Reserved range (testing)
    ]
    
    with open(output_path, 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        for row in sample_ranges:
            writer.writerow(row)
    
    print(f"[GeoBlocker] Sample database created at {output_path}")
    print("[GeoBlocker] Note: This is a sample DB for testing. Download full DB for production.")
