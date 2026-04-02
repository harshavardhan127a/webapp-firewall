"""
Storage Module for WAF
Supports multiple backends: Memory, SQLite, Redis
"""
import time
import sqlite3
import threading
import os
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional, Dict, List, Any

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False


class StorageBackend(ABC):
    """Abstract base class for storage backends"""
    
    @abstractmethod
    def add_blocked_ip(self, ip: str, reason: str, duration: int) -> None:
        """Add an IP to the blocked list"""
        pass
    
    @abstractmethod
    def is_blocked_ip(self, ip: str) -> bool:
        """Check if an IP is blocked"""
        pass
    
    @abstractmethod
    def remove_blocked_ip(self, ip: str) -> None:
        """Remove an IP from the blocked list"""
        pass
    
    @abstractmethod
    def get_blocked_ips(self) -> List[Dict[str, Any]]:
        """Get all blocked IPs"""
        pass
    
    @abstractmethod
    def increment_violation_count(self, ip: str) -> int:
        """Increment and return violation count for an IP"""
        pass
    
    @abstractmethod
    def get_violation_count(self, ip: str) -> int:
        """Get violation count for an IP"""
        pass
    
    @abstractmethod
    def add_rate_limit_entry(self, ip: str, timestamp: float) -> None:
        """Add a rate limit entry for an IP"""
        pass
    
    @abstractmethod
    def get_rate_limit_count(self, ip: str, window_start: float) -> int:
        """Get request count for an IP within the time window"""
        pass
    
    @abstractmethod
    def cleanup_expired(self) -> None:
        """Clean up expired entries"""
        pass
    
    @abstractmethod
    def add_permanent_block(self, ip: str, reason: str) -> None:
        """Add an IP to permanent block list"""
        pass
    
    @abstractmethod
    def is_permanently_blocked(self, ip: str) -> bool:
        """Check if IP is permanently blocked"""
        pass
    
    @abstractmethod
    def log_request(self, ip: str, method: str, path: str, blocked: bool, reason: str) -> None:
        """Log a request"""
        pass
    
    @abstractmethod
    def get_stats(self) -> Dict[str, Any]:
        """Get WAF statistics"""
        pass


class MemoryStorage(StorageBackend):
    """In-memory storage backend (not persistent)"""
    
    def __init__(self):
        self.blocked_ips: Dict[str, Dict] = {}
        self.permanent_blocks: Dict[str, Dict] = {}
        self.violation_counts: Dict[str, int] = {}
        self.rate_limits: Dict[str, List[float]] = {}
        self.request_logs: List[Dict] = []
        self.stats = {'total_requests': 0, 'blocked_requests': 0, 'allowed_requests': 0}
        self._lock = threading.Lock()
    
    def add_blocked_ip(self, ip: str, reason: str, duration: int) -> None:
        with self._lock:
            self.blocked_ips[ip] = {
                'blocked_at': time.time(),
                'expires_at': time.time() + duration,
                'reason': reason
            }
    
    def is_blocked_ip(self, ip: str) -> bool:
        with self._lock:
            if ip in self.blocked_ips:
                if time.time() < self.blocked_ips[ip]['expires_at']:
                    return True
                del self.blocked_ips[ip]
            return False
    
    def remove_blocked_ip(self, ip: str) -> None:
        with self._lock:
            self.blocked_ips.pop(ip, None)
    
    def get_blocked_ips(self) -> List[Dict[str, Any]]:
        with self._lock:
            current_time = time.time()
            return [
                {'ip': ip, **data} 
                for ip, data in self.blocked_ips.items() 
                if current_time < data['expires_at']
            ]
    
    def increment_violation_count(self, ip: str) -> int:
        with self._lock:
            self.violation_counts[ip] = self.violation_counts.get(ip, 0) + 1
            return self.violation_counts[ip]
    
    def get_violation_count(self, ip: str) -> int:
        with self._lock:
            return self.violation_counts.get(ip, 0)
    
    def add_rate_limit_entry(self, ip: str, timestamp: float) -> None:
        with self._lock:
            if ip not in self.rate_limits:
                self.rate_limits[ip] = []
            self.rate_limits[ip].append(timestamp)
    
    def get_rate_limit_count(self, ip: str, window_start: float) -> int:
        with self._lock:
            if ip not in self.rate_limits:
                return 0
            # Clean old entries and count
            self.rate_limits[ip] = [t for t in self.rate_limits[ip] if t >= window_start]
            return len(self.rate_limits[ip])
    
    def cleanup_expired(self) -> None:
        with self._lock:
            current_time = time.time()
            self.blocked_ips = {
                ip: data for ip, data in self.blocked_ips.items()
                if current_time < data['expires_at']
            }
            # Clean rate limit entries older than 5 minutes
            cutoff = current_time - 300
            for ip in list(self.rate_limits.keys()):
                self.rate_limits[ip] = [t for t in self.rate_limits[ip] if t >= cutoff]
                if not self.rate_limits[ip]:
                    del self.rate_limits[ip]
    
    def add_permanent_block(self, ip: str, reason: str) -> None:
        with self._lock:
            self.permanent_blocks[ip] = {
                'blocked_at': time.time(),
                'reason': reason
            }
    
    def is_permanently_blocked(self, ip: str) -> bool:
        with self._lock:
            return ip in self.permanent_blocks
    
    def log_request(self, ip: str, method: str, path: str, blocked: bool, reason: str) -> None:
        with self._lock:
            self.stats['total_requests'] += 1
            if blocked:
                self.stats['blocked_requests'] += 1
            else:
                self.stats['allowed_requests'] += 1
    
    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                **self.stats,
                'blocked_ips_count': len(self.blocked_ips),
                'permanent_blocks_count': len(self.permanent_blocks)
            }


class SQLiteStorage(StorageBackend):
    """SQLite storage backend (persistent)"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()
        self._lock = threading.Lock()
    
    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        return conn
    
    def _init_db(self) -> None:
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Blocked IPs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip TEXT PRIMARY KEY,
                blocked_at REAL,
                expires_at REAL,
                reason TEXT
            )
        ''')
        
        # Permanent blocks table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS permanent_blocks (
                ip TEXT PRIMARY KEY,
                blocked_at REAL,
                reason TEXT
            )
        ''')
        
        # Violation counts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS violation_counts (
                ip TEXT PRIMARY KEY,
                count INTEGER DEFAULT 0
            )
        ''')
        
        # Rate limits table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS rate_limits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                timestamp REAL
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_rate_limits_ip ON rate_limits(ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_rate_limits_timestamp ON rate_limits(timestamp)')
        
        # Request logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS request_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                ip TEXT,
                method TEXT,
                path TEXT,
                blocked INTEGER,
                reason TEXT
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON request_logs(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_ip ON request_logs(ip)')
        
        # Stats table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS stats (
                key TEXT PRIMARY KEY,
                value INTEGER DEFAULT 0
            )
        ''')
        cursor.execute('INSERT OR IGNORE INTO stats (key, value) VALUES ("total_requests", 0)')
        cursor.execute('INSERT OR IGNORE INTO stats (key, value) VALUES ("blocked_requests", 0)')
        cursor.execute('INSERT OR IGNORE INTO stats (key, value) VALUES ("allowed_requests", 0)')
        
        conn.commit()
        conn.close()
    
    def add_blocked_ip(self, ip: str, reason: str, duration: int) -> None:
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO blocked_ips (ip, blocked_at, expires_at, reason)
                VALUES (?, ?, ?, ?)
            ''', (ip, time.time(), time.time() + duration, reason))
            conn.commit()
            conn.close()
    
    def is_blocked_ip(self, ip: str) -> bool:
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(
                'SELECT 1 FROM blocked_ips WHERE ip = ? AND expires_at > ?',
                (ip, time.time())
            )
            result = cursor.fetchone() is not None
            conn.close()
            return result
    
    def remove_blocked_ip(self, ip: str) -> None:
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute('DELETE FROM blocked_ips WHERE ip = ?', (ip,))
            conn.commit()
            conn.close()
    
    def get_blocked_ips(self) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(
                'SELECT ip, blocked_at, expires_at, reason FROM blocked_ips WHERE expires_at > ?',
                (time.time(),)
            )
            results = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return results
    
    def increment_violation_count(self, ip: str) -> int:
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO violation_counts (ip, count) VALUES (?, 1)
                ON CONFLICT(ip) DO UPDATE SET count = count + 1
            ''', (ip,))
            cursor.execute('SELECT count FROM violation_counts WHERE ip = ?', (ip,))
            count = cursor.fetchone()[0]
            conn.commit()
            conn.close()
            return count
    
    def get_violation_count(self, ip: str) -> int:
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT count FROM violation_counts WHERE ip = ?', (ip,))
            row = cursor.fetchone()
            conn.close()
            return row[0] if row else 0
    
    def add_rate_limit_entry(self, ip: str, timestamp: float) -> None:
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute('INSERT INTO rate_limits (ip, timestamp) VALUES (?, ?)', (ip, timestamp))
            conn.commit()
            conn.close()
    
    def get_rate_limit_count(self, ip: str, window_start: float) -> int:
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(
                'SELECT COUNT(*) FROM rate_limits WHERE ip = ? AND timestamp >= ?',
                (ip, window_start)
            )
            count = cursor.fetchone()[0]
            conn.close()
            return count
    
    def cleanup_expired(self) -> None:
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            current_time = time.time()
            
            # Clean expired blocks
            cursor.execute('DELETE FROM blocked_ips WHERE expires_at <= ?', (current_time,))
            
            # Clean old rate limit entries (older than 5 minutes)
            cursor.execute('DELETE FROM rate_limits WHERE timestamp < ?', (current_time - 300,))
            
            # Clean old logs (older than 7 days)
            cursor.execute('DELETE FROM request_logs WHERE timestamp < ?', (current_time - 604800,))
            
            conn.commit()
            conn.close()
    
    def add_permanent_block(self, ip: str, reason: str) -> None:
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO permanent_blocks (ip, blocked_at, reason)
                VALUES (?, ?, ?)
            ''', (ip, time.time(), reason))
            conn.commit()
            conn.close()
    
    def is_permanently_blocked(self, ip: str) -> bool:
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT 1 FROM permanent_blocks WHERE ip = ?', (ip,))
            result = cursor.fetchone() is not None
            conn.close()
            return result
    
    def log_request(self, ip: str, method: str, path: str, blocked: bool, reason: str) -> None:
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO request_logs (timestamp, ip, method, path, blocked, reason)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (time.time(), ip, method, path, 1 if blocked else 0, reason))
            
            # Update stats
            cursor.execute('UPDATE stats SET value = value + 1 WHERE key = "total_requests"')
            if blocked:
                cursor.execute('UPDATE stats SET value = value + 1 WHERE key = "blocked_requests"')
            else:
                cursor.execute('UPDATE stats SET value = value + 1 WHERE key = "allowed_requests"')
            
            conn.commit()
            conn.close()
    
    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            stats = {}
            cursor.execute('SELECT key, value FROM stats')
            for row in cursor.fetchall():
                stats[row['key']] = row['value']
            
            cursor.execute('SELECT COUNT(*) FROM blocked_ips WHERE expires_at > ?', (time.time(),))
            stats['blocked_ips_count'] = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM permanent_blocks')
            stats['permanent_blocks_count'] = cursor.fetchone()[0]
            
            conn.close()
            return stats
    
    def get_recent_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent request logs"""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute('''
                SELECT timestamp, ip, method, path, blocked, reason 
                FROM request_logs 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            results = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return results


class RedisStorage(StorageBackend):
    """Redis storage backend (persistent, distributed)"""
    
    def __init__(self, host: str, port: int, db: int, password: Optional[str] = None):
        if not REDIS_AVAILABLE:
            raise ImportError("redis package is not installed. Install it with: pip install redis")
        
        self.redis = redis.Redis(
            host=host,
            port=port,
            db=db,
            password=password,
            decode_responses=True
        )
        self.prefix = "waf:"
    
    def add_blocked_ip(self, ip: str, reason: str, duration: int) -> None:
        key = f"{self.prefix}blocked:{ip}"
        self.redis.hset(key, mapping={
            'blocked_at': time.time(),
            'expires_at': time.time() + duration,
            'reason': reason
        })
        self.redis.expire(key, duration)
    
    def is_blocked_ip(self, ip: str) -> bool:
        return self.redis.exists(f"{self.prefix}blocked:{ip}") > 0
    
    def remove_blocked_ip(self, ip: str) -> None:
        self.redis.delete(f"{self.prefix}blocked:{ip}")
    
    def get_blocked_ips(self) -> List[Dict[str, Any]]:
        keys = self.redis.keys(f"{self.prefix}blocked:*")
        results = []
        for key in keys:
            data = self.redis.hgetall(key)
            if data:
                ip = key.replace(f"{self.prefix}blocked:", "")
                results.append({
                    'ip': ip,
                    'blocked_at': float(data.get('blocked_at', 0)),
                    'expires_at': float(data.get('expires_at', 0)),
                    'reason': data.get('reason', '')
                })
        return results
    
    def increment_violation_count(self, ip: str) -> int:
        return self.redis.incr(f"{self.prefix}violations:{ip}")
    
    def get_violation_count(self, ip: str) -> int:
        count = self.redis.get(f"{self.prefix}violations:{ip}")
        return int(count) if count else 0
    
    def add_rate_limit_entry(self, ip: str, timestamp: float) -> None:
        key = f"{self.prefix}ratelimit:{ip}"
        self.redis.zadd(key, {str(timestamp): timestamp})
        self.redis.expire(key, 300)  # 5 minute TTL
    
    def get_rate_limit_count(self, ip: str, window_start: float) -> int:
        key = f"{self.prefix}ratelimit:{ip}"
        # Remove old entries
        self.redis.zremrangebyscore(key, '-inf', window_start)
        return self.redis.zcard(key)
    
    def cleanup_expired(self) -> None:
        # Redis handles expiration automatically with TTL
        pass
    
    def add_permanent_block(self, ip: str, reason: str) -> None:
        self.redis.hset(f"{self.prefix}permblock:{ip}", mapping={
            'blocked_at': time.time(),
            'reason': reason
        })
    
    def is_permanently_blocked(self, ip: str) -> bool:
        return self.redis.exists(f"{self.prefix}permblock:{ip}") > 0
    
    def log_request(self, ip: str, method: str, path: str, blocked: bool, reason: str) -> None:
        self.redis.incr(f"{self.prefix}stats:total_requests")
        if blocked:
            self.redis.incr(f"{self.prefix}stats:blocked_requests")
        else:
            self.redis.incr(f"{self.prefix}stats:allowed_requests")
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            'total_requests': int(self.redis.get(f"{self.prefix}stats:total_requests") or 0),
            'blocked_requests': int(self.redis.get(f"{self.prefix}stats:blocked_requests") or 0),
            'allowed_requests': int(self.redis.get(f"{self.prefix}stats:allowed_requests") or 0),
            'blocked_ips_count': len(self.redis.keys(f"{self.prefix}blocked:*")),
            'permanent_blocks_count': len(self.redis.keys(f"{self.prefix}permblock:*"))
        }


def get_storage_backend(backend_type: str, **kwargs) -> StorageBackend:
    """Factory function to get the appropriate storage backend"""
    if backend_type == 'memory':
        return MemoryStorage()
    elif backend_type == 'sqlite':
        return SQLiteStorage(kwargs.get('db_path', 'waf.db'))
    elif backend_type == 'redis':
        return RedisStorage(
            host=kwargs.get('host', 'localhost'),
            port=kwargs.get('port', 6379),
            db=kwargs.get('db', 0),
            password=kwargs.get('password')
        )
    else:
        raise ValueError(f"Unknown storage backend: {backend_type}")
