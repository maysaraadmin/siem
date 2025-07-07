import sqlite3
import threading
import time
from typing import Optional, Any, List, Dict, Tuple, Union
from queue import Queue

class Database:
    def __init__(self, db_name: str = 'siem.db'):
        self.db_name = db_name
        self._conn: Optional[sqlite3.Connection] = None
        self._lock = threading.RLock()
        self._connect()
        
    def _connect(self):
        """Establish database connection"""
        self._conn = sqlite3.connect(
            self.db_name,
            check_same_thread=False,  # Allow multiple threads to access the connection
            isolation_level='IMMEDIATE'  # Better concurrency control
        )
        self._conn.row_factory = sqlite3.Row  # Access columns by name
        self._create_tables()
        
    def _get_connection(self) -> sqlite3.Connection:
        """Get thread-local database connection"""
        if not self._conn:
            self._connect()
        return self._conn
        
    def _create_tables(self):
        """Create necessary tables if they don't exist"""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Enable WAL mode for better concurrency
            cursor.execute('PRAGMA journal_mode=WAL')
            cursor.execute('PRAGMA synchronous=NORMAL')
            
            # Events table with indexes for common queries
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    source TEXT,
                    event_type TEXT,
                    severity INTEGER,
                    description TEXT,
                    ip_address TEXT,
                    status TEXT,
                    raw_data TEXT
                )
            ''')
            
            # Create indexes for performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_source ON events(source)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)')
            
            # Rules table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE,
                    condition TEXT,
                    action TEXT,
                    severity INTEGER,
                    enabled INTEGER DEFAULT 1,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            self._insert_sample_rules()
        
    def _insert_sample_rules(self):
        """Insert sample rules if the table is empty"""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM rules")
            if cursor.fetchone()[0] == 0:
                sample_rules = [
                    ("Failed Login Attempts", "event_type == 'Failed Login' AND COUNT() > 5", "alert", 3, 1),
                    ("Port Scan Detected", "event_type == 'Port Scan'", "block", 4, 1),
                    ("SQL Injection Attempt", "description LIKE '%SQL injection%'", "alert", 5, 1),
                    ("Brute Force Attack", "event_type == 'Failed Login' AND COUNT() > 10", "block", 5, 1),
                    ("Unauthorized Access", "event_type == 'Unauthorized Access'", "alert", 4, 1)
                ]
                
                # Use INSERT OR IGNORE to avoid duplicates if the table was just created
                cursor.executemany(
                    """
                    INSERT OR IGNORE INTO rules 
                    (name, condition, action, severity, enabled)
                    VALUES (?, ?, ?, ?, ?)
                    """, 
                    sample_rules
                )
                conn.commit()
            
    def close(self):
        """Close database connection"""
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None
    
    def execute_query(self, query: str, params: tuple = ()) -> List[sqlite3.Row]:
        """
        Execute a SQL query and return results.
        Thread-safe and handles connection errors by retrying.
        """
        max_retries = 3
        retry_delay = 0.1  # seconds
        
        for attempt in range(max_retries):
            try:
                with self._lock:
                    conn = self._get_connection()
                    cursor = conn.cursor()
                    cursor.execute(query, params)
                    return cursor.fetchall()
            except sqlite3.OperationalError as e:
                if "database is locked" in str(e) and attempt < max_retries - 1:
                    time.sleep(retry_delay * (attempt + 1))
                    continue
                raise
        return []
    
    def execute_update(self, query: str, params: tuple = ()) -> int:
        """
        Execute an update query and commit changes.
        Returns the number of rows affected.
        """
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()
            return cursor.rowcount
    
    def execute_many(self, query: str, params_list: List[tuple]) -> int:
        """
        Execute multiple parameterized queries in a transaction.
        Returns the number of rows affected.
        """
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.executemany(query, params_list)
            conn.commit()
            return cursor.rowcount
    
    def begin_transaction(self):
        """Begin a transaction explicitly"""
        self._get_connection().execute('BEGIN TRANSACTION')
    
    def commit_transaction(self):
        """Commit the current transaction"""
        self._get_connection().commit()
    
    def rollback_transaction(self):
        """Roll back the current transaction"""
        self._get_connection().rollback()
    
    def __del__(self):
        """Ensure connection is closed when the object is destroyed"""
        self.close()