import sqlite3
from typing import Optional

class Database:
    def __init__(self, db_name: str = 'siem.db'):
        self.db_name = db_name
        self.conn: Optional[sqlite3.Connection] = None
        self.cursor: Optional[sqlite3.Cursor] = None
        
    def connect(self):
        """Establish database connection"""
        self.conn = sqlite3.connect(self.db_name)
        self.cursor = self.conn.cursor()
        self._create_tables()
        
    def _create_tables(self):
        """Create necessary tables if they don't exist"""
        # Events table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                source TEXT,
                event_type TEXT,
                severity INTEGER,
                description TEXT,
                ip_address TEXT,
                status TEXT
            )
        ''')
        
        # Rules table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                condition TEXT,
                action TEXT,
                severity INTEGER,
                enabled INTEGER
            )
        ''')
        
        self.conn.commit()
        self._insert_sample_rules()
        
    def _insert_sample_rules(self):
        """Insert sample rules if the table is empty"""
        self.cursor.execute("SELECT COUNT(*) FROM rules")
        if self.cursor.fetchone()[0] == 0:
            sample_rules = [
                ("Failed Login Attempts", "event_type == 'Failed Login' AND COUNT() > 5", "alert", 3, 1),
                ("Port Scan Detected", "event_type == 'Port Scan'", "block", 4, 1),
                ("SQL Injection Attempt", "description LIKE '%SQL injection%'", "alert", 5, 1),
                ("Brute Force Attack", "event_type == 'Failed Login' AND COUNT() > 10", "block", 5, 1),
                ("Unauthorized Access", "event_type == 'Unauthorized Access'", "alert", 4, 1)
            ]
            self.cursor.executemany(
                "INSERT INTO rules (name, condition, action, severity, enabled) VALUES (?, ?, ?, ?, ?)", 
                sample_rules
            )
            self.conn.commit()
            
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            
    def execute_query(self, query: str, params: tuple = ()):
        """Execute a SQL query and return results"""
        self.cursor.execute(query, params)
        return self.cursor.fetchall()
    
    def execute_update(self, query: str, params: tuple = ()):
        """Execute an update query and commit changes"""
        self.cursor.execute(query, params)
        self.conn.commit()