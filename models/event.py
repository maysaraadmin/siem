from datetime import datetime
from typing import List, Dict, Any
from .database import Database

class EventModel:
    def __init__(self, db: Database):
        self.db = db
        
    def create_event(
        self,
        timestamp: datetime,
        source: str,
        event_type: str,
        severity: int,
        description: str,
        ip_address: str = "N/A",
        status: str = "New"
    ) -> int:
        """Create a new event in the database"""
        query = """
            INSERT INTO events (timestamp, source, event_type, severity, description, ip_address, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        params = (timestamp, source, event_type, severity, description, ip_address, status)
        self.db.execute_update(query, params)
        return self.db.cursor.lastrowid
    
    def get_events(
        self,
        source_filter: str = None,
        severity_filter: int = None,
        time_range: str = None,
        limit: int = 1000
    ) -> List[Dict[str, Any]]:
        """Retrieve events with optional filters"""
        query = "SELECT * FROM events"
        conditions = []
        params = []
        
        if source_filter and source_filter != 'All':
            conditions.append("source = ?")
            params.append(source_filter)
            
        if severity_filter and severity_filter != 'All':
            conditions.append("severity >= ?")
            params.append(int(severity_filter.split(' ')[0]))
            
        if time_range and time_range != 'All':
            if time_range == 'Last 24 hours':
                conditions.append("timestamp >= datetime('now', '-1 day')")
            elif time_range == 'Last 7 days':
                conditions.append("timestamp >= datetime('now', '-7 days')")
            elif time_range == 'Last 30 days':
                conditions.append("timestamp >= datetime('now', '-30 days')")
        
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
            
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        results = self.db.execute_query(query, tuple(params))
        
        events = []
        for row in results:
            events.append({
                'id': row[0],
                'timestamp': row[1],
                'source': row[2],
                'event_type': row[3],
                'severity': row[4],
                'description': row[5],
                'ip_address': row[6],
                'status': row[7]
            })
            
        return events
    
    def get_event_stats(self) -> Dict[str, int]:
        """Get statistics about events"""
        stats = {}
        
        # Total events
        result = self.db.execute_query("SELECT COUNT(*) FROM events")
        stats['total'] = result[0][0]
        
        # Critical events
        result = self.db.execute_query("SELECT COUNT(*) FROM events WHERE severity >= 4")
        stats['critical'] = result[0][0]
        
        # Warning events
        result = self.db.execute_query("SELECT COUNT(*) FROM events WHERE severity = 3")
        stats['warning'] = result[0][0]
        
        # Normal events
        result = self.db.execute_query("SELECT COUNT(*) FROM events WHERE severity <= 2")
        stats['normal'] = result[0][0]
        
        return stats
    
    def mark_event_resolved(self, event_id: int) -> bool:
        """Mark an event as resolved"""
        query = "UPDATE events SET status = 'Resolved' WHERE id = ?"
        self.db.execute_update(query, (event_id,))
        return True