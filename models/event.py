from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple, Optional
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
    
    def get_events_over_time(self, time_delta: timedelta) -> List[Tuple[str, int]]:
        """Get event counts grouped by time intervals"""
        if time_delta <= timedelta(hours=24):
            # Hourly grouping for 24 hours
            query = """
                SELECT strftime('%Y-%m-%d %H:00', timestamp) as time_interval, 
                       COUNT(*) as count 
                FROM events 
                WHERE timestamp >= datetime('now', ?) 
                GROUP BY time_interval 
                ORDER BY time_interval
            """
            param = f"-{int(time_delta.total_seconds()/3600)} hours"
        elif time_delta <= timedelta(days=7):
            # Daily grouping for 7 days
            query = """
                SELECT strftime('%Y-%m-%d', timestamp) as time_interval, 
                       COUNT(*) as count 
                FROM events 
                WHERE timestamp >= datetime('now', ?) 
                GROUP BY time_interval 
                ORDER BY time_interval
            """
            param = f"-{time_delta.days} days"
        else:
            # Weekly grouping for longer ranges
            query = """
                SELECT strftime('%Y-%m-%d', date(timestamp, 'weekday 0', '-6 days')) as time_interval, 
                       COUNT(*) as count 
                FROM events 
                WHERE timestamp >= datetime('now', ?) 
                GROUP BY time_interval 
                ORDER BY time_interval
            """
            param = f"-{time_delta.days} days"
        
        return self.db.execute_query(query, (param,))
    
    def get_event_sources(self, time_delta: timedelta) -> List[Tuple[str, int]]:
        """Get event counts by source"""
        query = """
            SELECT source, COUNT(*) as count 
            FROM events 
            WHERE timestamp >= datetime('now', ?) 
            GROUP BY source 
            ORDER BY count DESC
        """
        param = f"-{int(time_delta.total_seconds()/3600)} hours" if time_delta <= timedelta(hours=24) else f"-{time_delta.days} days"
        return self.db.execute_query(query, (param,))
    
    def get_severity_trends(self, time_delta: timedelta) -> List[Tuple[str, int, int]]:
        """Get severity counts over time"""
        if time_delta <= timedelta(hours=24):
            # Hourly grouping
            query = """
                SELECT strftime('%Y-%m-%d %H:00', timestamp) as time_interval,
                       severity,
                       COUNT(*) as count
                FROM events
                WHERE timestamp >= datetime('now', ?)
                GROUP BY time_interval, severity
                ORDER BY time_interval, severity
            """
            param = f"-{int(time_delta.total_seconds()/3600)} hours"
        else:
            # Daily grouping
            query = """
                SELECT strftime('%Y-%m-%d', timestamp) as time_interval,
                       severity,
                       COUNT(*) as count
                FROM events
                WHERE timestamp >= datetime('now', ?)
                GROUP BY time_interval, severity
                ORDER BY time_interval, severity
            """
            param = f"-{time_delta.days} days"
        
        return self.db.execute_query(query, (param,))

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
    
    def get_events_with_query(self, query: str, params: tuple = ()) -> List[tuple]:
        """Execute a custom query to get events"""
        return self.db.execute_query(query, params)
    
    def get_event_by_id(self, event_id: int) -> Optional[Dict]:
        """Get a single event by its ID"""
        query = """
            SELECT id, timestamp, source, event_type, severity, 
                   description, ip_address, status 
            FROM events 
            WHERE id = ?
        """
        result = self.db.execute_query(query, (event_id,))
        if result:
            return {
                'id': result[0][0],
                'timestamp': result[0][1],
                'source': result[0][2],
                'event_type': result[0][3],
                'severity': result[0][4],
                'description': result[0][5],
                'ip_address': result[0][6],
                'status': result[0][7]
            }
        return None
    
    def update_event_status(self, event_id: int, new_status: str) -> bool:
        """Update an event's status"""
        query = "UPDATE events SET status = ? WHERE id = ?"
        self.db.execute_update(query, (new_status, event_id))
        return True