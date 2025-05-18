import random
import time
import threading
from datetime import datetime
from typing import Optional
from .event import EventModel

class LogCollector:
    def __init__(self, event_model: EventModel):
        self.event_model = event_model
        self.running = False
        self.thread: Optional[threading.Thread] = None
        
    def start(self):
        """Start the log collection thread"""
        if self.running:
            return
            
        self.running = True
        self.thread = threading.Thread(target=self._collect_logs, daemon=True)
        self.thread.start()
        
    def stop(self):
        """Stop the log collection thread"""
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1)
            
    def _collect_logs(self):
        """Simulate log collection from various sources"""
        sources = ['System', 'Firewall', 'IDS', 'Application']
        event_types = [
            'Login', 'Failed Login', 'Logout', 'File Access', 
            'Configuration Change', 'Port Scan', 'Unauthorized Access',
            'Malware Detected', 'Brute Force Attempt', 'SQL Injection'
        ]
        
        while self.running:
            # Simulate receiving logs
            num_events = random.randint(1, 5)
            
            for _ in range(num_events):
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                source = random.choice(sources)
                event_type = random.choice(event_types)
                
                # Determine severity based on event type
                if event_type in ['Failed Login', 'File Access']:
                    severity = random.randint(1, 2)
                elif event_type in ['Port Scan', 'Configuration Change']:
                    severity = random.randint(2, 3)
                elif event_type in ['Unauthorized Access', 'Brute Force Attempt']:
                    severity = random.randint(3, 4)
                elif event_type in ['Malware Detected', 'SQL Injection']:
                    severity = 5
                else:
                    severity = 1
                
                description = f"{event_type} event from {source}"
                ip_address = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
                
                # Create the event
                self.event_model.create_event(
                    timestamp=timestamp,
                    source=source,
                    event_type=event_type,
                    severity=severity,
                    description=description,
                    ip_address=ip_address
                )
            
            # Sleep for a random interval (1-5 seconds)
            time.sleep(random.uniform(1, 5))