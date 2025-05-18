import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import sqlite3
import datetime
import random
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import pandas as pd
import socket
import threading
import json
from collections import defaultdict

class SIEMSystem:
    def __init__(self, root):
        self.root = root
        self.root.title("Python SIEM System")
        self.root.geometry("1200x800")
        
        # Initialize database
        self.init_db()
        
        # Create GUI components
        self.create_widgets()
        
        # Start log collection thread
        self.running = True
        self.collection_thread = threading.Thread(target=self.collect_logs)
        self.collection_thread.daemon = True
        self.collection_thread.start()
        
        # Load initial data
        self.update_event_table()
        self.update_dashboard()
        
    def init_db(self):
        self.conn = sqlite3.connect('siem.db')
        self.cursor = self.conn.cursor()
        
        # Create tables if they don't exist
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
        
        # Insert sample rules if empty
        self.cursor.execute("SELECT COUNT(*) FROM rules")
        if self.cursor.fetchone()[0] == 0:
            sample_rules = [
                ("Failed Login Attempts", "event_type == 'Failed Login' AND COUNT() > 5", "alert", 3, 1),
                ("Port Scan Detected", "event_type == 'Port Scan'", "block", 4, 1),
                ("SQL Injection Attempt", "description LIKE '%SQL injection%'", "alert", 5, 1),
                ("Brute Force Attack", "event_type == 'Failed Login' AND COUNT() > 10", "block", 5, 1),
                ("Unauthorized Access", "event_type == 'Unauthorized Access'", "alert", 4, 1)
            ]
            self.cursor.executemany("INSERT INTO rules (name, condition, action, severity, enabled) VALUES (?, ?, ?, ?, ?)", sample_rules)
            self.conn.commit()
    
    def create_widgets(self):
        # Create main notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Dashboard Tab
        self.dashboard_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_tab, text="Dashboard")
        self.create_dashboard()
        
        # Events Tab
        self.events_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.events_tab, text="Events")
        self.create_events_tab()
        
        # Rules Tab
        self.rules_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.rules_tab, text="Rules")
        self.create_rules_tab()
        
        # Analytics Tab
        self.analytics_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.analytics_tab, text="Analytics")
        self.create_analytics_tab()
        
        # Settings Tab
        self.settings_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_tab, text="Settings")
        self.create_settings_tab()
    
    def create_dashboard(self):
        # Dashboard frame
        dashboard_frame = ttk.Frame(self.dashboard_tab)
        dashboard_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Stats frame
        stats_frame = ttk.Frame(dashboard_frame)
        stats_frame.pack(fill=tk.X, pady=5)
        
        # Stats labels
        self.total_events_label = ttk.Label(stats_frame, text="Total Events: 0", font=('Arial', 10))
        self.total_events_label.pack(side=tk.LEFT, padx=10)
        
        self.critical_events_label = ttk.Label(stats_frame, text="Critical: 0", font=('Arial', 10), foreground='red')
        self.critical_events_label.pack(side=tk.LEFT, padx=10)
        
        self.warning_events_label = ttk.Label(stats_frame, text="Warnings: 0", font=('Arial', 10), foreground='orange')
        self.warning_events_label.pack(side=tk.LEFT, padx=10)
        
        self.normal_events_label = ttk.Label(stats_frame, text="Normal: 0", font=('Arial', 10), foreground='green')
        self.normal_events_label.pack(side=tk.LEFT, padx=10)
        
        # Charts frame
        charts_frame = ttk.Frame(dashboard_frame)
        charts_frame.pack(fill=tk.BOTH, expand=True)
        
        # Event types chart
        event_types_frame = ttk.Frame(charts_frame)
        event_types_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        ttk.Label(event_types_frame, text="Event Types", font=('Arial', 10)).pack()
        
        self.event_types_fig = plt.Figure(figsize=(5, 4), dpi=100)
        self.event_types_ax = self.event_types_fig.add_subplot(111)
        self.event_types_canvas = FigureCanvasTkAgg(self.event_types_fig, master=event_types_frame)
        self.event_types_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Severity chart
        severity_frame = ttk.Frame(charts_frame)
        severity_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        ttk.Label(severity_frame, text="Severity Levels", font=('Arial', 10)).pack()
        
        self.severity_fig = plt.Figure(figsize=(5, 4), dpi=100)
        self.severity_ax = self.severity_fig.add_subplot(111)
        self.severity_canvas = FigureCanvasTkAgg(self.severity_fig, master=severity_frame)
        self.severity_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Recent alerts frame
        alerts_frame = ttk.Frame(dashboard_frame)
        alerts_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        ttk.Label(alerts_frame, text="Recent Alerts", font=('Arial', 10)).pack()
        
        self.alerts_tree = ttk.Treeview(alerts_frame, columns=('timestamp', 'source', 'description'), show='headings')
        self.alerts_tree.heading('timestamp', text='Timestamp')
        self.alerts_tree.heading('source', text='Source')
        self.alerts_tree.heading('description', text='Description')
        self.alerts_tree.column('timestamp', width=150)
        self.alerts_tree.column('source', width=100)
        self.alerts_tree.column('description', width=400)
        
        scrollbar = ttk.Scrollbar(alerts_frame, orient=tk.VERTICAL, command=self.alerts_tree.yview)
        self.alerts_tree.configure(yscrollcommand=scrollbar.set)
        
        self.alerts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_events_tab(self):
        # Events frame
        events_frame = ttk.Frame(self.events_tab)
        events_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Filter frame
        filter_frame = ttk.Frame(events_frame)
        filter_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(filter_frame, text="Source:").pack(side=tk.LEFT, padx=5)
        self.source_filter = ttk.Combobox(filter_frame, values=['All', 'System', 'Firewall', 'IDS', 'Application'])
        self.source_filter.set('All')
        self.source_filter.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(filter_frame, text="Severity:").pack(side=tk.LEFT, padx=5)
        self.severity_filter = ttk.Combobox(filter_frame, values=['All', '1 - Low', '2 - Medium', '3 - High', '4 - Critical', '5 - Emergency'])
        self.severity_filter.set('All')
        self.severity_filter.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(filter_frame, text="Time Range:").pack(side=tk.LEFT, padx=5)
        self.time_filter = ttk.Combobox(filter_frame, values=['Last 24 hours', 'Last 7 days', 'Last 30 days', 'All'])
        self.time_filter.set('Last 24 hours')
        self.time_filter.pack(side=tk.LEFT, padx=5)
        
        filter_button = ttk.Button(filter_frame, text="Apply Filters", command=self.update_event_table)
        filter_button.pack(side=tk.LEFT, padx=10)
        
        # Events treeview
        self.events_tree = ttk.Treeview(events_frame, columns=('timestamp', 'source', 'event_type', 'severity', 'description', 'ip', 'status'), show='headings')
        self.events_tree.heading('timestamp', text='Timestamp')
        self.events_tree.heading('source', text='Source')
        self.events_tree.heading('event_type', text='Event Type')
        self.events_tree.heading('severity', text='Severity')
        self.events_tree.heading('description', text='Description')
        self.events_tree.heading('ip', text='IP Address')
        self.events_tree.heading('status', text='Status')
        
        self.events_tree.column('timestamp', width=150)
        self.events_tree.column('source', width=100)
        self.events_tree.column('event_type', width=120)
        self.events_tree.column('severity', width=80)
        self.events_tree.column('description', width=300)
        self.events_tree.column('ip', width=120)
        self.events_tree.column('status', width=100)
        
        scrollbar = ttk.Scrollbar(events_frame, orient=tk.VERTICAL, command=self.events_tree.yview)
        self.events_tree.configure(yscrollcommand=scrollbar.set)
        
        self.events_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Context menu
        self.event_context_menu = tk.Menu(self.root, tearoff=0)
        self.event_context_menu.add_command(label="View Details", command=self.view_event_details)
        self.event_context_menu.add_command(label="Mark as Resolved", command=self.mark_event_resolved)
        self.event_context_menu.add_command(label="Add to Watchlist", command=self.add_to_watchlist)
        
        self.events_tree.bind("<Button-3>", self.show_event_context_menu)
    
    def create_rules_tab(self):
        # Rules frame
        rules_frame = ttk.Frame(self.rules_tab)
        rules_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Rules treeview
        self.rules_tree = ttk.Treeview(rules_frame, columns=('name', 'condition', 'action', 'severity', 'enabled'), show='headings')
        self.rules_tree.heading('name', text='Rule Name')
        self.rules_tree.heading('condition', text='Condition')
        self.rules_tree.heading('action', text='Action')
        self.rules_tree.heading('severity', text='Severity')
        self.rules_tree.heading('enabled', text='Enabled')
        
        self.rules_tree.column('name', width=200)
        self.rules_tree.column('condition', width=300)
        self.rules_tree.column('action', width=100)
        self.rules_tree.column('severity', width=80)
        self.rules_tree.column('enabled', width=80)
        
        scrollbar = ttk.Scrollbar(rules_frame, orient=tk.VERTICAL, command=self.rules_tree.yview)
        self.rules_tree.configure(yscrollcommand=scrollbar.set)
        
        self.rules_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Buttons frame
        buttons_frame = ttk.Frame(rules_frame)
        buttons_frame.pack(fill=tk.X, pady=5)
        
        add_button = ttk.Button(buttons_frame, text="Add Rule", command=self.add_rule)
        add_button.pack(side=tk.LEFT, padx=5)
        
        edit_button = ttk.Button(buttons_frame, text="Edit Rule", command=self.edit_rule)
        edit_button.pack(side=tk.LEFT, padx=5)
        
        delete_button = ttk.Button(buttons_frame, text="Delete Rule", command=self.delete_rule)
        delete_button.pack(side=tk.LEFT, padx=5)
        
        toggle_button = ttk.Button(buttons_frame, text="Toggle Enable", command=self.toggle_rule)
        toggle_button.pack(side=tk.LEFT, padx=5)
        
        # Load rules
        self.update_rules_table()
    
    def create_analytics_tab(self):
        # Analytics frame
        analytics_frame = ttk.Frame(self.analytics_tab)
        analytics_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Time series chart
        time_frame = ttk.Frame(analytics_frame)
        time_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(time_frame, text="Events Over Time", font=('Arial', 10)).pack()
        
        self.time_fig = plt.Figure(figsize=(10, 4), dpi=100)
        self.time_ax = self.time_fig.add_subplot(111)
        self.time_canvas = FigureCanvasTkAgg(self.time_fig, master=time_frame)
        self.time_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Top sources frame
        sources_frame = ttk.Frame(analytics_frame)
        sources_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(sources_frame, text="Top Event Sources", font=('Arial', 10)).pack()
        
        self.sources_fig = plt.Figure(figsize=(10, 4), dpi=100)
        self.sources_ax = self.sources_fig.add_subplot(111)
        self.sources_canvas = FigureCanvasTkAgg(self.sources_fig, master=sources_frame)
        self.sources_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def create_settings_tab(self):
        # Settings frame
        settings_frame = ttk.Frame(self.settings_tab)
        settings_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Log sources frame
        log_frame = ttk.LabelFrame(settings_frame, text="Log Sources")
        log_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(log_frame, text="Syslog Server:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.syslog_ip = ttk.Entry(log_frame)
        self.syslog_ip.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        self.syslog_ip.insert(0, "0.0.0.0")
        
        ttk.Label(log_frame, text="Port:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.syslog_port = ttk.Entry(log_frame)
        self.syslog_port.grid(row=0, column=3, padx=5, pady=5, sticky=tk.EW)
        self.syslog_port.insert(0, "514")
        
        ttk.Label(log_frame, text="Log File Path:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.log_path = ttk.Entry(log_frame)
        self.log_path.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        
        browse_button = ttk.Button(log_frame, text="Browse", command=self.browse_log_file)
        browse_button.grid(row=1, column=2, columnspan=2, padx=5, pady=5)
        
        # Alert settings frame
        alert_frame = ttk.LabelFrame(settings_frame, text="Alert Settings")
        alert_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(alert_frame, text="Email Alerts:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.email_alerts = ttk.Checkbutton(alert_frame)
        self.email_alerts.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(alert_frame, text="Email Address:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.email_address = ttk.Entry(alert_frame)
        self.email_address.grid(row=0, column=3, padx=5, pady=5, sticky=tk.EW)
        
        ttk.Label(alert_frame, text="Alert Threshold:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.alert_threshold = ttk.Combobox(alert_frame, values=['Low (1)', 'Medium (2)', 'High (3)', 'Critical (4)', 'Emergency (5)'])
        self.alert_threshold.set('High (3)')
        self.alert_threshold.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Save button
        save_button = ttk.Button(settings_frame, text="Save Settings", command=self.save_settings)
        save_button.pack(pady=10)
    
    def browse_log_file(self):
        filepath = filedialog.askopenfilename()
        if filepath:
            self.log_path.delete(0, tk.END)
            self.log_path.insert(0, filepath)
    
    def save_settings(self):
        messagebox.showinfo("Settings", "Settings saved successfully")
    
    def update_event_table(self):
        # Clear existing data
        for item in self.events_tree.get_children():
            self.events_tree.delete(item)
        
        # Build query based on filters
        query = "SELECT timestamp, source, event_type, severity, description, ip_address, status FROM events"
        conditions = []
        
        # Source filter
        source = self.source_filter.get()
        if source != 'All':
            conditions.append(f"source = '{source}'")
        
        # Severity filter
        severity = self.severity_filter.get()
        if severity != 'All':
            sev_level = severity.split(' ')[0]
            conditions.append(f"severity >= {sev_level}")
        
        # Time filter
        time_range = self.time_filter.get()
        if time_range != 'All':
            if time_range == 'Last 24 hours':
                conditions.append("timestamp >= datetime('now', '-1 day')")
            elif time_range == 'Last 7 days':
                conditions.append("timestamp >= datetime('now', '-7 days')")
            elif time_range == 'Last 30 days':
                conditions.append("timestamp >= datetime('now', '-30 days')")
        
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        
        query += " ORDER BY timestamp DESC LIMIT 1000"
        
        # Execute query
        self.cursor.execute(query)
        events = self.cursor.fetchall()
        
        # Add events to treeview
        for event in events:
            severity = event[3]
            tags = ()
            if severity >= 4:
                tags = ('critical',)
            elif severity >= 3:
                tags = ('warning',)
            
            self.events_tree.insert('', tk.END, values=event, tags=tags)
        
        # Configure tag colors
        self.events_tree.tag_configure('critical', foreground='red')
        self.events_tree.tag_configure('warning', foreground='orange')
    
    def update_rules_table(self):
        # Clear existing data
        for item in self.rules_tree.get_children():
            self.rules_tree.delete(item)
        
        # Get rules from database
        self.cursor.execute("SELECT name, condition, action, severity, enabled FROM rules")
        rules = self.cursor.fetchall()
        
        # Add rules to treeview
        for rule in rules:
            enabled = "Yes" if rule[4] else "No"
            self.rules_tree.insert('', tk.END, values=(rule[0], rule[1], rule[2], rule[3], enabled))
    
    def update_dashboard(self):
        # Update stats
        self.cursor.execute("SELECT COUNT(*) FROM events")
        total_events = self.cursor.fetchone()[0]
        self.total_events_label.config(text=f"Total Events: {total_events}")
        
        self.cursor.execute("SELECT COUNT(*) FROM events WHERE severity >= 4")
        critical_events = self.cursor.fetchone()[0]
        self.critical_events_label.config(text=f"Critical: {critical_events}")
        
        self.cursor.execute("SELECT COUNT(*) FROM events WHERE severity = 3")
        warning_events = self.cursor.fetchone()[0]
        self.warning_events_label.config(text=f"Warnings: {warning_events}")
        
        self.cursor.execute("SELECT COUNT(*) FROM events WHERE severity <= 2")
        normal_events = self.cursor.fetchone()[0]
        self.normal_events_label.config(text=f"Normal: {normal_events}")
        
        # Update event types chart
        self.cursor.execute("SELECT event_type, COUNT(*) FROM events GROUP BY event_type ORDER BY COUNT(*) DESC LIMIT 10")
        event_types = self.cursor.fetchall()
        
        self.event_types_ax.clear()
        if event_types:
            df = pd.DataFrame(event_types, columns=['Event Type', 'Count'])
            df.plot(kind='bar', x='Event Type', y='Count', ax=self.event_types_ax, legend=False)
            self.event_types_ax.set_title('Top Event Types')
            self.event_types_ax.set_ylabel('Count')
            self.event_types_fig.tight_layout()
        
        self.event_types_canvas.draw()
        
        # Update severity chart
        self.cursor.execute("SELECT severity, COUNT(*) FROM events GROUP BY severity")
        severity_counts = self.cursor.fetchall()
        
        self.severity_ax.clear()
        if severity_counts:
            df = pd.DataFrame(severity_counts, columns=['Severity', 'Count'])
            df.plot(kind='pie', y='Count', labels=df['Severity'], ax=self.severity_ax, legend=False)
            self.severity_ax.set_title('Event Severity Distribution')
            self.severity_fig.tight_layout()
        
        self.severity_canvas.draw()
        
        # Update recent alerts
        for item in self.alerts_tree.get_children():
            self.alerts_tree.delete(item)
        
        self.cursor.execute("SELECT timestamp, source, description FROM events WHERE severity >= 3 ORDER BY timestamp DESC LIMIT 20")
        alerts = self.cursor.fetchall()
        
        for alert in alerts:
            self.alerts_tree.insert('', tk.END, values=alert)
        
        # Update analytics charts
        self.update_analytics_charts()
        
        # Schedule next update
        self.root.after(5000, self.update_dashboard)
    
    def update_analytics_charts(self):
        # Time series chart
        self.cursor.execute("""
            SELECT strftime('%Y-%m-%d %H:00', timestamp) as hour, 
                   COUNT(*) as count 
            FROM events 
            WHERE timestamp >= datetime('now', '-7 days') 
            GROUP BY hour 
            ORDER BY hour
        """)
        time_data = self.cursor.fetchall()
        
        self.time_ax.clear()
        if time_data:
            df = pd.DataFrame(time_data, columns=['Hour', 'Count'])
            df['Hour'] = pd.to_datetime(df['Hour'])
            df.plot(x='Hour', y='Count', ax=self.time_ax, legend=False)
            self.time_ax.set_title('Events Over Time (Last 7 Days)')
            self.time_ax.set_ylabel('Event Count')
            self.time_fig.tight_layout()
        
        self.time_canvas.draw()
        
        # Top sources chart
        self.cursor.execute("""
            SELECT source, COUNT(*) as count 
            FROM events 
            WHERE timestamp >= datetime('now', '-7 days') 
            GROUP BY source 
            ORDER BY count DESC 
            LIMIT 10
        """)
        source_data = self.cursor.fetchall()
        
        self.sources_ax.clear()
        if source_data:
            df = pd.DataFrame(source_data, columns=['Source', 'Count'])
            df.plot(kind='bar', x='Source', y='Count', ax=self.sources_ax, legend=False)
            self.sources_ax.set_title('Top Event Sources (Last 7 Days)')
            self.sources_ax.set_ylabel('Count')
            self.sources_fig.tight_layout()
        
        self.sources_canvas.draw()
    
    def collect_logs(self):
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
                timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
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
                status = 'New'
                
                # Insert into database
                self.cursor.execute("""
                    INSERT INTO events (timestamp, source, event_type, severity, description, ip_address, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (timestamp, source, event_type, severity, description, ip_address, status))
                
                self.conn.commit()
            
            # Check rules against new events
            self.check_rules()
            
            # Sleep for a random interval (1-5 seconds)
            time.sleep(random.uniform(1, 5))
    
    def check_rules(self):
        """Check events against defined rules and trigger actions"""
        self.cursor.execute("SELECT * FROM rules WHERE enabled = 1")
        rules = self.cursor.fetchall()
        
        for rule in rules:
            rule_id, name, condition, action, severity, enabled = rule
            
            # Simple condition evaluation (in a real SIEM, this would be more sophisticated)
            try:
                if "COUNT()" in condition:
                    # Handle count conditions
                    parts = condition.split("COUNT()")
                    base_condition = parts[0].strip()
                    count_condition = parts[1].strip()
                    
                    query = f"SELECT COUNT(*) FROM events WHERE {base_condition}"
                    self.cursor.execute(query)
                    count = self.cursor.fetchone()[0]
                    
                    if eval(f"{count}{count_condition}"):
                        self.trigger_action(action, rule_id, severity, name)
                else:
                    # Handle simple conditions
                    query = f"SELECT COUNT(*) FROM events WHERE {condition}"
                    self.cursor.execute(query)
                    count = self.cursor.fetchone()[0]
                    
                    if count > 0:
                        self.trigger_action(action, rule_id, severity, name)
            except Exception as e:
                print(f"Error evaluating rule {name}: {e}")
    
    def trigger_action(self, action, rule_id, severity, rule_name):
        """Trigger the appropriate action for a rule match"""
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        if action == "alert":
            # Create an alert event
            description = f"Rule triggered: {rule_name}"
            self.cursor.execute("""
                INSERT INTO events (timestamp, source, event_type, severity, description, ip_address, status)
                VALUES (?, 'SIEM', 'Rule Alert', ?, ?, 'N/A', 'New')
            """, (timestamp, severity, description))
            self.conn.commit()
            
            # In a real SIEM, this would send an email or other notification
            print(f"ALERT: {description}")
        
        elif action == "block":
            # Create a block event (in a real SIEM, this would actually block the IP)
            description = f"Block action from rule: {rule_name}"
            self.cursor.execute("""
                INSERT INTO events (timestamp, source, event_type, severity, description, ip_address, status)
                VALUES (?, 'SIEM', 'Block Action', ?, ?, 'N/A', 'New')
            """, (timestamp, severity, description))
            self.conn.commit()
            
            print(f"BLOCK: {description}")
    
    def add_rule(self):
        """Open dialog to add a new rule"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add New Rule")
        dialog.geometry("500x300")
        
        ttk.Label(dialog, text="Rule Name:").pack(pady=5)
        name_entry = ttk.Entry(dialog, width=50)
        name_entry.pack(pady=5)
        
        ttk.Label(dialog, text="Condition:").pack(pady=5)
        condition_entry = ttk.Entry(dialog, width=50)
        condition_entry.pack(pady=5)
        
        ttk.Label(dialog, text="Action:").pack(pady=5)
        action_var = tk.StringVar()
        action_combobox = ttk.Combobox(dialog, textvariable=action_var, values=['alert', 'block'])
        action_combobox.set('alert')
        action_combobox.pack(pady=5)
        
        ttk.Label(dialog, text="Severity:").pack(pady=5)
        severity_var = tk.IntVar()
        severity_combobox = ttk.Combobox(dialog, textvariable=severity_var, values=[1, 2, 3, 4, 5])
        severity_combobox.set(3)
        severity_combobox.pack(pady=5)
        
        enabled_var = tk.IntVar(value=1)
        enabled_check = ttk.Checkbutton(dialog, text="Enabled", variable=enabled_var)
        enabled_check.pack(pady=5)
        
        def save_rule():
            name = name_entry.get()
            condition = condition_entry.get()
            action = action_var.get()
            severity = severity_var.get()
            enabled = enabled_var.get()
            
            if not name or not condition:
                messagebox.showerror("Error", "Name and condition are required")
                return
            
            self.cursor.execute("""
                INSERT INTO rules (name, condition, action, severity, enabled)
                VALUES (?, ?, ?, ?, ?)
            """, (name, condition, action, severity, enabled))
            self.conn.commit()
            
            self.update_rules_table()
            dialog.destroy()
        
        save_button = ttk.Button(dialog, text="Save Rule", command=save_rule)
        save_button.pack(pady=10)
    
    def edit_rule(self):
        """Edit selected rule"""
        selected = self.rules_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a rule to edit")
            return
        
        item = self.rules_tree.item(selected[0])
        rule_name = item['values'][0]
        
        # Get full rule details from database
        self.cursor.execute("SELECT * FROM rules WHERE name = ?", (rule_name,))
        rule = self.cursor.fetchone()
        
        if not rule:
            messagebox.showerror("Error", "Rule not found in database")
            return
        
        rule_id, name, condition, action, severity, enabled = rule
        
        # Open edit dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Edit Rule")
        dialog.geometry("500x300")
        
        ttk.Label(dialog, text="Rule Name:").pack(pady=5)
        name_entry = ttk.Entry(dialog, width=50)
        name_entry.insert(0, name)
        name_entry.pack(pady=5)
        
        ttk.Label(dialog, text="Condition:").pack(pady=5)
        condition_entry = ttk.Entry(dialog, width=50)
        condition_entry.insert(0, condition)
        condition_entry.pack(pady=5)
        
        ttk.Label(dialog, text="Action:").pack(pady=5)
        action_var = tk.StringVar(value=action)
        action_combobox = ttk.Combobox(dialog, textvariable=action_var, values=['alert', 'block'])
        action_combobox.pack(pady=5)
        
        ttk.Label(dialog, text="Severity:").pack(pady=5)
        severity_var = tk.IntVar(value=severity)
        severity_combobox = ttk.Combobox(dialog, textvariable=severity_var, values=[1, 2, 3, 4, 5])
        severity_combobox.pack(pady=5)
        
        enabled_var = tk.IntVar(value=enabled)
        enabled_check = ttk.Checkbutton(dialog, text="Enabled", variable=enabled_var)
        enabled_check.pack(pady=5)
        
        def update_rule():
            new_name = name_entry.get()
            new_condition = condition_entry.get()
            new_action = action_var.get()
            new_severity = severity_var.get()
            new_enabled = enabled_var.get()
            
            if not new_name or not new_condition:
                messagebox.showerror("Error", "Name and condition are required")
                return
            
            self.cursor.execute("""
                UPDATE rules 
                SET name = ?, condition = ?, action = ?, severity = ?, enabled = ?
                WHERE id = ?
            """, (new_name, new_condition, new_action, new_severity, new_enabled, rule_id))
            self.conn.commit()
            
            self.update_rules_table()
            dialog.destroy()
        
        save_button = ttk.Button(dialog, text="Update Rule", command=update_rule)
        save_button.pack(pady=10)
    
    def delete_rule(self):
        """Delete selected rule"""
        selected = self.rules_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a rule to delete")
            return
        
        if not messagebox.askyesno("Confirm", "Are you sure you want to delete this rule?"):
            return
        
        item = self.rules_tree.item(selected[0])
        rule_name = item['values'][0]
        
        self.cursor.execute("DELETE FROM rules WHERE name = ?", (rule_name,))
        self.conn.commit()
        
        self.update_rules_table()
    
    def toggle_rule(self):
        """Toggle enabled status of selected rule"""
        selected = self.rules_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a rule to toggle")
            return
        
        item = self.rules_tree.item(selected[0])
        rule_name = item['values'][0]
        current_status = item['values'][4]
        new_status = 0 if current_status == "Yes" else 1
        
        self.cursor.execute("UPDATE rules SET enabled = ? WHERE name = ?", (new_status, rule_name))
        self.conn.commit()
        
        self.update_rules_table()
    
    def view_event_details(self):
        """Show details of selected event"""
        selected = self.events_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select an event to view")
            return
        
        item = self.events_tree.item(selected[0])
        values = item['values']
        
        dialog = tk.Toplevel(self.root)
        dialog.title("Event Details")
        dialog.geometry("500x300")
        
        details = (
            f"Timestamp: {values[0]}\n"
            f"Source: {values[1]}\n"
            f"Event Type: {values[2]}\n"
            f"Severity: {values[3]}\n"
            f"IP Address: {values[5]}\n"
            f"Status: {values[6]}\n\n"
            f"Description:\n{values[4]}"
        )
        
        text = tk.Text(dialog, wrap=tk.WORD)
        text.insert(tk.END, details)
        text.config(state=tk.DISABLED)
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    def mark_event_resolved(self):
        """Mark selected event as resolved"""
        selected = self.events_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select an event to mark as resolved")
            return
        
        item = self.events_tree.item(selected[0])
        timestamp = item['values'][0]
        source = item['values'][1]
        description = item['values'][4]
        
        self.cursor.execute("""
            UPDATE events 
            SET status = 'Resolved' 
            WHERE timestamp = ? AND source = ? AND description = ?
        """, (timestamp, source, description))
        self.conn.commit()
        
        self.update_event_table()
        messagebox.showinfo("Success", "Event marked as resolved")
    
    def add_to_watchlist(self):
        """Add IP from selected event to watchlist"""
        selected = self.events_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select an event to add to watchlist")
            return
        
        item = self.events_tree.item(selected[0])
        ip_address = item['values'][5]
        
        # In a real SIEM, this would add to an actual watchlist database table
        messagebox.showinfo("Watchlist", f"IP {ip_address} added to watchlist")
    
    def show_event_context_menu(self, event):
        """Show context menu for events"""
        item = self.events_tree.identify_row(event.y)
        if item:
            self.events_tree.selection_set(item)
            self.event_context_menu.post(event.x_root, event.y_root)
    
    def on_closing(self):
        """Handle window closing"""
        self.running = False
        if self.collection_thread.is_alive():
            self.collection_thread.join(timeout=1)
        self.conn.close()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = SIEMSystem(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()