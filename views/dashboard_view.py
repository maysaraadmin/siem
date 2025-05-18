import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import pandas as pd
from typing import Dict

class DashboardView:
    def __init__(self, parent, event_model, rule_model):
        self.event_model = event_model
        self.rule_model = rule_model
        
        self.frame = ttk.Frame(parent)
        self._create_widgets()
        self.update_dashboard()
        
    def _create_widgets(self):
        """Create dashboard widgets"""
        # Stats frame
        stats_frame = ttk.Frame(self.frame)
        stats_frame.pack(fill=tk.X, pady=5)
        
        self.total_events_label = ttk.Label(stats_frame, text="Total Events: 0", font=('Arial', 10))
        self.total_events_label.pack(side=tk.LEFT, padx=10)
        
        self.critical_events_label = ttk.Label(stats_frame, text="Critical: 0", font=('Arial', 10), foreground='red')
        self.critical_events_label.pack(side=tk.LEFT, padx=10)
        
        # Charts frame
        charts_frame = ttk.Frame(self.frame)
        charts_frame.pack(fill=tk.BOTH, expand=True)
        
        # Event types chart
        self._create_event_types_chart(charts_frame)
        
        # Recent alerts
        self._create_recent_alerts()
        
    def _create_event_types_chart(self, parent):
        """Create event types chart"""
        event_types_frame = ttk.Frame(parent)
        event_types_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        ttk.Label(event_types_frame, text="Event Types", font=('Arial', 10)).pack()
        
        self.event_types_fig = plt.Figure(figsize=(5, 4), dpi=100)
        self.event_types_ax = self.event_types_fig.add_subplot(111)
        self.event_types_canvas = FigureCanvasTkAgg(self.event_types_fig, master=event_types_frame)
        self.event_types_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
    def _create_recent_alerts(self):
        """Create recent alerts table"""
        alerts_frame = ttk.Frame(self.frame)
        alerts_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        ttk.Label(alerts_frame, text="Recent Alerts", font=('Arial', 10)).pack()
        
        self.alerts_tree = ttk.Treeview(alerts_frame, columns=('timestamp', 'source', 'description'), show='headings')
        self.alerts_tree.heading('timestamp', text='Timestamp')
        self.alerts_tree.heading('source', text='Source')
        self.alerts_tree.heading('description', text='Description')
        
        scrollbar = ttk.Scrollbar(alerts_frame, orient=tk.VERTICAL, command=self.alerts_tree.yview)
        self.alerts_tree.configure(yscrollcommand=scrollbar.set)
        
        self.alerts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
    def update_dashboard(self):
        """Update dashboard data"""
        # Update stats
        stats = self.event_model.get_event_stats()
        self.total_events_label.config(text=f"Total Events: {stats['total']}")
        self.critical_events_label.config(text=f"Critical: {stats['critical']}")
        
        # Update event types chart
        self._update_event_types_chart()
        
        # Update recent alerts
        self._update_recent_alerts()
        
        # Schedule next update
        self.frame.after(5000, self.update_dashboard)
        
    def _update_event_types_chart(self):
        """Update event types chart data"""
        # Get top event types from model
        # (Implementation would use event_model methods)
        pass
        
    def _update_recent_alerts(self):
        """Update recent alerts table"""
        # Get recent alerts from model
        # (Implementation would use event_model methods)
        pass