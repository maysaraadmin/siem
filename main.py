import tkinter as tk
from tkinter import ttk
from models.database import Database
from models.event import EventModel
from models.rule import RuleModel
from models.windows_log_collector import WindowsLogCollector
from views.dashboard_view import DashboardView
from views.events_view import EventsView
from views.rules_view import RulesView
from views.analytics_view import AnalyticsView
from views.settings_view import SettingsView

class SIEMSystem:
    def __init__(self, root):
        self.root = root
        self.root.title("Python SIEM System")
        self.root.geometry("1200x800")
        
        # Initialize models
        self.db = Database()
        self.db.connect()
        
        self.event_model = EventModel(self.db)
        self.rule_model = RuleModel(self.db)
        self.WindowsLogCollector = WindowsLogCollector(self.event_model)
        
        # Create GUI
        self._create_ui()
            
    def _create_ui(self):
        """Create the main application UI"""
        # Create main notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.dashboard_tab = DashboardView(self.notebook, self.event_model, self.rule_model)
        self.events_tab = EventsView(self.notebook, self.event_model)
        self.rules_tab = RulesView(self.notebook, self.rule_model)
        self.analytics_tab = AnalyticsView(self.notebook, self.event_model)
        self.settings_tab = SettingsView(self.notebook)
        
        # Add tabs to notebook
        self.notebook.add(self.dashboard_tab.frame, text="Dashboard")
        self.notebook.add(self.events_tab.frame, text="Events")
        self.notebook.add(self.rules_tab.frame, text="Rules")
        self.notebook.add(self.analytics_tab.frame, text="Analytics")
        self.notebook.add(self.settings_tab.frame, text="Settings")
        
    def on_closing(self):
        """Handle application shutdown"""
        self.WindowsLogCollector.stop()
        self.db.close()
        self.root.destroy()
    def start(self):
        """Start all collectors"""
        self.windows_collector.start()
        # Start other collectors...
        
    def stop(self):
        """Stop all collectors"""
        self.windows_collector.stop()
        # Stop other collectors...
        
if __name__ == "__main__":
    root = tk.Tk()
    app = SIEMSystem(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()