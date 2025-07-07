import tkinter as tk
from tkinter import ttk
from tkinter import font as tkfont
from models.database import Database
from models.event import EventModel
from models.rule import RuleModel
from models.windows_log_collector import WindowsLogCollector
from views.dashboard_view import DashboardView
from views.events_view import EventsView
from views.rules_view import RulesView
from views.analytics_view import AnalyticsView
from views.settings_view import SettingsView
from views.sysmon_view import SysmonView

class SIEMSystem:
    def __init__(self, root):
        self.root = root
        self.root.title("Python SIEM System")
        self.root.geometry("1200x800")
        
        # Initialize models
        # Database connection is now handled in __init__
        self.db = Database()
        
        # Pass root window reference to EventModel for thread-safe operations
        self.event_model = EventModel(self.db, root=self.root)
        self.rule_model = RuleModel(self.db)
        
        # Initialize Windows Log Collector
        self.windows_collector = WindowsLogCollector(self.event_model)
        
        # Create GUI
        self._create_ui()
            
    def _create_ui(self):
        """Create the main application UI with navigation bar"""
        # Create main container
        self.main_container = ttk.Frame(self.root)
        self.main_container.pack(fill=tk.BOTH, expand=True)
        
        # Create navigation bar
        self._create_navbar()
        
        # Create content frame
        self.content_frame = ttk.Frame(self.main_container)
        self.content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create a frame to hold the current view
        self.current_view_frame = ttk.Frame(self.content_frame)
        self.current_view_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create all views but don't pack them yet
        self.views = {}
        self.views['dashboard'] = DashboardView(self.current_view_frame, self.event_model, self.rule_model)
        self.views['events'] = EventsView(self.current_view_frame, self.event_model)
        self.views['rules'] = RulesView(self.current_view_frame, self.rule_model)
        self.views['analytics'] = AnalyticsView(self.current_view_frame, self.event_model)
        self.views['sysmon'] = SysmonView(self.current_view_frame, self.event_model)
        self.views['settings'] = SettingsView(self.current_view_frame)
        
        # Show dashboard by default
        self.show_dashboard()
    
    def _create_navbar(self):
        """Create the navigation bar"""
        # Create navbar frame
        navbar_frame = ttk.Frame(self.main_container, style="Navbar.TFrame")
        navbar_frame.pack(fill=tk.X, side=tk.TOP)
        
        # Add logo
        logo_label = ttk.Label(
            navbar_frame, 
            text="SIEM System", 
            font=('Helvetica', 12, 'bold'),
            padding=(15, 10)
        )
        logo_label.pack(side=tk.LEFT)
        
        # Add navigation buttons
        nav_buttons_frame = ttk.Frame(navbar_frame)
        nav_buttons_frame.pack(side=tk.LEFT, padx=20)
        
        # Navigation buttons
        nav_items = [
            ("Dashboard", self.show_dashboard),
            ("Events", self.show_events),
            ("Rules", self.show_rules),
            ("Analytics", self.show_analytics),
            ("Sysmon", self.show_sysmon),
            ("Settings", self.show_settings)
        ]
        
        self.nav_buttons = {}
        for text, command in nav_items:
            btn = ttk.Button(
                nav_buttons_frame,
                text=text,
                command=command,
                style="Nav.TButton"
            )
            btn.pack(side=tk.LEFT, padx=5)
            self.nav_buttons[text.lower()] = btn
        
        # Add status bar
        self.status_var = tk.StringVar()
        status_bar = ttk.Label(
            navbar_frame, 
            textvariable=self.status_var,
            padding=(10, 5),
            anchor=tk.E
        )
        status_bar.pack(side=tk.RIGHT, padx=10)
        self.update_status("Ready")
        
        # Configure styles
        self._configure_styles()
    
    def _configure_styles(self):
        """Configure custom styles for the UI"""
        style = ttk.Style()
        
        # Navbar style
        style.configure("Navbar.TFrame", background='#f0f0f0')
        
        # Nav button style
        style.configure("Nav.TButton", 
                       padding=10,
                       font=('Helvetica', 10))
        
        # Hover effect for buttons (requires Tkinter 8.6+)
        style.map("Nav.TButton",
                background=[("active", "#e0e0e0")])
    
    def update_status(self, message):
        """Update the status bar message"""
        self.status_var.set(f"Status: {message}")
    
    # Navigation methods
    def _switch_view(self, view_name):
        """Switch to the specified view"""
        # Hide all views
        for view in self.views.values():
            view.frame.pack_forget()
        
        # Show the selected view
        if view_name in self.views:
            self.views[view_name].frame.pack(fill=tk.BOTH, expand=True)
            
            # Update window title
            self.root.title(f"SIEM System - {view_name.capitalize()}")
    
    def show_dashboard(self):
        self._switch_view('dashboard')
    
    def show_events(self):
        self._switch_view('events')
    
    def show_rules(self):
        self._switch_view('rules')
    
    def show_analytics(self):
        self._switch_view('analytics')
    
    def show_sysmon(self):
        self._switch_view('sysmon')
    
    def show_settings(self):
        self._switch_view('settings')
        
    def on_closing(self):
        """Handle application shutdown"""
        if hasattr(self, 'windows_collector') and self.windows_collector:
            self.windows_collector.stop()
        if hasattr(self, 'db') and self.db:
            self.db.close()
        if hasattr(self, 'root') and self.root:
            self.root.destroy()
        
    def start(self):
        """Start all collectors and initialize the UI"""
        try:
            # Start collectors
            self.windows_collector.start()
            # Start other collectors...
            
            # Update status
            self.update_status("Application started")
            
        except Exception as e:
            self.update_status(f"Error starting application: {str(e)}")
            raise
    
    def stop(self):
        """Stop all collectors and clean up resources"""
        try:
            # Stop all views first
            for view in self.views.values():
                if hasattr(view, 'stop'):
                    view.stop()
            
            # Stop collectors
            if hasattr(self, 'windows_collector'):
                self.windows_collector.stop()
                
            # Update status
            self.update_status("Application shutting down...")
            
        except Exception as e:
            self.update_status(f"Error during shutdown: {str(e)}")
            raise
        
def main():
    try:
        print("Starting SIEM application...")
        root = tk.Tk()
        print("Tkinter root window created")
        
        print("Initializing SIEMSystem...")
        app = SIEMSystem(root)
        print("SIEMSystem initialized")
        
        # Start collectors
        print("Starting collectors...")
        app.start()
        print("Collectors started")
        
        # Set up cleanup on window close
        root.protocol("WM_DELETE_WINDOW", app.on_closing)
        
        print("Starting main event loop...")
        # Start the main event loop
        root.mainloop()
        print("Main event loop ended")
        
    except Exception as e:
        print(f"Error in SIEM application: {e}")
        import traceback
        print("\nTraceback:")
        traceback.print_exc()
    finally:
        print("\nCleaning up resources...")
        # Ensure all resources are properly cleaned up
        if 'app' in locals():
            try:
                print("Stopping collectors...")
                app.stop()
                print("Closing database connection...")
                app.db.close()
                print("Cleanup complete")
            except Exception as e:
                print(f"Error during cleanup: {e}")

if __name__ == "__main__":
    main()