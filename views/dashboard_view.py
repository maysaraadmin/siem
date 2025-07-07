import tkinter as tk
from tkinter import ttk
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import pandas as pd
from typing import Dict, List, Tuple
import psutil
import platform

class DashboardView:
    def __init__(self, parent, event_model, rule_model):
        self.event_model = event_model
        self.rule_model = rule_model
        self.last_update = None
        self.is_updating = False
        
        # Configure style
        self.style = ttk.Style()
        self.style.configure('TFrame', background='white')
        self.style.configure('Header.TLabel', font=('Arial', 12, 'bold'))
        self.style.configure('Metric.TLabel', font=('Arial', 24, 'bold'))
        
        # Initialize system status variables
        self.cpu_var = tk.StringVar(value="0%")
        self.mem_var = tk.StringVar(value="0%")
        self.disk_var = tk.StringVar(value="0%")
        
        self.frame = ttk.Frame(parent, padding=10)
        self.is_visible = True  # Track if the dashboard is currently visible
        self._create_widgets()
        
        # Initialize with empty data
        self._init_empty_charts()
        
        # Schedule the first update
        self.frame.after(100, self.update_dashboard)
    
    def _create_timeline_chart(self, parent):
        """Create event timeline chart with modern styling"""
        # Create a frame to hold the chart
        chart_frame = ttk.Frame(parent)
        chart_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create a figure and axis for the timeline chart
        self.timeline_fig, self.timeline_ax = plt.subplots(figsize=(8, 4), dpi=100)
        self.timeline_fig.patch.set_facecolor('#ffffff')
        self.timeline_ax.set_facecolor('#ffffff')
        
        # Customize the chart appearance
        self.timeline_ax.spines['top'].set_visible(False)
        self.timeline_ax.spines['right'].set_visible(False)
        self.timeline_ax.spines['left'].set_color('#d1d5db')
        self.timeline_ax.spines['bottom'].set_color('#d1d5db')
        
        # Set up the canvas for embedding in Tkinter
        self.timeline_canvas = FigureCanvasTkAgg(self.timeline_fig, master=chart_frame)
        self.timeline_canvas.draw()
        self.timeline_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Add a placeholder text
        self.timeline_ax.text(0.5, 0.5, 'Loading event data...', 
                             ha='center', va='center',
                             transform=self.timeline_ax.transAxes,
                             color='#6c757d')
        
        return chart_frame
        
    def _update_timeline_chart(self):
        """Update the timeline chart with the latest event data"""
        try:
            # Get event data for the last 24 hours
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=24)
            
            # Get events from the database
            query = """
                SELECT 
                    strftime('%Y-%m-%d %H:00', timestamp) as time_interval,
                    COUNT(*) as event_count
                FROM events
                WHERE timestamp BETWEEN ? AND ?
                GROUP BY time_interval
                ORDER BY time_interval
            """
            
            events = self.event_model.db.execute_query(
                query, 
                (start_time.strftime('%Y-%m-%d %H:%M:%S'), 
                 end_time.strftime('%Y-%m-%d %H:%M:%S'))
            )
            
            if not events:
                # No data to display
                self.timeline_ax.clear()
                self.timeline_ax.text(0.5, 0.5, 'No event data available', 
                                    ha='center', va='center',
                                    transform=self.timeline_ax.transAxes,
                                    color='#6c757d')
                self.timeline_ax.set_xticks([])
                self.timeline_ax.set_yticks([])
                self.timeline_canvas.draw()
                return
                
            # Convert to pandas DataFrame for easier manipulation
            import pandas as pd
            df = pd.DataFrame(events, columns=['time_interval', 'event_count'])
            df['time_interval'] = pd.to_datetime(df['time_interval'])
            
            # Create a complete time range with all hours
            time_range = pd.date_range(
                start=df['time_interval'].min().floor('H'),
                end=df['time_interval'].max().ceil('H'),
                freq='H'
            )
            
            # Reindex the dataframe to include all hours
            df = df.set_index('time_interval').reindex(time_range).fillna(0).reset_index()
            df = df.rename(columns={'index': 'time_interval'})
            
            # Plot the timeline
            self.timeline_ax.clear()
            
            # Customize the plot appearance
            self.timeline_ax.plot(df['time_interval'], df['event_count'], 
                                color='#4e73df', linewidth=2, marker='o', markersize=4,
                                markerfacecolor='#ffffff', markeredgewidth=1, 
                                markeredgecolor='#4e73df')
            
            # Format the x-axis
            self.timeline_ax.xaxis.set_major_formatter(
                plt.matplotlib.dates.DateFormatter('%H:%M')
            )
            plt.setp(self.timeline_ax.xaxis.get_majorticklabels(), rotation=45, ha='right')
            
            # Set titles and labels
            self.timeline_ax.set_title('Events per Hour', pad=15, fontsize=12, fontweight='bold')
            self.timeline_ax.set_xlabel('Time', labelpad=10)
            self.timeline_ax.set_ylabel('Number of Events', labelpad=10)
            
            # Customize grid
            self.timeline_ax.grid(True, linestyle='--', alpha=0.7, color='#e9ecef')
            
            # Adjust layout to prevent cutoff
            self.timeline_fig.tight_layout()
            
            # Draw the canvas
            self.timeline_canvas.draw()
            
        except Exception as e:
            print(f"Error updating timeline chart: {str(e)}")
            # Reset the chart on error
            self.timeline_ax.clear()
            self.timeline_ax.text(0.5, 0.5, 'Error loading data', 
                                ha='center', va='center',
                                transform=self.timeline_ax.transAxes,
                                color='#dc3545')
            self.timeline_ax.set_xticks([])
            self.timeline_ax.set_yticks([])
            self.timeline_canvas.draw()
    
    def _create_widgets(self):
        """Create dashboard widgets with modern styling"""
        # Configure style
        style = ttk.Style()
        style.configure('Card.TFrame', background='#ffffff', relief='raised', borderwidth=1)
        style.configure('Card.TLabel', background='#ffffff')
        style.configure('CardHeader.TLabel', background='#f8f9fa', font=('Segoe UI', 10, 'bold'))
        
        # Main container with padding
        container = ttk.Frame(self.frame, padding=10)
        container.pack(fill=tk.BOTH, expand=True)
        
        # Top row: Stats cards - using grid for better control
        stats_frame = ttk.Frame(container)
        stats_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Stats cards with improved styling
        self._create_stat_card(stats_frame, "Total Events", "0", 0, '#4e73df')
        self._create_stat_card(stats_frame, "Critical", "0", 1, '#e74a3b')
        self._create_stat_card(stats_frame, "Warnings", "0", 2, '#f6c23e')
        self._create_stat_card(stats_frame, "Sources", "0", 3, '#1cc88a')
        
        # Middle row: Charts - using grid for better layout
        middle_frame = ttk.Frame(container)
        middle_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 20))
        
        # Left column: Timeline chart (2/3 width)
        left_frame = ttk.Frame(middle_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        # Timeline chart with card style
        timeline_card = ttk.Frame(left_frame, style='Card.TFrame', padding=5)
        timeline_card.pack(fill=tk.BOTH, expand=True)
        ttk.Label(timeline_card, text="EVENT TIMELINE (24H)", style='CardHeader.TLabel').pack(anchor='w', pady=(0, 10))
        self._create_timeline_chart(timeline_card)
        
        # Right column: Two smaller cards stacked vertically
        right_frame = ttk.Frame(middle_frame, width=300)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(10, 0))
        
        # Severity distribution card
        severity_card = ttk.Frame(right_frame, style='Card.TFrame', padding=5)
        severity_card.pack(fill=tk.X, pady=(0, 15))
        ttk.Label(severity_card, text="SEVERITY DISTRIBUTION", style='CardHeader.TLabel').pack(anchor='w', pady=(0, 10))
        self._create_severity_chart(severity_card)
        
        # System status card
        status_card = ttk.Frame(right_frame, style='Card.TFrame', padding=5)
        status_card.pack(fill=tk.X, pady=(0, 15))
        ttk.Label(status_card, text="SYSTEM STATUS", style='CardHeader.TLabel').pack(anchor='w', pady=(0, 10))
        self._create_system_status(status_card)
        
        # Bottom row: Top sources and recent alerts
        bottom_frame = ttk.Frame(container)
        bottom_frame.pack(fill=tk.BOTH, expand=True)
        
        # Top sources card (left)
        self.sources_card = ttk.Frame(bottom_frame, style='Card.TFrame', padding=5)
        self.sources_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        ttk.Label(self.sources_card, text="TOP EVENT SOURCES", style='CardHeader.TLabel').pack(anchor='w', pady=(0, 10))
        self._create_top_sources_chart(self.sources_card)
        
        # Recent alerts card (right)
        alerts_card = ttk.Frame(bottom_frame, style='Card.TFrame', padding=5)
        alerts_card.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(10, 0))
        ttk.Label(alerts_card, text="RECENT ALERTS", style='CardHeader.TLabel').pack(anchor='w', pady=(0, 10))
        self._create_recent_alerts(alerts_card)
    
    def _create_stat_card(self, parent, title: str, value: str, column: int, color: str = '#4e73df'):
        """Create a modern metric card with icon and animation"""
        # Define icons for different metrics
        icons = {
            'Total Events': '📊',
            'Critical': '⚠️',
            'Warnings': '🔔',
            'Sources': '🔍'
        }
        
        # Create card with custom styling
        card = ttk.Frame(parent, style='Card.TFrame', padding=15)
        card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=8)
        
        # Card header with icon and title
        header_frame = ttk.Frame(card)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Icon
        # Use a solid light version of the color instead of alpha channel
        light_colors = {
            '#4e73df': '#e0e6ff',  # Blue
            '#e74a3b': '#fde8e6',  # Red
            '#f6c23e': '#fef5e6',  # Yellow
            '#1cc88a': '#e6f7f1'   # Green
        }
        icon_label = ttk.Label(
            header_frame, 
            text=icons.get(title, '📊'), 
            font=('Segoe UI', 14),
            background=light_colors.get(color, '#f0f0f0'),
            foreground=color,
            padding=(8, 4)
        )
        icon_label.pack(side=tk.LEFT)
        
        # Title
        ttk.Label(
            header_frame, 
            text=title.upper(), 
            style='CardHeader.TLabel',
            font=('Segoe UI', 9, 'bold'),
            foreground='#5a5c69'
        ).pack(side=tk.LEFT, padx=10)
        
        # Value with animation
        value_frame = ttk.Frame(card)
        value_frame.pack(fill=tk.X)
        
        value_label = ttk.Label(
            value_frame,
            text=value,
            font=('Segoe UI', 24, 'bold'),
            foreground=color,
            anchor='w'
        )
        value_label.pack(fill=tk.X, pady=(5, 0))
        
        # Store reference for updates
        if not hasattr(self, 'stat_labels'):
            self.stat_labels = {}
        self.stat_labels[title] = value_label
    
    def _create_severity_chart(self, parent):
        """Create severity distribution donut chart with modern styling"""
        # Create figure with custom style
        self.severity_fig = Figure(figsize=(6, 4), dpi=100, facecolor='#ffffff')
        self.severity_ax = self.severity_fig.add_subplot(111)
        
        # Configure plot style
        self.severity_ax.set_facecolor('#ffffff')
        
        # Remove top and right spines
        for spine in ['top', 'right']:
            self.severity_ax.spines[spine].set_visible(False)
            
        # Set colors for the donut chart
        self.severity_colors = ['#4e73df', '#1cc88a', '#f6c23e', '#e74a3b', '#858796']
        
        # Create an empty donut chart as placeholder
        self.severity_ax.pie(
            [1],  # Single value for the placeholder
            colors=['#f8f9fc'],  # Light gray color for the placeholder
            wedgeprops=dict(width=0.5, edgecolor='#ffffff'),  # Make it a donut
            startangle=90
        )
        
        # Add a centered text
        self.severity_ax.text(
            0, 0, 'Loading...', 
            ha='center', va='center', 
            fontsize=10, 
            color='#6c757d'
        )
        
        # Set aspect ratio to be equal so that pie is drawn as a circle
        self.severity_ax.axis('equal')
        
        # Create the canvas and add it to the parent
        self.severity_canvas = FigureCanvasTkAgg(self.severity_fig, master=parent)
        self.severity_canvas.draw()
        self.severity_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Add a small margin at the bottom
        ttk.Frame(parent, height=5).pack()
        
        return self.severity_canvas.get_tk_widget()
        
    def _update_top_sources_chart(self):
        """Update the top sources chart with the latest data"""
        try:
            # Get top event sources from the database
            query = """
                SELECT 
                    source,
                    COUNT(*) as count
                FROM events
                WHERE timestamp >= datetime('now', '-24 hours')
                GROUP BY source
                ORDER BY count DESC
                LIMIT 10
            """
            
            sources_data = self.event_model.db.execute_query(query)
            
            if not sources_data:
                # No data to display
                if hasattr(self, 'sources_ax'):
                    self.sources_ax.clear()
                    self.sources_ax.text(0.5, 0.5, 'No source data', 
                                      ha='center', va='center',
                                      transform=self.sources_ax.transAxes,
                                      color='#6c757d')
                    self.sources_ax.set_xticks([])
                    self.sources_ax.set_yticks([])
                    if hasattr(self, 'sources_canvas'):
                        self.sources_canvas.draw()
                return
                
            # Convert to lists for plotting
            sources = [row[0] for row in sources_data]
            counts = [row[1] for row in sources_data]
            
            # Clear the previous plot
            if not hasattr(self, 'sources_ax'):
                self.sources_fig = Figure(figsize=(8, 4), dpi=100, facecolor='#ffffff')
                self.sources_ax = self.sources_fig.add_subplot(111)
                
                # Configure plot style
                self.sources_ax.set_facecolor('#ffffff')
                
                # Remove top and right spines
                for spine in ['top', 'right']:
                    self.sources_ax.spines[spine].set_visible(False)
                
                # Create the canvas and add it to the parent
                self.sources_canvas = FigureCanvasTkAgg(self.sources_fig, master=self.sources_card)
                self.sources_canvas.draw()
                self.sources_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            else:
                self.sources_ax.clear()
            
            # Create horizontal bar chart
            y_pos = range(len(sources))
            bars = self.sources_ax.barh(y_pos, counts, color='#4e73df', height=0.6)
            
            # Add value labels on the bars
            for i, (count, bar) in enumerate(zip(counts, bars)):
                width = bar.get_width()
                self.sources_ax.text(
                    width + (0.02 * max(counts)),  # Position the text slightly to the right of the bar
                    i,  # Y position
                    f' {count}',  # Text to display
                    va='center',
                    fontsize=9
                )
            
            # Customize the chart
            self.sources_ax.set_yticks(y_pos)
            self.sources_ax.set_yticklabels(sources, fontsize=9)
            self.sources_ax.set_xlabel('Number of Events', fontsize=9)
            self.sources_ax.set_title('Top Event Sources (24h)', pad=15, fontsize=12, fontweight='bold')
            
            # Add grid lines
            self.sources_ax.grid(True, linestyle='--', alpha=0.3, axis='x')
            
            # Remove x-axis ticks but keep the grid
            self.sources_ax.tick_params(axis='x', which='both', bottom=False, top=False, labelbottom=True)
            
            # Make sure all elements fit in the figure
            self.sources_fig.tight_layout()
            
            # Draw the updated chart
            self.sources_canvas.draw()
            
        except Exception as e:
            print(f"Error updating top sources chart: {str(e)}")
            # Reset the chart on error
            if hasattr(self, 'sources_ax'):
                self.sources_ax.clear()
                self.sources_ax.text(0.5, 0.5, 'Error loading data', 
                                  ha='center', va='center',
                                  transform=self.sources_ax.transAxes,
                                  color='#dc3545')
                self.sources_ax.set_xticks([])
                self.sources_ax.set_yticks([])
                if hasattr(self, 'sources_canvas'):
                    self.sources_canvas.draw()
    
    def _update_severity_chart(self):
        """Update the severity distribution chart with the latest data"""
        try:
            # Get severity distribution from the database
            query = """
                SELECT 
                    severity,
                    COUNT(*) as count
                FROM events
                WHERE timestamp >= datetime('now', '-24 hours')
                GROUP BY severity
                ORDER BY severity
            """
            
            severity_data = self.event_model.db.execute_query(query)
            
            if not severity_data:
                # No data to display
                self.severity_ax.clear()
                self.severity_ax.text(0.5, 0.5, 'No severity data', 
                                    ha='center', va='center',
                                    transform=self.severity_ax.transAxes,
                                    color='#6c757d')
                self.severity_ax.set_xticks([])
                self.severity_ax.set_yticks([])
                self.severity_canvas.draw()
                return
                
            # Convert to lists for plotting
            severities = [row[0] for row in severity_data]
            counts = [row[1] for row in severity_data]
            
            # Clear the previous plot
            self.severity_ax.clear()
            
            # Create the donut chart
            wedges, texts, autotexts = self.severity_ax.pie(
                counts,
                labels=[f'Severity {sev}' for sev in severities],
                colors=self.severity_colors[:len(severities)],
                autopct='%1.1f%%',
                startangle=90,
                wedgeprops=dict(width=0.5, edgecolor='#ffffff'),
                textprops={'fontsize': 8}
            )
            
            # Equal aspect ratio ensures that pie is drawn as a circle
            self.severity_ax.axis('equal')
            
            # Add a title
            self.severity_ax.set_title('Severity Distribution', pad=15, fontsize=12, fontweight='bold')
            
            # Add a legend
            self.severity_ax.legend(
                wedges, 
                [f'Severity {sev} ({count})' for sev, count in zip(severities, counts)],
                title="Severity Levels",
                loc="center left",
                bbox_to_anchor=(1, 0, 0.5, 1)
            )
            
            # Draw the updated chart
            self.severity_canvas.draw()
            
        except Exception as e:
            print(f"Error updating severity chart: {str(e)}")
            # Reset the chart on error
            self.severity_ax.clear()
            self.severity_ax.text(0.5, 0.5, 'Error loading data', 
                                ha='center', va='center',
                                transform=self.severity_ax.transAxes,
                                color='#dc3545')
            self.severity_ax.set_xticks([])
            self.severity_ax.set_yticks([])
            self.severity_canvas.draw()
    
    def _create_timeline_chart(self, parent):
        """Create event timeline chart with modern styling"""
        # Create figure with custom style
        self.timeline_fig = Figure(figsize=(8, 4), dpi=100, facecolor='#ffffff')
        self.timeline_ax = self.timeline_fig.add_subplot(111)
        
        # Configure plot style
        self.timeline_ax.set_facecolor('#f8f9fc')
        self.timeline_fig.set_facecolor('#ffffff')
        
        # Configure grid and spines
        self.timeline_ax.grid(True, linestyle='--', alpha=0.3, color='#d1d3e2')
        for spine in self.timeline_ax.spines.values():
            spine.set_visible(False)
        
        # Adjust layout
        self.timeline_fig.subplots_adjust(
            left=0.08, 
            right=0.97, 
            top=0.95, 
            bottom=0.15,
            hspace=0.2
        )
        
        # Create canvas
        self.timeline_canvas = FigureCanvasTkAgg(self.timeline_fig, master=parent)
        self.timeline_canvas.draw()
        self.timeline_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def _create_severity_chart(self, parent):
        """Create severity distribution donut chart with modern styling"""
        # Create figure with custom style
        self.severity_fig = Figure(figsize=(6, 3), dpi=100, facecolor='#ffffff')
        self.severity_ax = self.severity_fig.add_subplot(111)
        
        # Configure plot style
        self.severity_ax.set_facecolor('#f8f9fc')
        self.severity_fig.set_facecolor('#ffffff')
        
        # Remove axis
        self.severity_ax.axis('equal')
        
        # Adjust layout
        self.severity_fig.subplots_adjust(
            left=0.1, 
            right=0.9, 
            top=0.9, 
            bottom=0.1
        )
        
        # Create canvas
        self.severity_canvas = FigureCanvasTkAgg(self.severity_fig, master=parent)
        self.severity_canvas.draw()
        self.severity_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def _create_system_status(self, parent):
        """Create modern system status indicators with progress bars"""
        # Create main container
        container = ttk.Frame(parent, style='Card.TFrame', padding=15)
        container.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        # Title
        ttk.Label(
            container, 
            text="SYSTEM STATUS", 
            font=('Segoe UI', 9, 'bold'),
            foreground='#5a5c69'
        ).pack(anchor='w', pady=(0, 15))
        
        # System metrics with progress bars
        metrics = [
            ("CPU", self.cpu_var, '#4e73df'),
            ("Memory", self.mem_var, '#1cc88a'),
            ("Disk", self.disk_var, '#36b9cc')
        ]
        
        for i, (label, var, color) in enumerate(metrics):
            # Create frame for each metric
            metric_frame = ttk.Frame(container)
            metric_frame.pack(fill=tk.X, pady=4)
            
            # Label
            ttk.Label(
                metric_frame, 
                text=label,
                font=('Segoe UI', 9),
                width=8,
                anchor='w'
            ).pack(side=tk.LEFT)
            
            # Progress bar
            progress = ttk.Progressbar(
                metric_frame, 
                orient='horizontal',
                length=100,
                mode='determinate',
                style=f'Horizontal.TProgressbar',
                takefocus=False
            )
            progress.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 10))
            
            # Value
            ttk.Label(
                metric_frame, 
                textvariable=var,
                font=('Segoe UI', 9, 'bold'),
                width=6,
                anchor='e'
            ).pack(side=tk.RIGHT)
            
            # Store progress bar reference
            if not hasattr(self, 'progress_bars'):
                self.progress_bars = {}
            self.progress_bars[label.lower()] = progress
        
        # OS Info
        os_frame = ttk.Frame(container)
        os_frame.pack(fill=tk.X, pady=(15, 0))
        
        ttk.Label(
            os_frame,
            text=f"{platform.system()} {platform.release()}",
            font=('Segoe UI', 8),
            foreground='#858796',
            anchor='w'
        ).pack(side=tk.LEFT)
        
        # Update progress bars when values change
        def update_progress(var, index, mode):
            try:
                value = int(var.get().strip('%'))
                if 'cpu' in var._name:
                    self.progress_bars['cpu']['value'] = value
                elif 'mem' in var._name:
                    self.progress_bars['memory']['value'] = value
                elif 'disk' in var._name:
                    self.progress_bars['disk']['value'] = value
            except (ValueError, KeyError):
                pass
        
        # Track variables for updates
        for var in [self.cpu_var, self.mem_var, self.disk_var]:
            var.trace_add('write', update_progress)
    
    def _create_top_sources_chart(self, parent):
        """Create top sources bar chart"""
        frame = ttk.LabelFrame(parent, text="Top Event Sources", padding=5)
        frame.pack(fill=tk.BOTH, expand=True)
        
        self.sources_fig = Figure(figsize=(6, 3), dpi=100)
        self.sources_ax = self.sources_fig.add_subplot(111)
        self.sources_fig.subplots_adjust(left=0.15, right=0.95, top=0.9, bottom=0.2)
        
        self.sources_canvas = FigureCanvasTkAgg(self.sources_fig, master=frame)
        self.sources_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def _create_recent_alerts(self, parent):
        """Create modern recent alerts table with better styling"""
        # Create main container
        container = ttk.Frame(parent, style='Card.TFrame')
        container.pack(fill=tk.BOTH, expand=True)
        
        # Create treeview with custom style
        style = ttk.Style()
        style.configure('Treeview', 
                       font=('Segoe UI', 9),
                       rowheight=25,
                       borderwidth=0,
                       highlightthickness=0)
        
        style.configure('Treeview.Heading', 
                       font=('Segoe UI', 9, 'bold'),
                       borderwidth=0)
        
        style.map('Treeview', background=[('selected', '#e8f0fe')])
        
        # Create treeview with scrollbars
        self.alerts_tree = ttk.Treeview(
            container, 
            columns=('time', 'source', 'event_type', 'severity', 'description'),
            show='headings',
            height=6,
            style='Treeview'
        )
        
        # Configure columns
        columns = {
            'time': {'text': 'TIME', 'width': 120, 'anchor': 'w'},
            'source': {'text': 'SOURCE', 'width': 100, 'anchor': 'w'},
            'event_type': {'text': 'EVENT TYPE', 'width': 150, 'anchor': 'w'},
            'severity': {'text': 'SEVERITY', 'width': 90, 'anchor': 'center'},
            'description': {'text': 'DESCRIPTION', 'width': 400, 'anchor': 'w'}
        }
        
        for col, config in columns.items():
            self.alerts_tree.heading(col, text=config['text'], anchor='center')
            self.alerts_tree.column(col, width=config['width'], anchor=config['anchor'])
        
        # Add scrollbars
        y_scroll = ttk.Scrollbar(container, orient='vertical', command=self.alerts_tree.yview)
        x_scroll = ttk.Scrollbar(container, orient='horizontal', command=self.alerts_tree.xview)
        self.alerts_tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        
        # Grid layout
        self.alerts_tree.grid(row=1, column=0, sticky='nsew', padx=5, pady=5)
        y_scroll.grid(row=1, column=1, sticky='ns', pady=5)
        x_scroll.grid(row=2, column=0, sticky='ew', padx=5)
        
        # Configure grid weights
        container.columnconfigure(0, weight=1)
        container.rowconfigure(1, weight=1)
    
    def _init_empty_charts(self):
        """Initialize charts with empty data"""
        # Initialize timeline chart
        self.timeline_ax.clear()
        self.timeline_ax.set_xticks([])
        self.timeline_ax.set_yticks([])
        self.timeline_ax.text(0.5, 0.5, 'Loading data...', 
                            ha='center', va='center', 
                            transform=self.timeline_ax.transAxes)
        self.timeline_canvas.draw()
        
        # Initialize severity chart
        self.severity_ax.clear()
        self.severity_ax.set_xticks([])
        self.severity_ax.set_yticks([])
        self.severity_ax.text(0.5, 0.5, 'Loading data...', 
                            ha='center', va='center', 
                            transform=self.severity_ax.transAxes)
        self.severity_canvas.draw()
        
        # Initialize sources chart
        self.sources_ax.clear()
        self.sources_ax.set_xticks([])
        self.sources_ax.set_yticks([])
        self.sources_ax.text(0.5, 0.5, 'Loading data...',
                           ha='center', va='center',
                           transform=self.sources_ax.transAxes)
        self.sources_canvas.draw()
    
    def update_dashboard(self):
        """Update all dashboard widgets with smooth transitions"""
        if not self.is_visible:
            return
            
        if self.is_updating:
            self.frame.after(1000, self.update_dashboard)
            return
            
        self.is_updating = True
        
        try:
            # Update stats with animation
            self._animate_stats_update()
            
            # Update charts with smooth transitions
            self._update_timeline_chart()
            self._update_severity_chart()
            self._update_top_sources_chart()
            
            # Update recent alerts with fade effect
            self._update_recent_alerts()
            
            # Update system status with progress bars
            self._update_system_status()
            
            # Update window title with timestamp
            self.master.master.title(f"SIEM Dashboard - Last updated: {datetime.now().strftime('%H:%M:%S')}")
            
        except Exception as e:
            print(f"Error updating dashboard: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.is_updating = False
            self.frame.after(5000, self.update_dashboard)  # Update every 5 seconds
    
    def _animate_stats_update(self):
        """Animate the statistics cards when updating"""
        try:
            # Get current values
            current_values = {
                'Total Events': int(self.stat_labels['Total Events']['text'] or 0),
                'Critical': int(self.stat_labels['Critical']['text'] or 0),
                'Warnings': int(self.stat_labels['Warnings']['text'] or 0),
                'Sources': int(self.stat_labels['Sources']['text'] or 0)
            }
            
            # Get new values
            new_values = {
                'Total Events': self.event_model.get_event_count(),
                'Critical': self.event_model.get_event_count(severity=5),
                'Warnings': self.event_model.get_event_count(severity=3),
                'Sources': len(self.event_model.get_event_sources() or [])
            }
            
            # Animate each counter
            for stat, new_value in new_values.items():
                current = current_values[stat]
                if current != new_value:
                    self._animate_counter(self.stat_labels[stat], current, new_value)
                    
        except Exception as e:
            print(f"Error animating stats: {e}")
    
    def _animate_counter(self, label, start, end, duration=500):
        """Animate a counter from start to end value"""
        steps = 20
        delay = duration // steps
        step = (end - start) / steps
        
        def update(step_num=0):
            if step_num <= steps:
                value = int(start + (step * step_num))
                label.config(text=str(value))
                label.after(delay, update, step_num + 1)
        
        update()
    
    def _update_recent_alerts(self):
        """Update recent alerts table with smooth transitions"""
        try:
            # Get recent alerts
            alerts = self.event_model.get_recent_alerts(limit=10)
            
            # Get current selection to restore after update
            selected = self.alerts_tree.selection()
            selected_values = [self.alerts_tree.item(i, 'values') for i in selected]
            
            # Clear existing items with fade effect
            for item in self.alerts_tree.get_children():
                self.alerts_tree.detach(item)
            
            # Add new items with animation
            for i, alert in enumerate(alerts):
                # alert format: (id, timestamp, source, event_type, severity, description, ...)
                severity = alert[4] if len(alert) > 4 else 'N/A'
                
                # Determine row color based on severity
                tag = ''
                if 'critical' in str(severity).lower():
                    tag = 'critical'
                elif 'warning' in str(severity).lower():
                    tag = 'warning'
                
                # Format timestamp
                timestamp = alert[1].strftime('%Y-%m-%d %H:%M:%S') if len(alert) > 1 else 'N/A'
                
                # Insert item with animation
                item_id = self.alerts_tree.insert(
                    '', 'end',
                    values=(
                        timestamp,
                        alert[2] if len(alert) > 2 else 'N/A',  # source
                        alert[3] if len(alert) > 3 else 'N/A',  # event_type
                        severity,
                        alert[5] if len(alert) > 5 else 'N/A'   # description
                    ),
                    tags=(tag,)
                )
                
                # Configure row style
                self.alerts_tree.tag_configure('critical', background='#ffebee', font=('Segoe UI', 9, 'bold'))
                self.alerts_tree.tag_configure('warning', background='#fff8e1')
                
                # Restore selection if this item was selected before
                if (timestamp, alert[2] if len(alert) > 2 else 'N/A') in [(v[0], v[1]) for v in selected_values]:
                    self.alerts_tree.selection_add(item_id)
            
            # Auto-scroll to top if not at bottom
            self.alerts_tree.yview_moveto(0)
            
        except Exception as e:
            print(f"Error updating recent alerts: {e}")
    
    def _update_system_status(self):
        """Update system status indicators with smooth animations"""
        try:
            # Get CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            self.cpu_var.set(f"{int(cpu_percent)}%")
            
            # Get memory usage
            mem = psutil.virtual_memory()
            mem_percent = mem.percent
            self.mem_var.set(f"{int(mem_percent)}%")
            
            # Get disk usage (using root directory)
            disk = psutil.disk_usage('/' if platform.system() == 'Linux' else 'C:\\')
            disk_percent = disk.percent
            self.disk_var.set(f"{int(disk_percent)}%")
            
            # Animate progress bars
            if hasattr(self, 'progress_bars'):
                # CPU progress bar
                self._animate_progress(
                    self.progress_bars['cpu'], 
                    self.progress_bars['cpu']['value'], 
                    cpu_percent
                )
                
                # Memory progress bar
                self._animate_progress(
                    self.progress_bars['memory'],
                    self.progress_bars['memory']['value'],
                    mem_percent
                )
                
                # Disk progress bar
                self._animate_progress(
                    self.progress_bars['disk'],
                    self.progress_bars['disk']['value'],
                    disk_percent
                )
                
        except Exception as e:
            print(f"Error updating system status: {e}")
            
    def _animate_progress(self, progress_bar, start, end, duration=500):
        """Animate a progress bar from start to end value"""
        steps = 20
        delay = duration // steps
        step = (end - start) / steps
        
        def update(step=0):
            if step <= steps:
                value = start + (step * (end - start) / steps)
                progress_bar['value'] = value
                progress_bar.after(delay, update, step + 1)
        
        update()
    
    def _update_severity_chart(self):
        """Update the severity distribution chart with smooth animations"""
        try:
            # Get severity distribution from model
            severities = self.event_model.get_severity_distribution()
            
            # Clear previous chart
            self.severity_ax.clear()
            
            if not severities:
                self.severity_ax.text(0.5, 0.5, 'No data available',
                                   ha='center', va='center',
                                   fontsize=10, color='gray')
                self.severity_ax.axis('off')
                self.severity_canvas.draw()
                return
            
            # Prepare data
            labels = [f"{s[0]} ({s[1]})" for s in severities]
            sizes = [s[1] for s in severities]
            colors = ['#36b9cc', '#1cc88a', '#f6c23e', '#e74a3b', '#858796']
            
            # Create donut chart
            wedges, texts, autotexts = self.severity_ax.pie(
                sizes, labels=labels, colors=colors[:len(sizes)],
                autopct='%1.1f%%', startangle=90,
                wedgeprops=dict(width=0.6, edgecolor='w'),
                textprops={'fontsize': 8}
            )
            
            # Equal aspect ratio ensures that pie is drawn as a circle
            self.severity_ax.axis('equal')
            
            # Add a title
            self.severity_ax.set_title('Severity Distribution', fontsize=10, pad=10)
            
            # Adjust layout
            self.severity_fig.tight_layout()
            
            # Draw canvas
            self.severity_canvas.draw()
            
        except Exception as e:
            print(f"Error updating severity chart: {e}")
            import traceback
            traceback.print_exc()
    
    def _update_system_status(self):
        """Update system status indicators with smooth animations"""
        try:
            # Get system stats with error handling
            try:
                cpu_percent = psutil.cpu_percent(interval=0.5)
                mem = psutil.virtual_memory()
                disk = psutil.disk_usage('/' if os.name != 'nt' else 'C:\\')
                
                # Update progress bars with animation
                for label, value in [
                    ('cpu', cpu_percent),
                    ('memory', mem.percent),
                    ('disk', disk.percent)
                ]:
                    if hasattr(self, 'progress_bars') and label in self.progress_bars:
                        current = self.progress_bars[label]['value']
                        self._animate_progress(self.progress_bars[label], current, value)
                
                # Update text variables with formatted values
                self.cpu_var.set(f"{cpu_percent:.1f}%")
                self.mem_var.set(f"{mem.percent:.1f}%")
                self.disk_var.set(f"{disk.percent:.1f}%")
                
            except Exception as e:
                print(f"Error getting system stats: {e}")
                # Set error state
                for var in [self.cpu_var, self.mem_var, self.disk_var]:
                    var.set("N/A")
                
        except Exception as e:
            print(f"Error updating system status: {e}")
            import traceback
            traceback.print_exc()
    
    def _animate_progress(self, progress_bar, start, end, duration=500):
        """Animate a progress bar from start to end value"""
        steps = 10
        delay = duration // steps
        delta = (end - start) / steps
        
        def update(step=0):
            if step <= steps:
                value = start + (delta * step)
                progress_bar['value'] = value
                
                # Update color based on value
                if value > 90:
                    color = '#e74a3b'  # Red
                elif value > 70:
                    color = '#f6c23e'  # Yellow
                else:
                    color = '#1cc88a'  # Green
                
                progress_bar.configure(style=f'H.TProgressbar', length=100)
                progress_bar.style = f'H.TProgressbar'
                progress_bar['style'] = f'H.TProgressbar'
                
                # Update style
                style = ttk.Style()
                style.configure('H.TProgressbar',
                              thickness=8,
                              troughcolor='#eaecf4',
                              background=color,
                              lightcolor=color,
                              darkcolor=color,
                              bordercolor='#d1d3e2',
                              troughrelief='flat',
                              relief='flat')
                
                progress_bar.after(delay, update, step + 1)
        
        update()
    
    def _update_top_sources_chart(self):
        """Update top sources chart with modern styling"""
        try:
            # Get top event sources
            sources = self.event_model.get_event_sources(limit=5)
            
            # Clear previous chart
            self.sources_ax.clear()
            
            if not sources:
                self.sources_ax.text(0.5, 0.5, 'No data available',
                                  ha='center', va='center',
                                  fontsize=10, color='gray')
                self.sources_ax.axis('off')
                self.sources_canvas.draw()
                return
                
            # Prepare data
            sources = sorted(sources, key=lambda x: x[1], reverse=True)
            labels = [s[0] for s in sources]
            counts = [s[1] for s in sources]
            
            # Create horizontal bar chart with gradient
            y_pos = range(len(labels))
            colors = ['#4e73df', '#2e59d9', '#1a3f8f', '#0d1f4b', '#060f23']
            bars = self.sources_ax.barh(y_pos, counts, color=colors[:len(labels)], height=0.6)
            
            # Add value labels inside bars
            for i, (v, bar) in enumerate(zip(counts, bars)):
                width = bar.get_width()
                label_x = width - (width * 0.05)  # Position inside bar
                if label_x < (max(counts) * 0.2):  # If bar is too small, put label outside
                    label_x = width + (max(counts) * 0.02)
                    text_color = '#2e59d9'
                else:
                    text_color = 'white'
                
                self.sources_ax.text(label_x, i, f"{v:,}",
                                  color=text_color, va='center',
                                  fontweight='bold', fontsize=9)
            
            # Configure y-axis
            self.sources_ax.set_yticks(y_pos)
            self.sources_ax.set_yticklabels(labels, fontsize=9)
            self.sources_ax.tick_params(axis='y', which='both', length=0)
            self.sources_ax.invert_yaxis()  # Highest count at top
            
            # Configure x-axis
            self.sources_ax.set_xticks([])  # Hide x-axis ticks
            self.sources_ax.set_xlim(0, max(counts) * 1.2)  # Add some padding
            
            # Remove spines
            for spine in ['top', 'right', 'bottom', 'left']:
                self.sources_ax.spines[spine].set_visible(False)
            
            # Add grid
            self.sources_ax.grid(axis='x', linestyle='--', alpha=0.3, color='#d1d3e2')
            
            # Add title
            self.sources_ax.set_title('Top Event Sources', fontsize=10, pad=10, loc='left')
            
            # Adjust layout with more padding
            self.sources_fig.tight_layout(rect=[0, 0, 1, 0.95])
            
            # Draw canvas
            self.sources_canvas.draw()
            
        except Exception as e:
            print(f"Error updating top sources chart: {e}")
            import traceback
            traceback.print_exc()
    
    def _update_recent_alerts(self):
        """Update recent alerts table"""
        try:
            # Clear existing items
            for item in self.alerts_tree.get_children():
                self.alerts_tree.delete(item)
            
            # Get recent alerts
            alerts = self.event_model.get_recent_alerts(limit=10)
            
            # Add to treeview
            for alert in alerts:
                # alert format: (id, timestamp, source, event_type, severity, description, ...)
                severity = alert[4] if len(alert) > 4 else 'N/A'
                
                # Determine row color based on severity
                tag = ''
                if 'critical' in str(severity).lower():
                    tag = 'critical'
                elif 'warning' in str(severity).lower():
                    tag = 'warning'
                
                # Insert item with appropriate tags
                self.alerts_tree.insert('', 'end', values=(
                    alert[1].strftime('%Y-%m-%d %H:%M:%S') if len(alert) > 1 else 'N/A',  # timestamp
                    alert[2] if len(alert) > 2 else 'N/A',  # source
                    alert[3] if len(alert) > 3 else 'N/A',  # event_type
                    severity,
                    alert[5] if len(alert) > 5 else 'N/A'   # description
                ), tags=(tag,))
            
            # Configure tag styles
            self.alerts_tree.tag_configure('critical', background='#ffebee')
            self.alerts_tree.tag_configure('warning', background='#fff8e1')
            
        except Exception as e:
            print(f"Error updating recent alerts: {e}")