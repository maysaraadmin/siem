import random
import time
import threading
from datetime import datetime
from typing import Optional, Dict, List
from .event import EventModel
import pythoncom
import win32evtlog
import win32con
import win32security
import os
import re

class WindowsLogCollector:
    def __init__(self, event_model: EventModel):
        self.event_model = event_model
        self.running = False
        self.threads: List[threading.Thread] = []
        self.log_handles: Dict[str, object] = {}
        
        # Define all Windows log sources we want to monitor
        self.log_sources = [
            ('Security', self._collect_security_events),
            ('System', self._collect_system_events),
            ('Application', self._collect_application_events),
            ('Microsoft-Windows-PowerShell/Operational', self._collect_powershell_events),
            ('Microsoft-Windows-TaskScheduler/Operational', self._collect_task_scheduler_events),
            ('Microsoft-Windows-Sysmon/Operational', self._collect_sysmon_events),
            ('Microsoft-Windows-Windows Defender/Operational', self._collect_defender_events),
            ('Microsoft-Windows-GroupPolicy/Operational', self._collect_gpo_events)
        ]
        
        # If domain controller, add these additional sources
        if self._is_domain_controller():
            self.log_sources.extend([
                ('Directory Service', self._collect_directory_service_events),
                ('DNS Server', self._collect_dns_events)
            ])

    def start(self):
        """Start all Windows log collection threads"""
        if self.running:
            return
            
        self.running = True
        
        # Start event log collectors
        for log_name, collector in self.log_sources:
            try:
                hand = win32evtlog.OpenEventLog(None, log_name)
                self.log_handles[log_name] = hand
                thread = threading.Thread(
                    target=collector,
                    args=(hand,),
                    daemon=True,
                    name=f"WinLog-{log_name[:10]}"
                )
                thread.start()
                self.threads.append(thread)
            except Exception as e:
                print(f"Failed to start {log_name} collector: {str(e)}")
        
        # Start additional log collectors
        self.threads.append(threading.Thread(
            target=self._collect_firewall_logs,
            daemon=True,
            name="WinLog-Firewall"
        ).start())
        
        print(f"Started {len(self.threads)} Windows log collectors")
        
    def stop(self):
        """Stop all log collection threads"""
        self.running = False
        for thread in self.threads:
            if thread and thread.is_alive():
                thread.join(timeout=2)
        
        for hand in self.log_handles.values():
            try:
                win32evtlog.CloseEventLog(hand)
            except:
                pass

    def _is_domain_controller(self):
        """Check if this system is a domain controller"""
        try:
            import win32net
            server_info = win32net.NetServerGetInfo(None, 101)
            return server_info['server_type'] & win32net.SV_TYPE_DOMAIN_CTRL
        except:
            return False

    # Individual log collectors for each source
    def _collect_security_events(self, hand):
        pythoncom.CoInitialize()
        self._collect_windows_events(
            hand,
            "Windows Security",
            self._get_security_event_map(),
            self._format_security_event
        )
        pythoncom.CoUninitialize()

    def _collect_system_events(self, hand):
        pythoncom.CoInitialize()
        self._collect_windows_events(
            hand,
            "Windows System",
            self._get_system_event_map(),
            self._format_system_event
        )
        pythoncom.CoUninitialize()

    def _collect_application_events(self, hand):
        pythoncom.CoInitialize()
        self._collect_windows_events(
            hand,
            "Windows Application",
            {},
            self._format_application_event,
            min_level=win32con.EVENTLOG_WARNING_TYPE
        )
        pythoncom.CoUninitialize()

    def _collect_powershell_events(self, hand):
        pythoncom.CoInitialize()
        self._collect_windows_events(
            hand,
            "Windows PowerShell",
            self._get_powershell_event_map(),
            self._format_powershell_event
        )
        pythoncom.CoUninitialize()

    def _collect_task_scheduler_events(self, hand):
        pythoncom.CoInitialize()
        self._collect_windows_events(
            hand,
            "Windows Task Scheduler",
            self._get_task_scheduler_event_map(),
            self._format_task_scheduler_event
        )
        pythoncom.CoUninitialize()

    def _collect_sysmon_events(self, hand):
        pythoncom.CoInitialize()
        self._collect_windows_events(
            hand,
            "Sysmon",
            self._get_sysmon_event_map(),
            self._format_sysmon_event
        )
        pythoncom.CoUninitialize()

    def _collect_defender_events(self, hand):
        pythoncom.CoInitialize()
        self._collect_windows_events(
            hand,
            "Windows Defender",
            self._get_defender_event_map(),
            self._format_defender_event
        )
        pythoncom.CoUninitialize()

    def _collect_gpo_events(self, hand):
        pythoncom.CoInitialize()
        self._collect_windows_events(
            hand,
            "Windows Group Policy",
            self._get_gpo_event_map(),
            self._format_gpo_event
        )
        pythoncom.CoUninitialize()

    def _collect_directory_service_events(self, hand):
        pythoncom.CoInitialize()
        self._collect_windows_events(
            hand,
            "Windows Directory Service",
            self._get_directory_service_event_map(),
            self._format_directory_service_event
        )
        pythoncom.CoUninitialize()

    def _collect_dns_events(self, hand):
        pythoncom.CoInitialize()
        self._collect_windows_events(
            hand,
            "Windows DNS",
            self._get_dns_event_map(),
            self._format_dns_event
        )
        pythoncom.CoUninitialize()

    def _collect_firewall_logs(self):
        pythoncom.CoInitialize()
        firewall_log_path = os.path.join(
            os.environ['SystemRoot'],
            'System32',
            'LogFiles',
            'Firewall',
            'pfirewall.log'
        )
        
        last_position = 0
        
        while self.running:
            try:
                if not os.path.exists(firewall_log_path):
                    time.sleep(30)
                    continue
                
                with open(firewall_log_path, 'r') as f:
                    f.seek(last_position)
                    for line in f:
                        self._process_firewall_log(line.strip())
                    last_position = f.tell()
                
            except Exception as e:
                print(f"Firewall log error: {str(e)}")
            
            time.sleep(10)
        
        pythoncom.CoUninitialize()

    # Base Windows Event Collector
    def _collect_windows_events(self, hand, source, event_map, formatter, min_level=None):
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        
        while self.running:
            try:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                
                if not events:
                    time.sleep(5)
                    continue
                
                for event in events:
                    if min_level and event.EventType < min_level:
                        continue
                    
                    event_id = event.EventID & 0xFFFF
                    
                    if event_id in event_map:
                        name, severity = event_map[event_id]
                    else:
                        name = f"Event ID {event_id}"
                        severity = 2  # Default medium severity
                    
                    message = formatter(event, name)
                    ip_address = self._extract_ip_from_event(event)
                    
                    self.event_model.create_event(
                        timestamp=datetime.fromtimestamp(event.TimeGenerated.timestamp()).strftime('%Y-%m-%d %H:%M:%S'),
                        source=source,
                        event_type=name,
                        severity=severity,
                        description=message,
                        ip_address=ip_address or "N/A"
                    )
                
                time.sleep(1)
                
            except Exception as e:
                print(f"Error in {source} collector: {str(e)}")
                time.sleep(10)

    # Event mapping methods
    def _get_security_event_map(self):
        return {
            4624: ("Successful Logon", 2),
            4625: ("Failed Logon", 3),
            4648: ("Logon with Explicit Credentials", 4),
            4672: ("Special Privileges Assigned", 4),
            4720: ("User Account Created", 3),
            4738: ("User Account Changed", 3),
            4740: ("User Account Locked Out", 3)
        }

    def _get_system_event_map(self):
        return {
            6005: ("System Startup", 1),
            6006: ("System Shutdown", 1),
            6008: ("Unexpected Shutdown", 3),
            7001: ("Service Start Failure", 3),
            7002: ("Service Failure", 3),
            4616: ("System Time Changed", 3)
        }

    def _get_powershell_event_map(self):
        return {
            4103: ("PowerShell Command Execution", 3),
            4104: ("PowerShell Script Block Execution", 4),
            4105: ("PowerShell Script Block Start", 2),
            4106: ("PowerShell Script Block End", 2)
        }

    def _get_task_scheduler_event_map(self):
        return {
            106: ("Scheduled Task Created", 3),
            140: ("Scheduled Task Updated", 3),
            141: ("Scheduled Task Deleted", 3),
            200: ("Scheduled Task Executed", 2)
        }

    def _get_sysmon_event_map(self):
        return {
            1: ("Process Create", 3),
            3: ("Network Connection", 3),
            6: ("Driver Loaded", 4),
            7: ("Image Loaded", 3),
            8: ("CreateRemoteThread", 4),
            10: ("Process Access", 4),
            11: ("File Create", 3),
            12: ("Registry Event", 3),
            13: ("Registry Value Set", 3),
            15: ("File Create Stream Hash", 3)
        }

    def _get_defender_event_map(self):
        return {
            1116: ("Malware Detected", 5),
            1117: ("Malware Remediated", 4),
            1118: ("Malware Allowed", 5),
            2000: ("Definition Update", 1),
            2001: ("Definition Update Failed", 3)
        }

    def _get_gpo_event_map(self):
        return {
            4000: ("GPO Processing Started", 2),
            4001: ("GPO Processing Completed", 2),
            4002: ("GPO Processing Failed", 3),
            4003: ("GPO Applied", 2),
            4004: ("GPO Not Applied", 2)
        }

    def _get_directory_service_event_map(self):
        return {
            4928: ("LDAP Bind", 2),
            4929: ("LDAP Unbind", 1),
            4768: ("Kerberos TGT Request", 2),
            4769: ("Kerberos Service Ticket Request", 2),
            4770: ("Kerberos Service Ticket Renewal", 2),
            4771: ("Kerberos Pre-Authentication Failed", 3)
        }

    def _get_dns_event_map(self):
        return {
            150: ("DNS Query", 1),
            151: ("DNS Response", 1),
            652: ("DNS Zone Transfer", 3)
        }

    # Event formatting methods
    def _format_security_event(self, event, name):
        try:
            message = f"{name}\nComputer: {event.ComputerName}\n"
            if event.StringInserts and len(event.StringInserts) > 1:
                message += f"User: {event.StringInserts[1]}\n"
            if event.StringInserts:
                message += "Details:\n" + "\n".join(f"- {i}" for i in event.StringInserts)
            return message
        except Exception as e:
            return f"{name} - Error formatting: {str(e)}"

    def _format_system_event(self, event, name):
        try:
            message = f"{name}\nComputer: {event.ComputerName}\n"
            if event.EventID in [7001, 7002] and event.StringInserts:
                message += f"Service: {event.StringInserts[0]}\n"
            if event.StringInserts:
                message += "Details: " + " | ".join(str(i) for i in event.StringInserts)
            return message
        except Exception as e:
            return f"{name} - Error formatting: {str(e)}"

    def _format_application_event(self, event, name):
        try:
            message = f"{name} (Event ID: {event.EventID & 0xFFFF})\n"
            message += f"Source: {event.SourceName}\n"
            message += f"Computer: {event.ComputerName}\n"
            if event.StringInserts:
                message += "Details: " + " | ".join(str(i) for i in event.StringInserts)
            return message
        except Exception as e:
            return f"Application Event - Error formatting: {str(e)}"

    def _format_powershell_event(self, event, name):
        try:
            message = f"{name}\nComputer: {event.ComputerName}\n"
            if event.StringInserts:
                message += "Details:\n" + "\n".join(f"- {i}" for i in event.StringInserts)
            return message
        except Exception as e:
            return f"{name} - Error formatting: {str(e)}"

    def _format_sysmon_event(self, event, name):
        try:
            message = f"{name}\nComputer: {event.ComputerName}\n"
            if event.StringInserts:
                message += "Details:\n" + "\n".join(
                    f"- Field {i}: {value}" 
                    for i, value in enumerate(event.StringInserts)
                )
            return message
        except Exception as e:
            return f"{name} - Error formatting: {str(e)}"

    def _process_firewall_log(self, line):
        if not line or line.startswith('#'):
            return
            
        parts = line.split()
        if len(parts) < 6:
            return
            
        date_time = f"{parts[0]} {parts[1]}"
        action = parts[2]
        protocol = parts[3]
        src_ip = parts[4]
        dst_ip = parts[5]
        
        severity = 3 if action in ["DROP", "BLOCK"] else 1
        
        self.event_model.create_event(
            timestamp=date_time,
            source="Windows Firewall",
            event_type=f"Firewall {action}",
            severity=severity,
            description=f"{protocol} connection from {src_ip} to {dst_ip}",
            ip_address=src_ip
        )

    def _extract_ip_from_event(self, event):
        try:
            if hasattr(event, 'EventID') and event.EventID in [4624, 4625, 4648]:
                if event.StringInserts and len(event.StringInserts) >= 19:
                    ip = event.StringInserts[18]
                    if ip and ip != '-':
                        return ip
            
            if hasattr(event, 'StringInserts'):
                for item in event.StringInserts:
                    if isinstance(item, str) and re.match(r'\d+\.\d+\.\d+\.\d+', item):
                        return item
        except:
            pass
        
        return None