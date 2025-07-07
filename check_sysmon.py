import os
import subprocess
import sys
import winreg

def is_sysmon_installed():
    """Check if Sysmon is installed"""
    try:
        # Check if Sysmon driver is installed
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                           r"SYSTEM\CurrentControlSet\Services\SysmonDrv")
        winreg.CloseKey(key)
        return True
    except WindowsError:
        return False

def is_sysmon_running():
    """Check if Sysmon service is running"""
    try:
        output = subprocess.check_output(['sc', 'query', 'Sysmon'], 
                                       stderr=subprocess.STDOUT,
                                       text=True)
        return "RUNNING" in output
    except subprocess.CalledProcessError:
        return False

def main():
    print("Checking Sysmon installation...")
    
    if not is_sysmon_installed():
        print("Sysmon is not installed.")
        print("Please run 'python install_sysmon.py' as Administrator to install Sysmon.")
        return
    
    if not is_sysmon_running():
        print("Sysmon is installed but not running.")
        print("Attempting to start Sysmon service...")
        try:
            subprocess.run(['net', 'start', 'Sysmon'], check=True)
            print("Sysmon service started successfully!")
        except subprocess.CalledProcessError as e:
            print(f"Failed to start Sysmon service: {e}")
            print("Please start the service manually or run 'net start Sysmon' as Administrator.")
            return
    else:
        print("Sysmon is installed and running.")
    
    print("\nSysmon Configuration:")
    try:
        subprocess.run([r"C:\Windows\Sysmon64.exe", '-c'], check=True)
    except FileNotFoundError:
        print("Could not find Sysmon64.exe. Make sure it's installed in the default location.")
    except subprocess.CalledProcessError as e:
        print(f"Error checking Sysmon configuration: {e}")

if __name__ == "__main__":
    main()
