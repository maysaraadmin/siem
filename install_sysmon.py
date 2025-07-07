import os
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

def download_sysmon():
    """Download Sysmon from Microsoft's official repository"""
    sysmon_url = "https://download.sysinternals.com/files/Sysmon.zip"
    temp_dir = tempfile.gettempdir()
    zip_path = os.path.join(temp_dir, "Sysmon.zip")
    
    print("Downloading Sysmon...")
    urllib.request.urlretrieve(sysmon_url, zip_path)
    
    # Extract the zip file
    import zipfile
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(temp_dir)
    
    return os.path.join(temp_dir, "Sysmon64.exe")

def install_sysmon():
    """Install and configure Sysmon with a default configuration"""
    # Check if running as administrator
    try:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("Error: This script requires administrator privileges.")
            print("Please run the script as Administrator.")
            sys.exit(1)
    except:
        print("Warning: Could not verify administrator privileges.")
    
    # Check if Sysmon is already installed
    sysmon_path = os.path.join(os.environ.get('SystemRoot', r'C:\\Windows'), 'Sysmon64.exe')
    
    if not os.path.exists(sysmon_path):
        print("Sysmon not found, downloading...")
        sysmon_path = download_sysmon()
    
    # Create a basic Sysmon configuration
    config = """<Sysmon schemaversion="4.90">
    <EventFiltering>
        <!-- Process creation -->
        <ProcessCreate onmatch="exclude">
            <Image condition="is">C:\\Windows\\Sysmon64.exe</Image>
        </ProcessCreate>
        
        <!-- Network connection -->
        <NetworkConnect onmatch="exclude">
            <Image condition="is">C:\\Windows\\System32\\svchost.exe</Image>
            <SourcePort condition="is">137</SourcePort>
            <DestinationPort condition="is">137</DestinationPort>
        </NetworkConnect>
        
        <!-- File creation time changed -->
        <FileCreateTime onmatch="exclude" />
        
        <!-- Raw access read of detected file -->
        <RawAccessRead onmatch="exclude" />
        
        <!-- Process accessing another process memory -->
        <ProcessAccess onmatch="exclude">
            <SourceImage condition="is">C:\\Windows\\system32\\wbem\\WmiPrvSE.exe</SourceImage>
            <SourceImage condition="is">C:\\Windows\\System32\\VBoxService.exe</SourceImage>
        </ProcessAccess>
    </EventFiltering>
</Sysmon>"""
    
    # Save config to a temporary file
    config_path = os.path.join(tempfile.gettempdir(), "sysmon_config.xml")
    with open(config_path, 'w') as f:
        f.write(config)
    
    # Install Sysmon with the configuration
    print("Installing Sysmon with configuration...")
    try:
        subprocess.run([sysmon_path, '-accepteula', '-i', config_path], check=True)
        print("Sysmon has been installed and configured successfully!")
    except subprocess.CalledProcessError as e:
        print(f"Error installing Sysmon: {e}")
        sys.exit(1)

if __name__ == "__main__":
    install_sysmon()
