import os
import sys
import subprocess

def find_tshark_path():
    """Locates the tshark binary on the system."""
    try:
        res = subprocess.run(["which", "tshark"], capture_output=True, text=True)
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
    except Exception:
        pass
    
    common_paths = [
        "/opt/homebrew/bin/tshark",
        "/usr/local/bin/tshark",
        "/usr/bin/tshark",
        "C:\\Program Files\\Wireshark\\tshark.exe",
        "/Applications/Wireshark.app/Contents/MacOS/tshark"
    ]
    for p in common_paths:
        if os.path.exists(p):
            return p
    return None

def start_tshark_process(tshark_path):
    """Spawns a tshark subprocess for raw 802.11 packet sniffing."""
    interface = "en0" if sys.platform == "darwin" else "wlan0"
    cmd = [
        tshark_path, 
        "-i", interface, 
        "-I", 
        "-l",
        "-Y", "wlan.fc.type_subtype == 8", # Beacons
        "-T", "fields",
        "-e", "frame.number",
        "-e", "wlan.ssid",
        "-e", "wlan.bssid",
        "-e", "wlan_radio.signal_dbm",
        "-e", "wlan.seq",
        "-e", "wlan_mgt.fixed.timestamp"
    ]
    
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        return process
    except Exception as e:
        print(f"[!] Tshark execution error: {e}", file=sys.stderr)
        return None
