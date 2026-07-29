import os
import sys
import subprocess

def find_tshark_path():
    """Locates the tshark binary on the system or bundled inside the project folder."""
    base_dir = getattr(sys, '_MEIPASS', os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    bundled_paths = [
        os.path.join(base_dir, "bin", "tshark", "tshark.exe"),
        os.path.join(base_dir, "bin", "tshark", "tshark"),
        os.path.join(base_dir, "bin", "tshark.exe"),
        os.path.join(base_dir, "bin", "tshark"),
        os.path.join(base_dir, "tools", "tshark", "tshark.exe"),
        os.path.join(base_dir, "tshark", "tshark.exe"),
    ]

    for bp in bundled_paths:
        if os.path.exists(bp):
            return bp

    try:
        which_cmd = "where" if sys.platform == "win32" else "which"
        res = subprocess.run([which_cmd, "tshark"], capture_output=True, text=True)
        if res.returncode == 0 and res.stdout.strip():
            first_line = res.stdout.strip().split('\n')[0].strip()
            if os.path.exists(first_line):
                return first_line
    except Exception:
        pass
    
    common_paths = [
        "C:\\Program Files\\Wireshark\\tshark.exe",
        "C:\\Program Files (x86)\\Wireshark\\tshark.exe",
        "/opt/homebrew/bin/tshark",
        "/usr/local/bin/tshark",
        "/usr/bin/tshark",
        "/Applications/Wireshark.app/Contents/MacOS/tshark"
    ]
    for p in common_paths:
        if os.path.exists(p):
            return p
    return None

def detect_wifi_interface(tshark_path):
    """Dynamically detects the Wi-Fi interface name/index for Tshark capture."""
    if sys.platform == "darwin":
        return "en0"
    elif sys.platform == "win32":
        try:
            res = subprocess.run([tshark_path, "-D"], capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                for line in res.stdout.split('\n'):
                    line_clean = line.strip()
                    if "(wi-fi)" in line_clean.lower() or "(wireless" in line_clean.lower():
                        parts = line_clean.split('.')
                        if len(parts) > 1 and parts[0].strip().isdigit():
                            return parts[0].strip()
        except Exception:
            pass
        return "5"
    else:
        return "wlan0"

def start_tshark_process(tshark_path):
    """Spawns a tshark subprocess for raw 802.11 packet sniffing."""
    interface = detect_wifi_interface(tshark_path)
    
    cmd = [
        tshark_path, 
        "-i", interface, 
        "-l",
        "-T", "fields",
        "-e", "frame.number",
        "-e", "wlan.ssid",
        "-e", "wlan.bssid",
        "-e", "eth.src",
        "-e", "wlan_radio.signal_dbm",
        "-e", "wlan.seq",
        "-e", "ip.id",
        "-e", "wlan.fixed.timestamp"
    ]

    
    # Filter 802.11 beacons on macOS where monitor mode is active
    if sys.platform == "darwin":
        cmd.insert(3, "-I")
        cmd.insert(4, "-Y")
        cmd.insert(5, "wlan.fc.type_subtype == 8")

    
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        return process
    except Exception as e:
        print(f"[!] Tshark execution error: {e}", file=sys.stderr)
        return None

