import os
import sys
import time
import subprocess
import threading

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

def find_wlan_helper():
    """Locates WlanHelper.exe on Windows for Npcap Monitor Mode control."""
    if sys.platform != "win32":
        return None
        
    candidates = [
        r"C:\Windows\System32\WlanHelper.exe",
        r"C:\Program Files\Npcap\WlanHelper.exe",
        r"C:\Program Files (x86)\Npcap\WlanHelper.exe",
        r"C:\Program Files\Wireshark\WlanHelper.exe",
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
            
    try:
        res = subprocess.run(["where", "WlanHelper.exe"], capture_output=True, text=True)
        if res.returncode == 0 and res.stdout.strip():
            first_line = res.stdout.strip().splitlines()[0].strip()
            if os.path.exists(first_line):
                return first_line
    except Exception:
        pass
    return None

def run_wlan_helper(wlan_helper_path, args):
    """Executes WlanHelper.exe cleanly by piping a newline to bypass keypress prompts."""
    cmd = [wlan_helper_path] + args
    try:
        res = subprocess.run(cmd, input="\n", capture_output=True, text=True, timeout=5)
        return res
    except Exception:
        return None

def get_wlan_interface_guid(wlan_helper_path):
    """Retrieves the Wi-Fi interface GUID using WlanHelper.exe -i."""
    res = run_wlan_helper(wlan_helper_path, ["-i"])
    if not res or not res.stdout:
        return None
        
    lines = [line.strip() for line in res.stdout.splitlines() if line.strip() and "press any key" not in line.lower() and "interactive" not in line.lower()]
    for line in lines:
        parts = line.split()
        for p in parts:
            p_clean = p.strip(".:,;()[]")
            if len(p_clean) == 36 and p_clean.count("-") == 4:
                return p_clean
    return None

def enable_windows_monitor_mode(wlan_helper_path, guid):
    """Attempts to set the Wi-Fi interface to Monitor Mode via WlanHelper and returns exact output message."""
    res = run_wlan_helper(wlan_helper_path, [guid, "mode", "monitor"])
    if res:
        out_msg = (res.stdout or "") + (res.stderr or "")
        out_msg_clean = out_msg.replace("Press any key to continue . . .", "").strip()
        if "error" not in out_msg_clean.lower() and "failure" not in out_msg_clean.lower():
            res_chk = run_wlan_helper(wlan_helper_path, [guid, "mode"])
            if res_chk and "monitor" in res_chk.stdout.lower():
                return True, "Success"
        return False, out_msg_clean if out_msg_clean else "Unknown failure from WlanHelper"
    return False, "Failed to execute WlanHelper.exe"

def restore_windows_managed_mode(wlan_helper_path, guid):
    """Restores the Wi-Fi interface back to Managed Mode."""
    run_wlan_helper(wlan_helper_path, [guid, "mode", "managed"])

def start_channel_hopper(wlan_helper_path, guid, channels=None, interval_sec=0.25):
    """Spawns a daemon thread to hop channels continuously in Monitor Mode."""
    if channels is None:
        channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        
    def hopper_worker():
        while True:
            for ch in channels:
                run_wlan_helper(wlan_helper_path, [guid, "channel", str(ch)])
                time.sleep(interval_sec)

    t = threading.Thread(target=hopper_worker, daemon=True)
    t.start()
    return t

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
    
    # Attempt WlanHelper Monitor Mode on Windows if Admin
    if sys.platform == "win32":
        wlan_helper = find_wlan_helper()
        if wlan_helper:
            guid = get_wlan_interface_guid(wlan_helper)
            if guid:
                print(f"[*] Found Windows Wi-Fi GUID: {guid}", file=sys.stderr)
                success, err_reason = enable_windows_monitor_mode(wlan_helper, guid)
                if success:
                    print(f"[+] SUCCESS: Enabled WlanHelper Monitor Mode on GUID {guid}!", file=sys.stderr)
                    interface = f"\\Device\\NPF_{{{guid}}}"
                    start_channel_hopper(wlan_helper, guid)
                else:
                    print(f"[!] WlanHelper Monitor Mode failed on GUID {guid}:", file=sys.stderr)
                    if err_reason:
                        for err_line in err_reason.splitlines():
                            if err_line.strip():
                                print(f"    -> {err_line.strip()}", file=sys.stderr)
                    print(f"[*] Falling back to standard interface capture.", file=sys.stderr)

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
