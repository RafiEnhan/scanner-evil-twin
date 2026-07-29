import sys
import time
import subprocess
import hashlib
from collections import defaultdict

def scan_live_mac_airspace():
    """Native 802.11 Airspace Scan Engine supporting Windows (netsh) and macOS (system_profiler)."""
    raw_networks = []

    if sys.platform == "win32":
        try:
            res = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"], capture_output=True, text=True, timeout=5, encoding='utf-8', errors='ignore')
            lines = res.stdout.split('\n')
            current_ssid = None
            current_net = None

            for line in lines:
                s = line.strip()
                if s.startswith("SSID "):
                    parts = s.split(":", 1)
                    if len(parts) > 1:
                        current_ssid = parts[1].strip()
                elif s.startswith("BSSID "):
                    parts = s.split(":", 1)
                    if len(parts) > 1:
                        bssid_val = parts[1].strip()
                        if current_ssid:
                            current_net = {
                                "ssid": current_ssid,
                                "bssid": bssid_val.lower(),
                                "rssi": -70,
                                "channel": "6"
                            }
                            raw_networks.append(current_net)
                elif current_net and "Signal" in s:
                    parts = s.split(":", 1)
                    if len(parts) > 1:
                        try:
                            sig_pct = int(parts[1].replace("%", "").strip())
                            rssi_val = int((sig_pct / 2.0) - 100)
                            current_net["rssi"] = rssi_val
                        except Exception:
                            pass
                elif current_net and "Channel" in s:
                    parts = s.split(":", 1)
                    if len(parts) > 1:
                        current_net["channel"] = parts[1].strip()
        except Exception:
            pass
    else:
        try:
            res = subprocess.run(["system_profiler", "SPAirPortDataType"], capture_output=True, text=True, timeout=5)
            lines = res.stdout.split('\n')
            current_net = None
            in_section = False

            for line in lines:
                s = line.strip()
                if "Current Network Information:" in line or "Other Local Wi-Fi Networks:" in line:
                    in_section = True
                elif in_section and s.endswith(":") and not any(k in s for k in ["PHY", "Security", "Signal", "Interfaces", "awdl0", "en0", "CoreWLAN", "Network Type"]):
                    ssid = s[:-1].strip()
                    if ssid and len(ssid) > 1:
                        current_net = {"ssid": ssid, "rssi": -70, "channel": "6"}
                        raw_networks.append(current_net)
                elif current_net and ":" in s:
                    parts = s.split(":", 1)
                    k = parts[0].strip()
                    v = parts[1].strip()
                    if k == "Signal / Noise":
                        try:
                            rssi_val = int(v.split('/')[0].replace('dBm', '').strip())
                            current_net["rssi"] = rssi_val
                        except Exception:
                            pass
                    elif k == "Channel":
                        current_net["channel"] = v.split(' ')[0]
        except Exception:
            pass

    sorted_networks = sorted(raw_networks, key=lambda x: (x.get("ssid", ""), -x.get("rssi", -100)))
    ssid_counters = defaultdict(int)

    targets = []
    for net in sorted_networks:
        ssid = net["ssid"]
        ssid_counters[ssid] += 1
        cnt = ssid_counters[ssid]
        
        if "bssid" not in net or not net["bssid"]:
            h = hashlib.md5(f"{ssid}_ap_{cnt}".encode('utf-8')).hexdigest()
            bssid = f"{h[0:2]}:{h[2:4]}:{h[4:6]}:{h[6:8]}:{h[8:10]}:{h[10:12]}"
            net["bssid"] = bssid
        else:
            net["bssid"] = net["bssid"].lower()
        
        net["tsf"] = int(time.time() * 1e6)
        net["seq"] = 0
        net["engine"] = "Windows Netsh Native Scanner" if sys.platform == "win32" else "CoreWLAN (macOS System Profiler)"
        targets.append(net)

    return targets

