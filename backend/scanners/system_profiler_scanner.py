import sys
import re
import time
import subprocess
import hashlib
from collections import defaultdict

def scan_live_mac_airspace():
    """
    Memindai jaringan Wi-Fi aktif di sekitar perangkat menggunakan tool native OS.
    Mendukung Windows (netsh), Linux (nmcli), dan macOS (system_profiler).

    Sinyal dalam persentase (Windows/Linux) dikonversi ke estimasi dBm
    menggunakan formula: rssi = (pct / 2) - 100.
    BSSID yang tidak tersedia akan di-generate secara deterministik via MD5.

    Returns:
        list[dict]: Daftar jaringan yang ditemukan. Setiap entry berisi:
            - ssid (str): Nama jaringan.
            - bssid (str): MAC address AP dalam format lowercase.
            - rssi (int): Kekuatan sinyal dalam dBm.
            - channel (str): Channel Wi-Fi.
            - tsf (int): Timestamp dalam mikro detik (time.time * 1e6).
            - seq (int): Sequence number, selalu 0 dari scanner ini.
            - engine (str): Label scanner engine yang digunakan.
    """
    raw_networks = []

    if sys.platform == "win32":
        try:
            res = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                capture_output=True, text=True, timeout=5, encoding='utf-8', errors='ignore'
            )
            lines = res.stdout.split('\n')
            current_ssid = None
            current_net = None

            for line in lines:
                s = line.strip()
                if s.startswith("SSID "):
                    parts = s.split(":", 1)
                    if len(parts) > 1:
                        current_ssid = parts[1].strip() or "Hidden Network"
                elif s.startswith("BSSID "):
                    parts = s.split(":", 1)
                    if len(parts) > 1:
                        bssid_val = parts[1].strip()
                        if current_ssid is not None:
                            current_net = {
                                "ssid": current_ssid or "Hidden Network",
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
                elif current_net and s.startswith("Channel ") and ":" in s:
                    parts = s.split(":", 1)
                    if len(parts) > 1:
                        chan_val = parts[1].strip()
                        if chan_val.isdigit():
                            current_net["channel"] = chan_val
        except Exception:
            pass

    elif sys.platform.startswith("linux"):
        try:
            res = subprocess.run(
                ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,CHAN", "device", "wifi", "list"],
                capture_output=True, text=True, timeout=5, encoding='utf-8', errors='ignore'
            )
            lines = res.stdout.split('\n')
            for line in lines:
                s = line.strip()
                if not s:
                    continue

                parts = re.split(r'(?<!\\):', s)

                if len(parts) >= 4:
                    # Kembalikan escaped colon di SSID menjadi ':' biasa
                    ssid = parts[0].replace('\\:', ':').strip() or "Hidden Network"

                    # BSSID selalu terdiri dari 6 oktet hex di posisi parts[1:7]
                    if len(parts) >= 7:
                        bssid = ":".join(p.strip() for p in parts[1:7]).lower()
                    else:
                        bssid = parts[1].strip().lower()

                    try:
                        sig_pct = int(parts[-2].strip())
                        rssi_val = int((sig_pct / 2.0) - 100)
                    except Exception:
                        rssi_val = -70
                    chan = parts[-1].strip()
                    raw_networks.append({
                        "ssid": ssid,
                        "bssid": bssid,
                        "rssi": rssi_val,
                        "channel": chan
                    })
        except Exception:
            pass

    else:
        # macOS: parsing output system_profiler SPAirPortDataType
        try:
            res = subprocess.run(
                ["system_profiler", "SPAirPortDataType"],
                capture_output=True, text=True, timeout=5
            )
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

    # Urutkan per SSID lalu RSSI terkuat, lalu normalisasi BSSID & tambahkan metadata
    sorted_networks = sorted(raw_networks, key=lambda x: (x.get("ssid", ""), -x.get("rssi", -100)))
    ssid_counters = defaultdict(int)

    targets = []
    for net in sorted_networks:
        ssid = net["ssid"]
        ssid_counters[ssid] += 1
        cnt = ssid_counters[ssid]

        if "bssid" not in net or not net["bssid"]:
            # Generate BSSID deterministik via MD5 jika tidak tersedia
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
