import os
import sys
import time
import subprocess
import threading

def find_tshark_path():
    """
    Mencari binary tshark, dengan prioritas: bundled di folder proyek,
    lalu PATH sistem, lalu lokasi instalasi umum Wireshark.

    Returns:
        str | None: Path absolut ke tshark binary, atau None jika tidak ditemukan.
    """
    base_dir = getattr(sys, '_MEIPASS', os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    if sys.platform == "win32":
        bundled_paths = [
            os.path.join(base_dir, "bin", "tshark", "tshark.exe"),
            os.path.join(base_dir, "bin", "tshark.exe"),
            os.path.join(base_dir, "tools", "tshark", "tshark.exe"),
            os.path.join(base_dir, "tshark", "tshark.exe"),
        ]
        for bp in bundled_paths:
            if os.path.isfile(bp):
                return bp
    else:
        bundled_paths = [
            os.path.join(base_dir, "bin", "tshark", "tshark"),
        ]
        for bp in bundled_paths:
            if os.path.isfile(bp) and not bp.endswith('.exe'):
                return bp

    try:
        which_cmd = "where" if sys.platform == "win32" else "which"
        res = subprocess.run([which_cmd, "tshark"], capture_output=True, text=True)
        if res.returncode == 0 and res.stdout.strip():
            first_line = res.stdout.strip().split('\n')[0].strip()
            if os.path.isfile(first_line):
                return first_line
    except Exception:
        pass

    common_paths = [
        "C:\\Program Files\\Wireshark\\tshark.exe",
        "C:\\Program Files (x86)\\Wireshark\\tshark.exe",
        "/Applications/Wireshark.app/Contents/MacOS/tshark",
        "/opt/homebrew/bin/tshark",
        "/usr/local/bin/tshark",
        "/usr/bin/tshark",
    ]
    for p in common_paths:
        if os.path.isfile(p):
            return p
    return None

def find_wlan_helper():
    """
    Mencari WlanHelper.exe milik Npcap untuk kontrol Monitor Mode di Windows.

    Returns:
        str | None: Path absolut ke WlanHelper.exe, atau None jika tidak ditemukan
                    atau platform bukan Windows.
    """
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
    """
    Menjalankan WlanHelper.exe dengan argumen tertentu. Mengirim newline ke stdin
    untuk melewati prompt interaktif yang muncul di beberapa versi Npcap.

    Args:
        wlan_helper_path (str): Path absolut ke WlanHelper.exe.
        args (list[str]): Daftar argumen CLI yang akan diteruskan ke WlanHelper.

    Returns:
        subprocess.CompletedProcess | None: Hasil proses, atau None jika gagal dijalankan.
    """
    cmd = [wlan_helper_path] + args
    try:
        res = subprocess.run(cmd, input="\n", capture_output=True, text=True, timeout=5)
        return res
    except Exception:
        return None

def get_wlan_interface_guid(wlan_helper_path):
    """
    Mengambil GUID interface Wi-Fi dari output WlanHelper.exe -i.
    GUID diidentifikasi dari string berformat 36 karakter dengan 4 tanda hubung.

    Args:
        wlan_helper_path (str): Path absolut ke WlanHelper.exe.

    Returns:
        str | None: GUID interface Wi-Fi (misal: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'),
                    atau None jika tidak ditemukan.
    """
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
    """
    Mengaktifkan Monitor Mode pada interface Wi-Fi via WlanHelper.exe,
    lalu memverifikasi hasilnya dengan query ulang mode aktif.

    Args:
        wlan_helper_path (str): Path absolut ke WlanHelper.exe.
        guid (str): GUID interface Wi-Fi target.

    Returns:
        tuple[bool, str]: (True, 'Success') jika berhasil, atau
                          (False, pesan_error) jika gagal.
    """
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
    """
    Mengembalikan interface Wi-Fi dari Monitor Mode ke Managed Mode.

    Args:
        wlan_helper_path (str): Path absolut ke WlanHelper.exe.
        guid (str): GUID interface Wi-Fi target.
    """
    run_wlan_helper(wlan_helper_path, [guid, "mode", "managed"])

def start_channel_hopper(wlan_helper_path, guid, channels=None, interval_sec=0.25):
    """
    Menjalankan daemon thread yang berpindah channel Wi-Fi secara berulang
    agar capture mencakup seluruh spektrum 2.4 GHz.

    Args:
        wlan_helper_path (str): Path absolut ke WlanHelper.exe.
        guid (str): GUID interface Wi-Fi target.
        channels (list[int] | None): Daftar channel yang akan di-hop.
                                     Default: channel 1–13.
        interval_sec (float): Jeda antar perpindahan channel dalam detik. Default: 0.25.

    Returns:
        threading.Thread: Daemon thread yang sedang berjalan.
    """
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
    """
    Mendeteksi nama atau indeks interface Wi-Fi yang tersedia untuk capture tshark.
    Di Windows, memilih interface berlabel '(Wi-Fi)' atau '(Wireless)' dari output tshark -D.

    Args:
        tshark_path (str): Path absolut ke tshark binary.

    Returns:
        str: Nama atau indeks interface (misal: 'en0', 'wlan0', atau '1').
             Fallback ke '5' jika deteksi otomatis di Windows gagal.
    """
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
    """
    Memulai proses tshark untuk capture paket 802.11 secara real-time.
    Di Windows, mencoba mengaktifkan Monitor Mode via WlanHelper sebelum capture.
    Di macOS, menambahkan flag monitor mode (-I) dan filter beacon frame.

    Args:
        tshark_path (str): Path absolut ke tshark binary.

    Returns:
        subprocess.Popen | None: Objek proses tshark yang sedang berjalan,
                                 atau None jika gagal diluncurkan.
    """
    interface = detect_wifi_interface(tshark_path)

    # Aktifkan Monitor Mode via WlanHelper jika di Windows
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

    # Filter hanya beacon frame (subtype 8) di macOS dengan monitor mode aktif
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
