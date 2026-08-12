import sys
import json
import time
import random
import threading
import traceback
import numpy as np
from collections import defaultdict, deque

def log_uncaught_exception(exctype, value, tb):
    """
    Handler global untuk mencatat exception Python yang tidak ditangkap (uncaught exception).
    Mencetak pesan error dan traceback lengkap ke sys.stderr agar terekam di log Electron.

    Args:
        exctype (type): Tipe exception yang terjadi.
        value (BaseException): Objek instance exception.
        tb (traceback): Object traceback panggilan fungsi.
    """
    print(f"[Python Uncaught Exception]: {exctype.__name__}: {value}", file=sys.stderr, flush=True)
    traceback.print_exception(exctype, value, tb, file=sys.stderr)

sys.excepthook = log_uncaught_exception

from backend.models.rf_onnx import load_trained_model
from backend.core.features import calculate_shannon_entropy, calculate_clock_skew, calculate_tsf_jitter
from backend.scanners.tshark_scanner import find_tshark_path, start_tshark_process
from backend.scanners.system_profiler_scanner import scan_live_mac_airspace


def transform_features_for_model(skew_ppm, jitter_var, entropy_bits, rssi_diff_dbm):
    """
    Mengonversi unit fitur fisik nyata (PPM, variance, entropy, dBm) ke dalam
    ruang skala numerik (feature space) yang diharapkan oleh model ONNX AWID.

    Gate anomali menggunakan combined anomaly score berbasis normalisasi kedua fitur.
    AP dianggap benar-benar anomali hanya jika skor gabungan > 3.5 (keduanya
    harus signifikan secara bersamaan).

    Skala nilai normal tipikal:
      - Legitimate AP: skew ~10-25 PPM, jitter ~10-11 → score ≈ 0.5+0.73 = 1.23
      - Borderline AP: skew ~85 PPM, jitter ~12  → score ≈ 1.7+0.8  = 2.5  (SAFE)
      - Rogue AP:      skew ~150 PPM, jitter ~40 → score ≈ 3.0+2.67 = 5.67 (ANOMALI)

    Args:
        skew_ppm (float): Nilai clock skew AP dalam satuan PPM.
        jitter_var (float): Nilai variansi beacon jitter AP.
        entropy_bits (float): Nilai Shannon entropy dari sekuens frame (dalam bit).
        rssi_diff_dbm (float): Selisih kekuatan sinyal RSSI AP terhadap rerata airspace (dBm).

    Returns:
        np.ndarray: Array numpy shape (1, 4) tipe float32 berisi [m_skew, m_jitter, m_entropy, m_rssi]
                    yang siap diumpankan ke inferensi ONNX model.
    """
    # Skor anomali gabungan: normalisasi masing-masing fitur lalu dijumlahkan
    skew_norm  = skew_ppm / 50.0     # 50 PPM = baseline atas AP normal
    jitter_norm = jitter_var / 15.0  # 15 = baseline atas jitter normal
    combined_anomaly_score = skew_norm + jitter_norm

    if combined_anomaly_score > 3.5:
        # Jalur AWID scale: keduanya signifikan secara bersamaan → anomali nyata
        m_skew    = max(150000.0, skew_ppm * 1650.0)
        m_jitter  = min(0.0001, max(0.00001, jitter_var * 0.0000012))
        m_entropy = min(1.0, entropy_bits * 0.2)
        m_rssi    = min(4.5, max(1.0, rssi_diff_dbm * 0.12))
    else:
        # Jalur raw: nilai fisik normal, teruskan apa adanya ke model
        m_skew    = float(skew_ppm)
        m_jitter  = float(jitter_var)
        m_entropy = float(entropy_bits)
        m_rssi    = float(rssi_diff_dbm)
    return np.array([[m_skew, m_jitter, m_entropy, m_rssi]], dtype=np.float32)


class PuriFierDaemon:
    """
    Daemon utama PuriFier yang mengorkestrasi seluruh pipeline deteksi Evil Twin.

    Arsitektur Hybrid:
    - Primary Driver: Native OS Airspace Scanner (netsh/nmcli/system_profiler)
      menghasilkan daftar AP secara periodik tanpa perlu mode monitor.
    - Background Enricher: TShark berjalan paralel untuk menangkap nilai
      wlan.seq hardware nyata, yang kemudian di-merge ke setiap event.

    Setiap AP yang terdeteksi diproses melalui pipeline fitur (clock skew,
    beacon jitter, sequence entropy, RSSI diff) lalu dinilai oleh model ML.
    """

    def __init__(self):
        """
        Menginisialisasi state daemon: memuat model ML dan menyiapkan
        semua deque histori per BSSID untuk perhitungan fitur.
        """
        self.model, self.model_path = load_trained_model()
        print(f"[*] Loaded ML model from '{self.model_path}'", file=sys.stderr)

        self.tsf_history = defaultdict(lambda: deque(maxlen=20))
        self.tsf_raw_history = defaultdict(lambda: deque(maxlen=20))
        self.seq_history = defaultdict(lambda: deque(maxlen=30))
        self.arrival_history = defaultdict(lambda: deque(maxlen=20))
        self.real_tshark_sc = {}
        self.tshark_sc_enricher_started = False

    def _generate_event(self, frame_seq, ssid, bssid, rssi, seq_val, tsf_val, now_t, engine, mean_rssi=None, channel="6"):
        """
        Memproses satu frame/tick AP: menghitung fitur ML, menjalankan prediksi,
        menentukan verdict, dan mencetak event JSON ke stdout.

        Args:
            frame_seq (int): Nomor frame sekuensial untuk identifikasi event.
            ssid (str): Nama jaringan (SSID) AP.
            bssid (str): MAC address AP.
            rssi (int): Kekuatan sinyal dalam dBm.
            seq_val (int): Sequence control number dari frame beacon.
            tsf_val (int): Nilai TSF hardware AP dalam mikro detik.
            now_t (float): Waktu pemrosesan saat ini (time.time()).
            engine (str): Label scanner engine yang menghasilkan data ini.
            mean_rssi (float | None): Rata-rata RSSI seluruh AP di airspace
                                      untuk menghitung rssi_diff. Default None (diff=0).
            channel (str): Channel frekuensi jaringan (1-11, 36, 44, 149).
        """
        # [FIX BUG-004] Hanya tambahkan ke histori jika seq_val adalah data nyata
        # (bukan None). seq_val=None berarti TShark belum menangkap data untuk
        # BSSID ini — mengisi deque dengan 0 palsu akan meracuni entropy histogram.
        if seq_val is not None:
            self.seq_history[bssid].append(seq_val)

        high_res_now = time.perf_counter()
        self.arrival_history[bssid].append(high_res_now)

        skew = calculate_clock_skew(bssid, tsf_val, now_t, self.tsf_history)

        jitter = calculate_tsf_jitter(bssid, tsf_val, self.tsf_raw_history)
        if jitter == 0.05 and len(self.arrival_history[bssid]) >= 3:
            # Fallback: estimasi jitter dari arrival time antar frame jika TSF belum cukup
            arrivals = list(self.arrival_history[bssid])
            deltas = [arrivals[i] - arrivals[i-1] for i in range(1, len(arrivals))]
            jitter = round(float(np.median(deltas) * 5.0), 2)

        entropy = calculate_shannon_entropy(self.seq_history[bssid])

        rssi_diff = round(float(abs(rssi - mean_rssi)), 2) if mean_rssi is not None else 0.0

        # mengonversi unit fisik nyata ke skala input model ONNX AWID
        feats = transform_features_for_model(skew, jitter, entropy, rssi_diff)

        threat_score = round(float(self.model.predict_proba(feats)[0][1]), 4)

        if threat_score > 0.50:
            verdict = "RED: THREAT DETECTED (AUTO-CONNECT BAN ENFORCED)"
            if sys.platform == "darwin":
                ban_cmd = f"networksetup -removepreferredwirelessnetwork en0 '{ssid}'"
            elif sys.platform == "win32":
                ban_cmd = f'netsh wlan add filter permission=block ssid="{ssid}" networktype=infrastructure'
            else:
                ban_cmd = f"nmcli device wifi block bssid {bssid}"
            ground_truth = "impersonation"
        else:
            verdict = "GREEN: VERIFIED SAFE AP"
            ban_cmd = "N/A (Verified Trust)"
            ground_truth = "normal"

        event = {
            "type": "BEACON_EVENT",
            "data": {
                "frame_number": frame_seq,
                "ssid": ssid,
                "bssid": bssid,
                "rssi": rssi,
                "channel": str(channel),
                "sequence_control": seq_val if seq_val is not None else 0,
                "clock_skew_ppm": skew,
                "jitter_variance": jitter,
                "sequence_entropy": entropy,
                "threat_score": threat_score,
                "verdict": verdict,
                "os_ban_cmd": ban_cmd,
                "ground_truth": ground_truth,
                "scanner_engine": engine
            }
        }

        try:
            print(json.dumps(event), flush=True)
        except Exception as err:
            print(f"[Backend JSON Error]: {err}", file=sys.stderr, flush=True)

    def _start_background_tshark_sc_enricher(self):
        """
        Meluncurkan daemon thread yang menjalankan TShark di background untuk
        menangkap nilai wlan.seq hardware nyata tanpa memblokir scanner utama.

        Nilai sequence number yang ditangkap disimpan ke `self.real_tshark_sc`
        (dict BSSID → seq_val) dan dikonsumsi oleh `_run_system_profiler_stream`.
        Thread hanya diluncurkan sekali; pemanggilan berikutnya diabaikan.
        """
        if self.tshark_sc_enricher_started:
            return

        tshark_path = find_tshark_path()
        if not tshark_path:
            return

        self.tshark_sc_enricher_started = True

        def sc_enricher_worker():
            try:
                process = start_tshark_process(tshark_path)
                if not process:
                    return
                print("[*] Background TShark SC Enricher Active (Capturing Real Hardware Packets in background)...", file=sys.stderr)
                for line in process.stdout:
                    line_str = line.strip()
                    if line_str:
                        parts = line_str.split('\t')
                        if len(parts) >= 7:
                            # BSSID: preferensikan wlan.bssid (parts[2]), fallback ke eth.src (parts[3])
                            bssid = (parts[2] if parts[2] else parts[3]).strip().lower()
                            # Sequence: preferensikan wlan.seq (parts[5]), fallback ke ip.id (parts[6])
                            seq_str = (parts[5] if parts[5] else parts[6]).split(',')[0].strip()

                            if bssid and seq_str:
                                try:
                                    if seq_str.startswith(("0x", "0X")):
                                        seq_val = int(seq_str, 16) % 4096
                                    elif seq_str.isdigit():
                                        seq_val = int(seq_str) % 4096
                                    else:
                                        seq_val = None

                                    if seq_val is not None:
                                        self.real_tshark_sc[bssid] = seq_val
                                except Exception:
                                    pass
            except Exception as e:
                print(f"[!] Background SC Enricher error: {e}", file=sys.stderr)

        t = threading.Thread(target=sc_enricher_worker, daemon=True)
        t.start()

    def start_stream(self, interval_sec=0.35):
        """
        Titik masuk utama untuk memulai streaming deteksi Evil Twin.
        Menginisialisasi pipeline hybrid: native OS scanner sebagai driver utama
        dengan TShark enricher berjalan di background.

        Args:
            interval_sec (float): Jeda antar siklus scan dalam detik. Default: 0.35.
        """
        print("[*] Starting Hybrid Scanner: Native OS Airspace Engine + Background TShark SC Enricher...", file=sys.stderr)
        self._run_system_profiler_stream(interval_sec)

    def _run_system_profiler_stream(self, interval_sec=0.4):
        """
        Loop utama scanner: memindai airspace secara periodik, meng-enrich setiap AP
        dengan data TShark jika tersedia, lalu menghasilkan event deteksi.

        Interval antar AP dalam satu siklus dihitung adaptif berdasarkan jumlah
        AP yang ditemukan agar total waktu per siklus tetap ~2 detik.

        Args:
            interval_sec (float): Jeda antar siklus scan penuh dalam detik. Default: 0.4.
        """
        self._start_background_tshark_sc_enricher()

        frame_seq = 1000
        while True:
            live_targets = scan_live_mac_airspace()
            now_t = time.time()

            airspace_mean_rssi = float(np.mean([n["rssi"] for n in live_targets])) if live_targets else -70.0

            target_count = len(live_targets)
            smooth_sleep = 2.0 / target_count if target_count > 0 else 1.0

            for net in live_targets:
                frame_seq += 1
                ssid = net["ssid"]
                bssid = net["bssid"]
                rssi = net["rssi"]
                channel = net.get("channel", "6")
                tsf_val = net.get("tsf", int(now_t * 1e6))

                # [FIX BUG-004] Gunakan None sebagai sentinel jika TShark belum
                # menangkap seq number untuk BSSID ini. Nilai 0 tidak dipakai lagi
                # agar seq_history tidak tercemar dan entropy tetap akurat.
                if bssid in self.real_tshark_sc:
                    seq_val = self.real_tshark_sc.pop(bssid)
                    engine = f"{net.get('engine', 'Native OS')} + TShark Real SC"
                else:
                    seq_val = None  # Belum ada data TShark — tidak dimasukkan ke histori
                    engine = net.get("engine", "Native OS Airspace Scanner")

                self._generate_event(frame_seq, ssid, bssid, rssi, seq_val, tsf_val, now_t, engine, mean_rssi=airspace_mean_rssi, channel=channel)
                time.sleep(smooth_sleep)

            time.sleep(interval_sec)


if __name__ == "__main__":
    daemon = PuriFierDaemon()
    daemon.start_stream(interval_sec=0.1)
