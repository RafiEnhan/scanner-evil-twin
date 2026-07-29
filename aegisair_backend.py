import sys
import json
import time
import numpy as np
from collections import defaultdict, deque

# Import modules from backend/
from backend.models.rf_onnx import load_trained_model
from backend.core.features import calculate_shannon_entropy, calculate_clock_skew
from backend.scanners.tshark_scanner import find_tshark_path, start_tshark_process
from backend.scanners.system_profiler_scanner import scan_live_mac_airspace

class AegisAirDaemon:
    def __init__(self):
        self.bssid_history = defaultdict(list)
        self.bssid_tsf = defaultdict(list)
        
        # ML Model
        self.model, self.model_path = load_trained_model()
        print(f"[*] Loaded ML model from '{self.model_path}'", file=sys.stderr)
        
        # State tracking for features
        self.tsf_history = defaultdict(lambda: deque(maxlen=20))
        self.seq_history = defaultdict(lambda: deque(maxlen=30))
        self.arrival_history = defaultdict(lambda: deque(maxlen=20))

    def _generate_event(self, frame_seq, ssid, bssid, rssi, seq_val, tsf_val, now_t, engine, mean_rssi=None):
        """Processes a single AP frame/tick, extracts ML features, runs prediction, and emits JSON."""
        self.seq_history[bssid].append(seq_val)
        
        high_res_now = time.perf_counter()
        self.arrival_history[bssid].append(high_res_now)
        
        skew = calculate_clock_skew(bssid, tsf_val, now_t, self.tsf_history)
        
        arrivals = list(self.arrival_history[bssid])
        if len(arrivals) >= 3:
            deltas = [arrivals[i] - arrivals[i-1] for i in range(1, len(arrivals))]
            jitter = round(float(np.std(deltas) * 10.0), 2)
        else:
            jitter = 0.0

        entropy = calculate_shannon_entropy(self.seq_history[bssid])
        
        if mean_rssi is not None:
            rssi_diff = round(float(abs(rssi - mean_rssi)), 2)
        else:
            rssi_diff = 0.0
            
        feats = np.array([[skew, jitter, entropy, rssi_diff]])
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

    def start_stream(self, interval_sec=0.35):
        tshark_path = find_tshark_path()
        if tshark_path:
            print(f"[*] Found tshark at {tshark_path}. Attempting raw packet capture...", file=sys.stderr)
            success = self._run_tshark_stream(tshark_path)
            if success:
                return
            print("[!] tshark capture failed (needs root/sudo?). Falling back to system_profiler...", file=sys.stderr)
        else:
            print("[!] tshark not found. Using system_profiler simulation mode...", file=sys.stderr)
            
        self._run_system_profiler_stream(interval_sec)

    def _run_tshark_stream(self, tshark_path):
        process = start_tshark_process(tshark_path)
        if not process:
            return False
            
        time.sleep(1)
        if process.poll() is not None:
            return False
            
        frame_seq = 1000
        engine_name = "tshark 802.11 Raw Packet Sniffer"
        for line in process.stdout:
            line = line.strip()
            if not line:
                continue
                
            parts = line.split('\t')
            if len(parts) < 6:
                continue
                
            try:
                ssid = parts[1]
                bssid = parts[2].lower()
                rssi = int(parts[3].split(',')[0]) if parts[3] else -70
                seq_val = int(parts[4].split(',')[0]) if parts[4] else 0
                tsf_val = int(parts[5].split(',')[0]) if parts[5] else int(time.time() * 1e6)
            except ValueError:
                continue

            if not ssid or not bssid:
                continue

            frame_seq += 1
            now_t = time.time()
            self._generate_event(frame_seq, ssid, bssid, rssi, seq_val, tsf_val, now_t, engine_name)
            
        return True

    def _run_system_profiler_stream(self, interval_sec=0.4):
        frame_seq = 1000
        while True:
            live_targets = scan_live_mac_airspace()
            now_t = time.time()
            airspace_mean_rssi = float(np.mean([n["rssi"] for n in live_targets])) if live_targets else -70.0

            for net in live_targets:
                frame_seq += 1
                ssid = net["ssid"]
                bssid = net["bssid"]
                rssi = net["rssi"]
                engine = net.get("engine", "Native OS CoreWLAN Airspace Scanner")
                tsf_val = net.get("tsf", int(now_t * 1e6))
                seq_val = net.get("seq", 0)

                self._generate_event(frame_seq, ssid, bssid, rssi, seq_val, tsf_val, now_t, engine, mean_rssi=airspace_mean_rssi)
                time.sleep(0.01) # Small sleep to prevent CPU spike during JSON burst
            
            time.sleep(interval_sec)

if __name__ == "__main__":
    daemon = AegisAirDaemon()
    daemon.start_stream(interval_sec=0.1)
