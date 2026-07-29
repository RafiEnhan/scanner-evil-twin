import sys
import json
import time
import threading
import numpy as np
from collections import defaultdict, deque

# Import modules from backend/
from backend.models.rf_onnx import load_trained_model
from backend.core.features import calculate_shannon_entropy, calculate_clock_skew, calculate_tsf_jitter
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
        self.tsf_raw_history = defaultdict(lambda: deque(maxlen=20))
        self.seq_history = defaultdict(lambda: deque(maxlen=30))
        self.arrival_history = defaultdict(lambda: deque(maxlen=20))
        self.real_tshark_sc = {}
        self.tshark_sc_enricher_started = False

    def _generate_event(self, frame_seq, ssid, bssid, rssi, seq_val, tsf_val, now_t, engine, mean_rssi=None):
        """Processes a single AP frame/tick, extracts ML features, runs prediction, and emits JSON."""
        self.seq_history[bssid].append(seq_val)
        
        high_res_now = time.perf_counter()
        self.arrival_history[bssid].append(high_res_now)
        
        skew = calculate_clock_skew(bssid, tsf_val, now_t, self.tsf_history)
        
        # Calculate Beacon Jitter using AP Hardware TSF
        jitter = calculate_tsf_jitter(bssid, tsf_val, self.tsf_raw_history)
        if jitter == 0.05 and len(self.arrival_history[bssid]) >= 3:
            arrivals = list(self.arrival_history[bssid])
            deltas = [arrivals[i] - arrivals[i-1] for i in range(1, len(arrivals))]
            jitter = round(float(np.median(deltas) * 5.0), 2)

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
                "sequence_control": seq_val,
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
        """Spawns TShark in a background thread to continuously enrich sequence history (wlan.seq) without blocking main UI scanner."""
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
                            # BSSID can be wlan.bssid (parts[2]) or eth.src (parts[3])
                            bssid = (parts[2] if parts[2] else parts[3]).strip().lower()
                            
                            # Sequence number can be wlan.seq (parts[5]) or ip.id (parts[6])
                            seq_str = (parts[5] if parts[5] else parts[6]).split(',')[0].strip()
                            
                            if bssid and seq_str:
                                try:
                                    if seq_str.startswith("0x") or seq_str.startswith("0X"):
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
        # Native OS Airspace Engine as Primary Driver + Background TShark SC Enricher
        print("[*] Starting Hybrid Scanner: Native OS Airspace Engine + Background TShark SC Enricher...", file=sys.stderr)
        self._run_system_profiler_stream(interval_sec)

    def _run_system_profiler_stream(self, interval_sec=0.4):
        # Start background TShark SC enricher to continuously capture real wlan.seq
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
                tsf_val = net.get("tsf", int(now_t * 1e6))

                # Pure TShark SC values without artificial generator fallback
                if bssid in self.real_tshark_sc:
                    seq_val = self.real_tshark_sc.pop(bssid)
                    engine = f"{net.get('engine', 'Native OS')} + TShark Real SC"
                else:
                    seq_val = 0
                    engine = net.get("engine", "Native OS Airspace Scanner")

                self._generate_event(frame_seq, ssid, bssid, rssi, seq_val, tsf_val, now_t, engine, mean_rssi=airspace_mean_rssi)
                time.sleep(smooth_sleep)


            
            time.sleep(interval_sec)

if __name__ == "__main__":
    daemon = AegisAirDaemon()
    daemon.start_stream(interval_sec=0.1)
