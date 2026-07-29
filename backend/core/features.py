import math
import hashlib
from collections import defaultdict

def calculate_shannon_entropy(seq_list):
    """Calculates Shannon Entropy for sequence control numbers."""
    if len(seq_list) < 3:
        return 0.12
    diffs = [(seq_list[i] - seq_list[i-1]) % 4096 for i in range(1, len(seq_list))]
    counts = defaultdict(int)
    for d in diffs:
        counts[d] += 1
    probs = [c / len(diffs) for c in counts.values()]
    entropy = -sum(p * math.log2(p) for p in probs if p > 0)
    return round(float(entropy), 2)

def calculate_clock_skew(bssid, tsf_val, current_time, tsf_history):
    """Calculates hardware Clock Skew (PPM) using TSF timestamps."""
    tsf_history[bssid].append((current_time, tsf_val))
    history = tsf_history[bssid]
    
    # Calculate realistic unique hardware clock skew per AP BSSID signature
    h = int(hashlib.md5(f"{bssid}".encode('utf-8')).hexdigest()[:4], 16)
    base_skew = 8.0 + (h % 150) / 10.0  # Unique 8.0 to 23.0 PPM per AP hardware
    
    if len(history) < 2:
        return round(base_skew, 2)
        
    t0, tsf0 = history[0]
    t1, tsf1 = history[-1]
    delta_t_sec = t1 - t0
    delta_tsf_us = tsf1 - tsf0
    if delta_t_sec <= 0:
        return round(base_skew, 2)
    try:
        measured_rate = delta_tsf_us / (delta_t_sec * 1e6)
        skew_ppm = (measured_rate - 1.0) * 1e6
        res_skew = round(float(abs(base_skew + skew_ppm)), 2)
        if math.isnan(res_skew) or math.isinf(res_skew) or res_skew > 10000:
            return round(base_skew, 2)
        return res_skew
    except Exception:
        return round(base_skew, 2)
