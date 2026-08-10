import math
import hashlib
import numpy as np
from collections import defaultdict

def calculate_shannon_entropy(seq_list):
    """
    Menghitung Shannon Entropy dari daftar sequence control number 802.11.
    Entropy dihitung dari distribusi selisih antar nilai berurutan (modulo 4096),
    menghasilkan ukuran keacakan pola transmisi beacon suatu AP.

    Args:
        seq_list (list[int] | deque): Daftar sequence number yang telah dikumpulkan
                                      untuk satu BSSID tertentu.

    Returns:
        float: Nilai entropy dalam bit (dibulatkan 2 desimal).
               Mengembalikan 0.0 jika data kurang dari 2 sampel.
    """
    if len(seq_list) < 2:
        return 0.0
    diffs = [(seq_list[i] - seq_list[i-1]) % 4096 for i in range(1, len(seq_list))]
    if not diffs:
        return 0.0
    counts = defaultdict(int)
    for d in diffs:
        counts[d] += 1
    probs = [c / len(diffs) for c in counts.values()]
    entropy = -sum(p * math.log2(p) for p in probs if p > 0)
    res = round(float(entropy), 2)
    return 0.0 if abs(res) < 1e-6 else res


def calculate_clock_skew(bssid, tsf_val, current_time, tsf_history):
    """
    Menghitung Clock Skew hardware AP dalam satuan PPM (Parts Per Million)
    menggunakan timestamp TSF (Time Synchronization Function) dari beacon frame.

    Skew dasar diturunkan secara deterministik dari MD5 BSSID (rentang 8–23 PPM)
    untuk mensimulasikan variasi hardware antar perangkat. Jika histori TSF
    cukup, nilai terukur dari delta nyata ditambahkan ke skew dasar.

    Args:
        bssid (str): MAC address AP sebagai identifier unik.
        tsf_val (int): Nilai TSF terbaru dari beacon frame (dalam mikro detik).
        current_time (float): Waktu penerimaan frame (time.time()).
        tsf_history (defaultdict): Dict berisi histori (current_time, tsf_val)
                                   per BSSID untuk perhitungan delta.

    Returns:
        float: Estimasi clock skew dalam PPM (dibulatkan 2 desimal).
    """
    tsf_history[bssid].append((current_time, tsf_val))
    history = tsf_history[bssid]

    # Skew dasar deterministik per hardware AP berdasarkan hash BSSID (rentang 8.0–23.0 PPM)
    h = int(hashlib.md5(f"{bssid}".encode('utf-8')).hexdigest()[:4], 16)
    base_skew = 8.0 + (h % 150) / 10.0

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

def calculate_tsf_jitter(bssid, tsf_val, tsf_val_history):
    """
    Menghitung Beacon Jitter menggunakan timestamp TSF hardware AP secara langsung.
    Metode ini imun terhadap noise penjadwalan OS (AWDL, background scan) karena
    menggunakan clock hardware AP, bukan clock penerima.

    Jitter dihitung sebagai standar deviasi interval antar beacon (dalam detik),
    lalu dikalikan 100 untuk skala yang lebih mudah dibaca.
    Hanya interval dalam rentang valid 0.01–2.0 detik yang diperhitungkan.

    Args:
        bssid (str): MAC address AP sebagai identifier unik.
        tsf_val (int): Nilai TSF terbaru dari beacon frame (dalam mikro detik).
        tsf_val_history (defaultdict): Dict berisi histori TSF per BSSID.

    Returns:
        float: Nilai jitter (dibulatkan 2 desimal).
               Mengembalikan 0.05 sebagai default jika data belum cukup (< 3 sampel).
    """
    tsf_val_history[bssid].append(tsf_val)
    history = list(tsf_val_history[bssid])

    if len(history) < 3:
        return 0.05

    tsf_deltas = []
    for i in range(1, len(history)):
        diff = history[i] - history[i-1]
        if diff > 0:
            delta_sec = diff / 1e6  # konversi mikro detik ke detik
            # Filter interval beacon yang valid (0.01s – 2.0s)
            if 0.01 <= delta_sec <= 2.0:
                tsf_deltas.append(delta_sec)

    if len(tsf_deltas) >= 2:
        jitter_val = float(np.std(tsf_deltas) * 100.0)
        return round(float(jitter_val), 2)

    return 0.05
