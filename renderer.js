document.addEventListener('DOMContentLoaded', () => {
  let totalPackets = 0;
  let safeAps = 0;
  let dosAlerts = 0;
  let threatsBanned = 0;

  const elemTotal = document.getElementById('kpi-total-packets');
  const elemSafe = document.getElementById('kpi-safe-aps');
  const elemDos = document.getElementById('kpi-dos-alerts');
  const elemBanned = document.getElementById('kpi-threats-banned');
  const elemTbody = document.getElementById('airspace-tbody');
  const elemRowCount = document.getElementById('table-row-count');
  const elemFeedContainer = document.getElementById('threat-feed-container');
  const elemBlipsLayer = document.getElementById('radar-blips-layer');
  
  const threatStatusMsg = document.getElementById('threat-status-msg');
  const cmdBox = document.getElementById('cmd-box');
  const btnForceExec = document.getElementById('btn-force-exec');

  // HEADING VECTOR DOM ELEMENTS
  const headingVal = document.getElementById('heading-val');
  const headingDistVal = document.getElementById('heading-dist-val');

  // MODAL DOM ELEMENTS
  const modalOverlay = document.getElementById('detail-modal');
  const modalCloseBtn = document.getElementById('modal-close-btn');
  const modalSsid = document.getElementById('modal-ssid');
  const modalBssid = document.getElementById('modal-bssid');
  const modalVerdict = document.getElementById('modal-verdict');
  const modalRssi = document.getElementById('modal-rssi');
  const modalRssiTrend = document.getElementById('modal-rssi-trend');
  const modalDistEst = document.getElementById('modal-dist-est');
  const modalHeadingVector = document.getElementById('modal-heading-vector');
  const modalSkew = document.getElementById('modal-skew');
  const modalJitter = document.getElementById('modal-jitter');
  const modalEntropy = document.getElementById('modal-entropy');
  const modalSeqCtrl = document.getElementById('modal-seq-ctrl');
  const modalScorePct = document.getElementById('modal-score-pct');
  const modalScoreBar = document.getElementById('modal-score-bar');
  const modalCmdText = document.getElementById('modal-cmd-text');
  const modalBtnBan = document.getElementById('modal-btn-ban');


  let activeBanCmd = "";
  const trackedBlips = new Map();
  const ssidDataMap = new Map(); // Store by SSID to strictly prevent duplicate blips for normal APs
  const rssiHistoryMap = new Map();

  if (window.aegisairAPI) {
    window.aegisairAPI.onBackendEvent((event) => {
      if (event.type === 'BEACON_EVENT') {
        processBeaconEvent(event.data);
      }
    });
  }

  function processBeaconEvent(data) {
    totalPackets++;
    elemTotal.innerText = totalPackets.toLocaleString();

    const isRed = data.verdict.includes('RED');
    const isAmber = data.verdict.includes('AMBER');
    const isGreen = data.verdict.includes('GREEN');

    // Deduplication Key: Normal APs grouped by SSID. Rogue Threat APs get unique threat keys.
    const ssidKey = data.ssid.toLowerCase().trim();
    const storageKey = isRed ? `${ssidKey}_threat_${data.bssid.toLowerCase()}` : ssidKey;

    const prevRssi = rssiHistoryMap.get(storageKey) || data.rssi;
    const deltaRssi = data.rssi - prevRssi;
    rssiHistoryMap.set(storageKey, data.rssi);

    const exp = (-30 - data.rssi) / 25.0;
    const estDistMeters = Math.max(0.5, Math.min(25.0, Math.pow(10, exp))).toFixed(1);
    data.est_dist = estDistMeters;
    data.delta_rssi = deltaRssi;

    let activeBanCmd = "";
    let activeBanSsid = "";
    let activeBanBssid = "";

    // Keep strongest / latest beacon for normal APs, separate for threats
    data.lastSeen = Date.now();
    const existingData = ssidDataMap.get(storageKey);
    if (!existingData || isRed || data.rssi > existingData.rssi) {
      ssidDataMap.set(storageKey, data);
    } else {
      existingData.lastSeen = Date.now();
    }

    if (isGreen) safeAps++;
    if (isAmber) dosAlerts++;
    if (isRed) threatsBanned++;

    elemSafe.innerText = safeAps.toLocaleString();
    elemDos.innerText = dosAlerts.toLocaleString();
    elemBanned.innerText = threatsBanned.toLocaleString();

    // 1. Airspace Table Row
    const firstRow = elemTbody.querySelector('.empty-row');
    if (firstRow) firstRow.remove();

    const tr = document.createElement('tr');
    tr.className = 'interactive-row';
    let tagClass = 'green';
    if (isAmber) tagClass = 'amber';
    if (isRed) tagClass = 'red';

    const cleanVerdict = data.verdict.replace(/[\u{1F600}-\u{1F64F}\u{1F300}-\u{1F5FF}\u{1F680}-\u{1F6FF}\u{1F1E0}-\u{1F1FF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}]/gu, '').trim();
    const scDisplay = (data.sequence_control !== undefined && data.sequence_control > 0) ? data.sequence_control : 'N/A';

    tr.innerHTML = `
      <td>#${data.frame_number}</td>
      <td><strong>${escapeHtml(data.ssid)}</strong></td>
      <td><code>${data.bssid}</code></td>
      <td>${data.rssi} dBm</td>
      <td><code>${scDisplay}</code></td>
      <td>${data.clock_skew_ppm} ppm</td>
      <td>${data.sequence_entropy}</td>
      <td><strong>${(data.threat_score * 100).toFixed(1)}%</strong></td>
      <td><span class="verdict-tag ${tagClass}">${escapeHtml(cleanVerdict)}</span></td>
      <td><code>${escapeHtml(data.os_ban_cmd)}</code></td>
    `;


    tr.addEventListener('click', () => {
      openApDetailModal(data);
    });

    elemTbody.prepend(tr);
    if (elemTbody.children.length > 50) {
      elemTbody.removeChild(elemTbody.lastChild);
    }
    elemRowCount.innerText = `${ssidDataMap.size} Unique Networks Monitored`;

    // 2. Strict SSID Anti-Collision Radar Placement (Zero Duplicate Normal Blips)
    updateStrictDeduplicatedRadarBlips();

    // 3. Log Feed
    if (isRed || isAmber) {
      addFeedItem(data, cleanVerdict, tagClass);
    }

    // 4. Active Threat Display
    if (isRed) {
      threatStatusMsg.innerHTML = `<strong class="text-red">EVIL TWIN THREAT DETECTED!</strong> BSSID: <code>${data.bssid}</code> (SSID: ${escapeHtml(data.ssid)}). ONNX Threat Score: ${(data.threat_score*100).toFixed(1)}%.`;
      cmdBox.style.display = 'flex';
      cmdBox.querySelector('code').innerText = data.os_ban_cmd;
      activeBanCmd = data.os_ban_cmd;
      activeBanSsid = data.ssid;
      activeBanBssid = data.bssid;

      if (window.aegisairAPI && data.os_ban_cmd && !data.os_ban_cmd.startsWith('N/A')) {
        window.aegisairAPI.executeOsBan(data.os_ban_cmd, { ssid: data.ssid, bssid: data.bssid });
      }
    }
  }

  btnForceExec.addEventListener('click', () => {
    if (activeBanCmd && window.aegisairAPI) {
      window.aegisairAPI.executeOsBan(activeBanCmd, { ssid: activeBanSsid, bssid: activeBanBssid }).then(res => {
        alert(res.output || "Enforcement Executed.");
      });
    }
  });

  // Cleanup stale APs every 4 seconds (remove APs not seen for > 15 seconds)
  setInterval(() => {
    const now = Date.now();
    let updated = false;
    ssidDataMap.forEach((data, key) => {
      if (now - (data.lastSeen || now) > 15000) {
        ssidDataMap.delete(key);
        const blipEl = trackedBlips.get(key);
        if (blipEl) {
          blipEl.remove();
          trackedBlips.delete(key);
        }
        updated = true;
      }
    });
    if (updated) {
      updateStrictDeduplicatedRadarBlips();
      elemRowCount.innerText = `${ssidDataMap.size} Unique Networks Monitored`;
    }
  }, 4000);

  /**
   * STRICT UNIQUE SSID RADAR PLACEMENT:
   * - Ensures exactly ONE blip per unique SSID for normal networks.
   * - Threat APs are displayed separately as RED blips.
   * - Spaced evenly across 360 degrees.
   */
  function updateStrictDeduplicatedRadarBlips() {
    const activeKeys = Array.from(ssidDataMap.keys()).sort();
    const totalAps = activeKeys.length;
    
    if (totalAps === 0) return;

    // Remove obsolete DOM blips not in current activeKeys
    trackedBlips.forEach((blipEl, key) => {
      if (!ssidDataMap.has(key)) {
        blipEl.remove();
        trackedBlips.delete(key);
      }
    });

    const angleStep = (2 * Math.PI) / totalAps;
    let closestTarget = null;
    let minDistance = 999;

    activeKeys.forEach((key, index) => {
      const data = ssidDataMap.get(key);
      if (!data) return;

      const angleRad = index * angleStep - Math.PI / 2;
      const angleDeg = Math.round((angleRad * 180 / Math.PI + 360) % 360);

      const clampedRssi = Math.max(-95, Math.min(-30, data.rssi));
      const normalizedDistance = (clampedRssi - (-30)) / ((-95) - (-30));
      const radius = 30 + normalizedDistance * 105;

      const x = 160 + radius * Math.cos(angleRad);
      const y = 160 + radius * Math.sin(angleRad);

      data.heading_angle = angleDeg;

      if (parseFloat(data.est_dist) < minDistance) {
        minDistance = parseFloat(data.est_dist);
        closestTarget = data;
      }

      let blip = trackedBlips.get(key);
      if (!blip) {
        blip = document.createElement('div');
        
        const label = document.createElement('span');
        label.className = 'blip-label';
        label.innerText = data.ssid.length > 12 ? data.ssid.substring(0, 10) + '..' : data.ssid;
        blip.appendChild(label);

        blip.addEventListener('click', (e) => {
          e.stopPropagation();
          const latestData = ssidDataMap.get(key) || data;
          openApDetailModal(latestData);
        });

        elemBlipsLayer.appendChild(blip);
        trackedBlips.set(key, blip);
      }

      let currentTagClass = 'green';
      if (data.verdict.includes('AMBER')) currentTagClass = 'amber';
      if (data.verdict.includes('RED')) currentTagClass = 'red';

      blip.className = `radar-blip ${currentTagClass}`;
      blip.style.left = `${x}px`;
      blip.style.top = `${y}px`;
    });

    // Update Heading Bar
    if (closestTarget) {
      headingDistVal.innerText = `${closestTarget.est_dist} M`;
      if (closestTarget.delta_rssi > 0) {
        headingVal.innerText = `APPROACHING ${closestTarget.ssid.toUpperCase()} (${closestTarget.heading_angle}° VECTOR)`;
        headingVal.style.color = "var(--accent-green)";
      } else if (closestTarget.delta_rssi < 0) {
        headingVal.innerText = `MOVING AWAY FROM ${closestTarget.ssid.toUpperCase()} (RECALIBRATING)`;
        headingVal.style.color = "var(--accent-amber)";
      } else {
        headingVal.innerText = `VECTOR HEADING: ${closestTarget.heading_angle}° (${closestTarget.ssid.toUpperCase()})`;
        headingVal.style.color = "var(--accent-cyan)";
      }
    }
  }

  const loggedFeedBssids = new Set();

  function addFeedItem(data, cleanVerdict, tagClass) {
    // Strictly ensure only 1 card per threat BSSID in the event log feed
    if (loggedFeedBssids.has(data.bssid)) {
      return;
    }
    loggedFeedBssids.add(data.bssid);

    const item = document.createElement('div');
    item.className = `feed-item ${tagClass}`;
    item.innerHTML = `
      <div class="feed-top">
        <span>${escapeHtml(cleanVerdict)}</span>
        <span>Score: ${(data.threat_score * 100).toFixed(1)}%</span>
      </div>
      <div class="feed-bot">
        SSID: ${escapeHtml(data.ssid)} | BSSID: ${data.bssid} | Skew: ${data.clock_skew_ppm} ppm
      </div>
    `;

    item.addEventListener('click', () => {
      openApDetailModal(data);
    });

    elemFeedContainer.prepend(item);
    if (elemFeedContainer.children.length > 20) {
      elemFeedContainer.removeChild(elemFeedContainer.lastChild);
    }
  }

  function openApDetailModal(data) {
    modalSsid.innerText = data.ssid;
    modalBssid.innerText = data.bssid;
    modalRssi.innerText = `${data.rssi} dBm`;
    
    if (data.delta_rssi > 0) {
      modalRssiTrend.innerText = "Signal Trend: Strengthening (+ RSSI)";
      modalRssiTrend.style.color = "var(--accent-green)";
    } else if (data.delta_rssi < 0) {
      modalRssiTrend.innerText = "Signal Trend: Weakening (- RSSI)";
      modalRssiTrend.style.color = "var(--accent-amber)";
    } else {
      modalRssiTrend.innerText = "Signal Trend: Stable";
      modalRssiTrend.style.color = "var(--text-muted)";
    }

    modalDistEst.innerText = `${data.est_dist || "2.8"} M`;
    modalHeadingVector.innerText = `${data.heading_angle || "45"}° Vector`;

    modalSkew.innerText = `${data.clock_skew_ppm} ppm`;
    modalJitter.innerText = `${data.jitter_variance}`;
    modalEntropy.innerText = `${data.sequence_entropy}`;
    if (modalSeqCtrl) {
      modalSeqCtrl.innerText = (data.sequence_control !== undefined && data.sequence_control > 0) ? data.sequence_control : 'N/A';
    }

    
    const pct = (data.threat_score * 100).toFixed(1);
    modalScorePct.innerText = `${pct}%`;
    modalScoreBar.style.width = `${Math.min(100, Math.max(2, pct))}%`;

    const isRed = data.verdict.includes('RED');
    const isAmber = data.verdict.includes('AMBER');

    if (isRed) {
      modalVerdict.innerText = "RED: THREAT DETECTED (EVIL TWIN)";
      modalVerdict.style.color = "var(--accent-red)";
      modalScoreBar.style.backgroundColor = "var(--accent-red)";
    } else if (isAmber) {
      modalVerdict.innerText = "AMBER: DOS/INJECTION WARNING";
      modalVerdict.style.color = "var(--accent-amber)";
      modalScoreBar.style.backgroundColor = "var(--accent-amber)";
    } else {
      modalVerdict.innerText = "GREEN: VERIFIED SAFE AP";
      modalVerdict.style.color = "var(--accent-green)";
      modalScoreBar.style.backgroundColor = "var(--accent-green)";
    }

    modalCmdText.innerText = data.os_ban_cmd;

    modalBtnBan.onclick = () => {
      if (data.os_ban_cmd && !data.os_ban_cmd.startsWith("N/A") && window.aegisairAPI) {
        window.aegisairAPI.executeOsBan(data.os_ban_cmd, { ssid: data.ssid, bssid: data.bssid }).then(res => {
          alert(res.output || "Enforcement Command Executed.");
        });
      } else {
        alert("Action not required for Verified Safe AP.");
      }
    };

    modalOverlay.classList.remove('hidden');
  }

  modalCloseBtn.addEventListener('click', () => {
    modalOverlay.classList.add('hidden');
  });

  modalOverlay.addEventListener('click', (e) => {
    if (e.target === modalOverlay) {
      modalOverlay.classList.add('hidden');
    }
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !modalOverlay.classList.contains('hidden')) {
      modalOverlay.classList.add('hidden');
    }
  });

  function escapeHtml(str) {
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
});
