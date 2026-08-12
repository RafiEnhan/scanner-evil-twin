document.addEventListener('DOMContentLoaded', () => {
  let totalPackets = 0;
  let safeAps = 0;
  let threatsBanned = 0;

  const elemTotal = document.getElementById('kpi-total-packets');
  const elemSafe = document.getElementById('kpi-safe-aps');
  const elemUniqueNetworks = document.getElementById('kpi-unique-networks');
  const elemBanned = document.getElementById('kpi-threats-banned');
  const elemTbody = document.getElementById('airspace-tbody');
  const elemRowCount = document.getElementById('table-row-count');
  const elemFeedContainer = document.getElementById('threat-feed-container');
  const elemBlipsLayer = document.getElementById('radar-blips-layer');
  const radarDistBadge = document.getElementById('radar-dist-badge');
  const trackedBlips = new Map();
  
  const cmdBox = document.getElementById('cmd-box');
  const cmdText = document.getElementById('cmd-text');
  const btnForceExec = document.getElementById('btn-force-exec');

  const themeToggleBtn = document.getElementById('theme-toggle-btn');
  const themeToggleIcon = document.getElementById('theme-toggle-icon');
  const themeToggleText = document.getElementById('theme-toggle-text');

  const channelZoomModal = document.getElementById('channel-zoom-modal');
  const channelZoomCloseBtn = document.getElementById('channel-zoom-close-btn');
  const channelZoomTitle = document.getElementById('channel-zoom-title');
  const channelZoomSubtitle = document.getElementById('channel-zoom-subtitle');
  const wideSpectrumBars = document.getElementById('wide-spectrum-bars');
  const chFilterAll = document.getElementById('ch-filter-all');
  const chFilterThreats = document.getElementById('ch-filter-threats');
  const chFilterSafe = document.getElementById('ch-filter-safe');
  const chCountAll = document.getElementById('ch-count-all');
  const chCountThreats = document.getElementById('ch-count-threats');
  const chCountSafe = document.getElementById('ch-count-safe');

  const kpiUniqueCard = document.getElementById('kpi-unique-card');
  const uniqueNetworksModal = document.getElementById('unique-networks-modal');
  const uniqueModalCloseBtn = document.getElementById('unique-modal-close-btn');
  const uniqueModalCount = document.getElementById('unique-modal-count');
  const uniqueNetworksTbody = document.getElementById('unique-networks-tbody');

  const forensicSsid = document.getElementById('forensic-ssid');
  const forensicBssid = document.getElementById('forensic-bssid');
  const forensicStatusBadge = document.getElementById('forensic-status-badge');
  const forensicThreatScore = document.getElementById('forensic-threat-score');
  const forensicEntropyBar = document.getElementById('forensic-entropy-bar');
  const forensicEntropyVal = document.getElementById('forensic-entropy-val');
  const forensicSkewVal = document.getElementById('forensic-skew-val');
  const btnIsolateAp = document.getElementById('btn-isolate-ap');

  const modalOverlay = document.getElementById('detail-modal');
  const modalCloseBtn = document.getElementById('modal-close-btn');
  const modalSsid = document.getElementById('modal-ssid');
  const modalBssid = document.getElementById('modal-bssid');
  const modalVerdict = document.getElementById('modal-verdict');
  const modalRssi = document.getElementById('modal-rssi');
  const modalSkew = document.getElementById('modal-skew');
  const modalJitter = document.getElementById('modal-jitter');
  const modalEntropy = document.getElementById('modal-entropy');
  const modalSeqCtrl = document.getElementById('modal-seq-ctrl');
  const modalScorePct = document.getElementById('modal-score-pct');
  const modalScoreBar = document.getElementById('modal-score-bar');
  const modalCmdText = document.getElementById('modal-cmd-text');
  const modalBtnBan = document.getElementById('modal-btn-ban');

  const threatAlertModal = document.getElementById('threat-alert-modal');
  const threatStackBg1 = document.getElementById('threat-stack-bg-1');
  const threatStackBg2 = document.getElementById('threat-stack-bg-2');
  const threatStackCounter = document.getElementById('threat-stack-counter');
  const threatAlertSsid = document.getElementById('threat-alert-ssid');
  const threatAlertBssid = document.getElementById('threat-alert-bssid');
  const threatAlertScore = document.getElementById('threat-alert-score');
  const threatAlertChRssi = document.getElementById('threat-alert-ch-rssi');
  const threatAlertSkew = document.getElementById('threat-alert-skew');
  const threatAlertJitter = document.getElementById('threat-alert-jitter');
  const threatAlertEntropy = document.getElementById('threat-alert-entropy');
  const threatAlertCmd = document.getElementById('threat-alert-cmd');
  const btnThreatIgnore = document.getElementById('btn-threat-ignore');
  const btnThreatBlock = document.getElementById('btn-threat-block');

  const threatQueueMap = new Map();
  const threatIgnoreCountMap = new Map(); // key = bssidKey, value = ignore count (int)
  const bannedNetworkSet = new Set(); // key = bssidKey (set of banned BSSIDs)

  function markNetworkAsBanned(bssid) {
    const bssidKey = bssid ? bssid.toLowerCase().trim() : '00:00:00:00:00:00';
    bannedNetworkSet.add(bssidKey);
    threatQueueMap.delete(bssidKey);
    renderThreatAlertStack();
  }

  let activeBanCmd = "";
  let activeBanSsid = "";
  let activeBanBssid = "";

  const ssidDataMap = new Map();
  const channelSsidMap = new Map(); 

  if (themeToggleBtn) {
    themeToggleBtn.addEventListener('click', () => {
      const htmlEl = document.documentElement;
      htmlEl.classList.toggle('light');
      htmlEl.classList.toggle('dark');
      
      const isLight = htmlEl.classList.contains('light');
      themeToggleText.innerText = isLight ? 'DARK' : 'LIGHT';
      if (themeToggleIcon) {
        themeToggleIcon.innerHTML = isLight 
          ? `<path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/>` 
          : `<circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/>`;
      }
    });
  }

  if (kpiUniqueCard) {
    kpiUniqueCard.addEventListener('click', () => {
      openUniqueNetworksModal();
    });
  }

  if (uniqueModalCloseBtn) {
    uniqueModalCloseBtn.addEventListener('click', () => {
      uniqueNetworksModal.classList.add('hidden');
    });
  }

  if (uniqueNetworksModal) {
    uniqueNetworksModal.addEventListener('click', (e) => {
      if (e.target === uniqueNetworksModal) {
        uniqueNetworksModal.classList.add('hidden');
      }
    });
  }

  if (window.purifierAPI) {
    window.purifierAPI.onBackendEvent((event) => {
      if (event.type === 'BEACON_EVENT') {
        processBeaconEvent(event.data);
      }
    });
  }

  function getChannelNumber(data) {
    if (data.channel) {
      const parsed = parseInt(data.channel);
      if (!isNaN(parsed) && parsed > 0) {
        if ([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 36, 44, 149].includes(parsed)) return parsed;
        if (parsed <= 13) return Math.min(11, Math.max(1, parsed));
        if (parsed > 13 && parsed <= 40) return 36;
        if (parsed > 40 && parsed <= 100) return 44;
        if (parsed > 100) return 149;
      }
    }
    
    let hash = 0;
    const str = data.ssid || data.bssid || "wifi";
    for (let i = 0; i < str.length; i++) {
      hash = str.charCodeAt(i) + ((hash << 5) - hash);
    }
    const validChs = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 36, 44, 149];
    return validChs[Math.abs(hash) % validChs.length];
  }

  function processBeaconEvent(data) {
    totalPackets++;
    elemTotal.innerText = totalPackets.toLocaleString();

    if (!data.ssid || !data.ssid.trim()) {
      data.ssid = "Hidden Network";
    }

    const isRed = data.verdict.includes('RED');
    const isAmber = data.verdict.includes('AMBER');
    const isGreen = data.verdict.includes('GREEN');

    const bssidKey = data.bssid ? data.bssid.toLowerCase().trim() : '00:00:00:00:00:00';
    const storageKey = isRed ? `${bssidKey}_threat` : bssidKey;

    data.resolvedChannel = getChannelNumber(data);
    data.lastSeen = Date.now();
    ssidDataMap.set(storageKey, data);

    if (isGreen) safeAps++;
    if (isRed) threatsBanned++;

    elemSafe.innerText = safeAps.toLocaleString();
    elemBanned.innerText = threatsBanned.toLocaleString();
    if (elemUniqueNetworks) {
      elemUniqueNetworks.innerText = ssidDataMap.size.toLocaleString();
    }

    updateChannelActivityAndSSIDChips(data);

    const firstRow = elemTbody.querySelector('.empty-row');
    if (firstRow) firstRow.remove();

    const tr = document.createElement('tr');
    tr.className = `ap-row ${isRed ? 'threat-ap' : ''}`;
    let tagClass = 'text-green';
    if (isAmber) tagClass = 'text-amber';
    if (isRed) tagClass = 'text-red';

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
      <td><strong class="${tagClass}">${(data.threat_score * 100).toFixed(1)}%</strong></td>
      <td><span class="${tagClass}">${escapeHtml(cleanVerdict)}</span></td>
      <td><button class="btn-isolate" style="font-size:9px;">View</button></td>
    `;

    tr.addEventListener('click', () => {
      document.querySelectorAll('.ap-row').forEach(r => r.classList.remove('selected-ap'));
      tr.classList.add('selected-ap');
      updateForensicsPanel(data);
      openApDetailModal(data);
    });

    elemTbody.prepend(tr);
    if (elemTbody.children.length > 50) {
      elemTbody.removeChild(elemTbody.lastChild);
    }
    elemRowCount.innerText = `${ssidDataMap.size} Unique Networks Monitored`;

    updateRadarBlips();

    appendTerminalLog(data, cleanVerdict, isRed, isAmber);

    if (isRed) {
      updateForensicsPanel(data);
      if (cmdBox) {
        cmdBox.style.display = 'none'; // Sesuai permintaan, tombol ban tidak di bawah lagi
      }

      const threatBssidKey = data.bssid ? data.bssid.toLowerCase().trim() : '00:00:00:00:00:00';
      const currentIgnoreCount = threatIgnoreCountMap.get(threatBssidKey) || 0;
      const isAlreadyBanned = bannedNetworkSet.has(threatBssidKey);

      // Jika jaringan ini belum di-ban dan belum di-ignore 3 kali, tampilkan popup modal
      if (currentIgnoreCount < 3 && !isAlreadyBanned) {
        if (!threatQueueMap.has(threatBssidKey)) {
          threatQueueMap.set(threatBssidKey, Object.assign({}, data));
        } else {
          const existing = threatQueueMap.get(threatBssidKey);
          existing.rssi = data.rssi;
          existing.threat_score = data.threat_score;
          existing.clock_skew_ppm = data.clock_skew_ppm;
          existing.jitter_variance = data.jitter_variance;
          existing.sequence_entropy = data.sequence_entropy;
          existing.os_ban_cmd = data.os_ban_cmd;
        }

        renderThreatAlertStack();
      }
    }
  }

  function renderThreatAlertStack() {
    const queue = Array.from(threatQueueMap.values());
    if (queue.length === 0) {
      if (threatAlertModal) threatAlertModal.classList.add('hidden');
      return;
    }

    const activeThreat = queue[0];
    const activeBssidKey = activeThreat.bssid ? activeThreat.bssid.toLowerCase().trim() : '00:00:00:00:00:00';
    const ignoreCount = threatIgnoreCountMap.get(activeBssidKey) || 0;

    if (threatAlertSsid) threatAlertSsid.innerText = activeThreat.ssid;
    if (threatAlertBssid) threatAlertBssid.innerText = activeThreat.bssid;
    if (threatAlertScore) threatAlertScore.innerText = `${(activeThreat.threat_score * 100).toFixed(1)}%`;
    if (threatAlertChRssi) threatAlertChRssi.innerText = `CH ${activeThreat.resolvedChannel || activeThreat.channel || 6} (${activeThreat.rssi} dBm)`;
    if (threatAlertSkew) threatAlertSkew.innerText = `${activeThreat.clock_skew_ppm} ppm`;
    if (threatAlertJitter) threatAlertJitter.innerText = `${activeThreat.jitter_variance}`;
    if (threatAlertEntropy) threatAlertEntropy.innerText = `${activeThreat.sequence_entropy}`;
    if (threatAlertCmd) threatAlertCmd.innerText = activeThreat.os_ban_cmd;

    if (threatStackCounter) {
      if (queue.length > 1) {
        threatStackCounter.classList.remove('hidden');
        threatStackCounter.innerText = `1 of ${queue.length} Pending Threats`;
      } else {
        threatStackCounter.classList.add('hidden');
      }
    }

    if (threatStackBg1) {
      if (queue.length > 1) threatStackBg1.classList.remove('hidden');
      else threatStackBg1.classList.add('hidden');
    }

    if (threatStackBg2) {
      if (queue.length > 2) threatStackBg2.classList.remove('hidden');
      else threatStackBg2.classList.add('hidden');
    }

    if (btnThreatIgnore) {
      btnThreatIgnore.innerHTML = `
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6L6 18M6 6l12 12"/></svg>
        IGNORE (${ignoreCount}/3)
      `;
      btnThreatIgnore.title = `Ignore this alert (${ignoreCount}/3). Mutes popups permanently for this network after 3 ignores.`;
      btnThreatIgnore.onclick = () => {
        dismissActiveThreat(activeThreat.bssid, true); // true = ignored action
      };
    }

    if (btnThreatBlock) {
      btnThreatBlock.onclick = () => {
        markNetworkAsBanned(activeThreat.bssid);
        if (window.purifierAPI && activeThreat.os_ban_cmd && !activeThreat.os_ban_cmd.startsWith("N/A")) {
          window.purifierAPI.executeOsBan(activeThreat.os_ban_cmd, { ssid: activeThreat.ssid, bssid: activeThreat.bssid }).then(res => {
            if (res.success) {
              alert(`OS BAN EXECUTED:\n\n${res.output}`);
            } else {
              alert(`OS BAN FAILED:\n\n${res.output}`);
            }
          });
        }
      };
    }

    if (threatAlertModal && threatAlertModal.classList.contains('hidden')) {
      threatAlertModal.classList.remove('hidden');
    }
  }

  function dismissActiveThreat(bssid, isIgnoredAction = false) {
    const bssidKey = bssid ? bssid.toLowerCase().trim() : '00:00:00:00:00:00';

    if (isIgnoredAction) {
      const count = (threatIgnoreCountMap.get(bssidKey) || 0) + 1;
      threatIgnoreCountMap.set(bssidKey, count);
    }

    threatQueueMap.delete(bssidKey);
    renderThreatAlertStack();
  }

  function updateRadarBlips() {
    if (!elemBlipsLayer) return;

    const activeKeys = Array.from(ssidDataMap.keys()).sort();
    const totalAps = activeKeys.length;
    
    if (totalAps === 0) return;

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

      const exp = (-30 - data.rssi) / 25.0;
      const estDistMeters = Math.max(0.5, Math.min(25.0, Math.pow(10, exp))).toFixed(1);
      data.est_dist = estDistMeters;

      const angleRad = index * angleStep - Math.PI / 2;
      const clampedRssi = Math.max(-95, Math.min(-30, data.rssi));
      const normalizedDistance = (clampedRssi - (-30)) / ((-95) - (-30));
      const radius = 18 + normalizedDistance * 82;

      const x = 110 + radius * Math.cos(angleRad);
      const y = 110 + radius * Math.sin(angleRad);

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
          updateForensicsPanel(latestData);
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

    if (closestTarget && radarDistBadge) {
      radarDistBadge.innerText = `Est. Dist: ${closestTarget.est_dist} m (${closestTarget.ssid.substring(0, 8)})`;
    }
  }

  function updateChannelActivityAndSSIDChips(data) {
    const ch = data.resolvedChannel;
    const currentRssi = data.rssi;
    const isRed = data.verdict.includes('RED');
    const currentStatus = isRed ? 'crit' : 'clear';

    if (!channelSsidMap.has(ch)) {
      channelSsidMap.set(ch, new Map());
    }
    const chMap = channelSsidMap.get(ch);
    const bssidKey = data.bssid ? data.bssid.toLowerCase().trim() : '00:00:00:00:00:00';
    chMap.set(bssidKey, { ssid: data.ssid, status: currentStatus, data: data, rssi: currentRssi });

    const barItemEl = document.querySelector(`.spectrum-bar-item[data-ch="${ch}"]`);
    const groupedContainer = document.getElementById(`grouped-bars-${ch}`);
    
    if (groupedContainer) {
      groupedContainer.innerHTML = '';
      let items = Array.from(chMap.values());

      items.sort((a, b) => {
        const aRed = a.status === 'crit' || a.data.verdict.includes('RED');
        const bRed = b.status === 'crit' || b.data.verdict.includes('RED');
        if (aRed && !bRed) return -1;
        if (!aRed && bRed) return 1;
        return b.rssi - a.rssi;
      });

      let oldBadge = barItemEl ? barItemEl.querySelector('.more-aps-badge') : null;
      if (oldBadge) oldBadge.remove();

      if (items.length > 6 && barItemEl) {
        const moreBadge = document.createElement('span');
        moreBadge.className = 'more-aps-badge';
        moreBadge.innerText = `+${items.length - 6} APs`;
        moreBadge.title = `Click to open Channel ${ch} Zoom Inspector`;
        moreBadge.addEventListener('click', (e) => {
          e.stopPropagation();
          openChannelZoomModal(ch);
        });
        barItemEl.prepend(moreBadge);
      }

      const visibleItems = items.slice(0, 6);
      visibleItems.forEach(item => {
        const barWrapper = document.createElement('div');
        barWrapper.className = 'wifi-slim-bar';

        const isItemRed = item.status === 'crit' || item.data.verdict.includes('RED');
        
        let rssiClass = 'rssi-strong';
        if (item.rssi < -55 && item.rssi >= -70) rssiClass = 'rssi-medium';
        else if (item.rssi < -70 && item.rssi >= -82) rssiClass = 'rssi-fair';
        else if (item.rssi < -82) rssiClass = 'rssi-weak';

        const heightPct = Math.max(22, Math.min(96, ((item.rssi + 105) / 75) * 100));

        const barFill = document.createElement('div');
        barFill.className = `slim-bar-fill ${isItemRed ? 'threat-rogue' : rssiClass}`;
        barFill.style.height = `${heightPct}%`;

        const cleanVerdict = item.data.verdict.replace(/[\u{1F600}-\u{1F64F}\u{1F300}-\u{1F5FF}\u{1F680}-\u{1F6FF}\u{1F1E0}-\u{1F1FF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}]/gu, '').trim();

        const tooltip = document.createElement('div');
        tooltip.className = 'bar-tooltip';
        tooltip.innerHTML = `
          <strong>${escapeHtml(item.ssid)}</strong><br>
          <span style="font-family:var(--font-mono); opacity:0.8;">${item.data.bssid}</span><br>
          Signal: <strong>${item.rssi} dBm</strong> (~${item.data.est_dist || '2.8'}m)<br>
          Verdict: <span class="${isItemRed ? 'text-red' : 'text-green'}">${escapeHtml(cleanVerdict)}</span>
        `;

        barWrapper.appendChild(tooltip);
        barWrapper.appendChild(barFill);

        barWrapper.addEventListener('click', (e) => {
          e.stopPropagation();
          updateForensicsPanel(item.data);
          openApDetailModal(item.data);
        });

        groupedContainer.appendChild(barWrapper);
      });

      if (barItemEl) {
        barItemEl.onclick = () => {
          openChannelZoomModal(ch);
        };
      }
    }
  }

  let activeZoomChannel = null;
  let activeFilterMode = 'all';

  function openChannelZoomModal(ch) {
    if (!channelZoomModal) return;
    activeZoomChannel = ch;

    const chMap = channelSsidMap.get(ch);
    const items = chMap ? Array.from(chMap.values()) : [];

    if (channelZoomTitle) channelZoomTitle.innerText = `CHANNEL ${ch} SPECTRUM INSPECTOR`;
    if (channelZoomSubtitle) channelZoomSubtitle.innerText = `${items.length} Active WiFi Networks Monitored on Channel ${ch}`;

    renderZoomModalBars(items, activeFilterMode);

    if (chFilterAll) {
      chFilterAll.onclick = () => { setZoomFilter('all', items); };
    }
    if (chFilterThreats) {
      chFilterThreats.onclick = () => { setZoomFilter('threats', items); };
    }
    if (chFilterSafe) {
      chFilterSafe.onclick = () => { setZoomFilter('safe', items); };
    }

    channelZoomModal.classList.remove('hidden');
  }

  function setZoomFilter(mode, items) {
    activeFilterMode = mode;
    [chFilterAll, chFilterThreats, chFilterSafe].forEach(btn => {
      if (btn) btn.classList.remove('active');
    });

    if (mode === 'all' && chFilterAll) chFilterAll.classList.add('active');
    if (mode === 'threats' && chFilterThreats) chFilterThreats.classList.add('active');
    if (mode === 'safe' && chFilterSafe) chFilterSafe.classList.add('active');

    renderZoomModalBars(items, mode);
  }

  function renderZoomModalBars(items, filterMode) {
    if (!wideSpectrumBars) return;
    wideSpectrumBars.innerHTML = '';

    const threatItems = items.filter(i => i.status === 'crit' || i.data.verdict.includes('RED'));
    const safeItems = items.filter(i => !(i.status === 'crit' || i.data.verdict.includes('RED')));

    if (chCountAll) chCountAll.innerText = items.length;
    if (chCountThreats) chCountThreats.innerText = threatItems.length;
    if (chCountSafe) chCountSafe.innerText = safeItems.length;

    let filtered = items;
    if (filterMode === 'threats') filtered = threatItems;
    if (filterMode === 'safe') filtered = safeItems;

    if (filtered.length === 0) {
      wideSpectrumBars.innerHTML = `<div class="w-full text-center text-dim py-8">No WiFis matching filter criteria.</div>`;
      return;
    }

    filtered.forEach(item => {
      const wideItem = document.createElement('div');
      wideItem.className = 'wide-bar-item';

      const isItemRed = item.status === 'crit' || item.data.verdict.includes('RED');
      let rssiClass = 'rssi-strong';
      if (item.rssi < -55 && item.rssi >= -70) rssiClass = 'rssi-medium';
      else if (item.rssi < -70 && item.rssi >= -82) rssiClass = 'rssi-fair';
      else if (item.rssi < -82) rssiClass = 'rssi-weak';

      const heightPct = Math.max(25, Math.min(96, ((item.rssi + 105) / 75) * 100));

      wideItem.innerHTML = `
        <span class="wide-bar-rssi">${item.rssi}dBm</span>
        <div class="wide-bar-fill ${isItemRed ? 'threat-rogue' : rssiClass}" style="height:${heightPct}%;"></div>
        <span class="wide-bar-label" title="${escapeHtml(item.ssid)}">${escapeHtml(item.ssid)}</span>
      `;

      wideItem.addEventListener('click', (e) => {
        e.stopPropagation();
        channelZoomModal.classList.add('hidden');
        updateForensicsPanel(item.data);
        openApDetailModal(item.data);
      });

      wideSpectrumBars.appendChild(wideItem);
    });
  }

  if (channelZoomCloseBtn) {
    channelZoomCloseBtn.addEventListener('click', () => {
      if (channelZoomModal) channelZoomModal.classList.add('hidden');
    });
  }

  let openedFromUniqueModal = false;

  function openUniqueNetworksModal() {
    if (!uniqueNetworksTbody) return;

    uniqueNetworksTbody.innerHTML = '';
    const activeAps = Array.from(ssidDataMap.values());
    uniqueModalCount.innerText = `${activeAps.length} Unique SSIDs Monitored`;

    if (activeAps.length === 0) {
      uniqueNetworksTbody.innerHTML = `<tr class="empty-row"><td colspan="6">No networks detected yet...</td></tr>`;
      uniqueNetworksModal.classList.remove('hidden');
      return;
    }

    activeAps.forEach(data => {
      const tr = document.createElement('tr');
      const isRed = data.verdict.includes('RED');
      const isAmber = data.verdict.includes('AMBER');
      let tagClass = 'text-green';
      if (isAmber) tagClass = 'text-amber';
      if (isRed) tagClass = 'text-red';

      const cleanVerdict = data.verdict.replace(/[\u{1F600}-\u{1F64F}\u{1F300}-\u{1F5FF}\u{1F680}-\u{1F6FF}\u{1F1E0}-\u{1F1FF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}]/gu, '').trim();

      tr.innerHTML = `
        <td><strong>${escapeHtml(data.ssid)}</strong></td>
        <td><code>${data.bssid}</code></td>
        <td>CH ${data.resolvedChannel || data.channel || 6}</td>
        <td>${data.rssi} dBm</td>
        <td><span class="${tagClass}">${escapeHtml(cleanVerdict)}</span></td>
        <td><button class="btn-isolate" style="font-size:9px;">Inspect</button></td>
      `;

      tr.addEventListener('click', () => {
        openedFromUniqueModal = true;
        uniqueNetworksModal.classList.add('hidden');
        updateForensicsPanel(data);
        openApDetailModal(data);
      });

      uniqueNetworksTbody.appendChild(tr);
    });

    uniqueNetworksModal.classList.remove('hidden');
  }

  function closeDetailModal() {
    modalOverlay.classList.add('hidden');
    if (openedFromUniqueModal) {
      openedFromUniqueModal = false;
      uniqueNetworksModal.classList.remove('hidden');
    }
  }

  modalCloseBtn.addEventListener('click', () => {
    closeDetailModal();
  });

  modalOverlay.addEventListener('click', (e) => {
    if (e.target === modalOverlay) {
      closeDetailModal();
    }
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      if (!modalOverlay.classList.contains('hidden')) {
        closeDetailModal();
      } else if (!uniqueNetworksModal.classList.contains('hidden')) {
        uniqueNetworksModal.classList.add('hidden');
      }
    }
  });

  function updateForensicsPanel(data) {
    if (!forensicSsid) return;

    forensicSsid.innerText = data.ssid || 'UNKNOWN AP';
    forensicBssid.innerText = data.bssid || '00:00:00:00:00:00';
    
    const pct = (data.threat_score * 100).toFixed(1);
    forensicThreatScore.innerText = `${pct}%`;

    const isRed = data.verdict.includes('RED');
    const isAmber = data.verdict.includes('AMBER');

    if (isRed) {
      forensicThreatScore.className = 'gauge-num text-red';
      forensicStatusBadge.innerText = 'RED: EVIL TWIN THREAT DETECTED';
      forensicStatusBadge.className = 'forensic-badge text-red';
    } else if (isAmber) {
      forensicThreatScore.className = 'gauge-num text-amber';
      forensicStatusBadge.innerText = 'AMBER: ANOMALY WARNING';
      forensicStatusBadge.className = 'forensic-badge text-amber';
    } else {
      forensicThreatScore.className = 'gauge-num text-green';
      forensicStatusBadge.innerText = 'GREEN: VERIFIED SAFE AP';
      forensicStatusBadge.className = 'forensic-badge text-green';
    }

    const entropyVal = parseFloat(data.sequence_entropy || 0.05);
    const entropyPct = Math.min(100, Math.max(5, (entropyVal / 1.0) * 100));
    if (forensicEntropyBar) forensicEntropyBar.style.width = `${entropyPct}%`;
    if (forensicEntropyVal) forensicEntropyVal.innerText = `${data.sequence_entropy} (${entropyVal > 0.4 ? 'ABNORMAL' : 'NORMAL'})`;

    if (forensicSkewVal) forensicSkewVal.innerText = `${data.clock_skew_ppm > 0 ? '+' : ''}${data.clock_skew_ppm} ppm`;

    if (btnIsolateAp) {
      btnIsolateAp.onclick = () => {
        markNetworkAsBanned(data.bssid);
        if (data.os_ban_cmd && !data.os_ban_cmd.startsWith("N/A") && window.purifierAPI) {
          window.purifierAPI.executeOsBan(data.os_ban_cmd, { ssid: data.ssid, bssid: data.bssid }).then(res => {
            if (res.success) {
              alert(`OS BAN EXECUTED:\n\n${res.output}`);
            } else {
              alert(`OS BAN FAILED:\n\n${res.output}`);
            }
          });
        } else {
          alert(`Isolating ${data.ssid} (${data.bssid}).`);
        }
      };
    }
  }

  function appendTerminalLog(data, cleanVerdict, isRed, isAmber) {
    if (!elemFeedContainer) return;

    const timestamp = new Date().toLocaleTimeString();
    const div = document.createElement('div');

    if (isRed) {
      div.className = 'log-entry blocked';
      div.innerText = `[${timestamp}] BLOCKED: ${data.ssid} (${data.bssid}) - ${cleanVerdict} (Threat: ${(data.threat_score*100).toFixed(1)}%)`;
    } else if (isAmber) {
      div.className = 'log-entry warn';
      div.innerText = `[${timestamp}] WARN: ${data.ssid} (${data.bssid}) - Layer 2 Anomaly (Skew: ${data.clock_skew_ppm}ppm)`;
    } else {
      div.className = 'log-entry info';
      div.innerText = `[${timestamp}] SAFE: ${data.ssid} (${data.bssid}) - Verified Trust`;
    }

    elemFeedContainer.appendChild(div);
    elemFeedContainer.scrollTop = elemFeedContainer.scrollHeight;

    if (elemFeedContainer.children.length > 50) {
      elemFeedContainer.removeChild(elemFeedContainer.firstChild);
    }
  }

  if (btnForceExec) {
    btnForceExec.addEventListener('click', () => {
      markNetworkAsBanned(activeBanBssid);
      if (activeBanCmd && window.purifierAPI) {
        window.purifierAPI.executeOsBan(activeBanCmd, { ssid: activeBanSsid, bssid: activeBanBssid }).then(res => {
          if (res.success) {
            alert(`OS BAN EXECUTED:\n\n${res.output}`);
          } else {
            alert(`OS BAN FAILED:\n\n${res.output}`);
          }
        });
      }
    });
  }

  function openApDetailModal(data) {
    modalSsid.innerText = data.ssid;
    modalBssid.innerText = data.bssid;
    modalRssi.innerText = `${data.rssi} dBm`;

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
      modalVerdict.innerText = "AMBER: DOS WARNING";
      modalVerdict.style.color = "var(--accent-amber)";
      modalScoreBar.style.backgroundColor = "var(--accent-amber)";
    } else {
      modalVerdict.innerText = "GREEN: VERIFIED SAFE AP";
      modalVerdict.style.color = "var(--accent-green)";
      modalScoreBar.style.backgroundColor = "var(--accent-green)";
    }

    modalCmdText.innerText = data.os_ban_cmd;

    modalBtnBan.onclick = () => {
      markNetworkAsBanned(data.bssid);
      if (data.os_ban_cmd && !data.os_ban_cmd.startsWith("N/A") && window.purifierAPI) {
        window.purifierAPI.executeOsBan(data.os_ban_cmd, { ssid: data.ssid, bssid: data.bssid }).then(res => {
          if (res.success) {
            alert(`OS BAN EXECUTED:\n\n${res.output}`);
          } else {
            alert(`OS BAN FAILED:\n\n${res.output}`);
          }
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
    if (e.key === 'Escape') {
      if (modalOverlay && !modalOverlay.classList.contains('hidden')) modalOverlay.classList.add('hidden');
      if (uniqueNetworksModal && !uniqueNetworksModal.classList.contains('hidden')) uniqueNetworksModal.classList.add('hidden');
      if (channelZoomModal && !channelZoomModal.classList.contains('hidden')) channelZoomModal.classList.add('hidden');
    }
  });

  function escapeHtml(str) {
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
});
