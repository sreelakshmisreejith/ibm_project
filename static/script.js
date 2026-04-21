/* ═══════════════════════════════════════════════════════════
   MEDTRACE FORENSICS — CYBER COMMAND CENTER
   Frontend Controller · v2.0.1
   ═══════════════════════════════════════════════════════════ */

'use strict';

// ── DOM REFERENCES ────────────────────────────────────────────
const form          = document.getElementById('scan-form');
const scanButton    = document.getElementById('scan-button');
const dirInput      = document.getElementById('directory-path');
const statusBox     = document.getElementById('scan-status');
const recordsBody   = document.getElementById('records-body');
const downloadLink  = document.getElementById('download-link');
const logConsole    = document.getElementById('log-console');
const searchInput   = document.getElementById('search-input');
const riskFilter    = document.getElementById('risk-filter');
const clearLogsBtn  = document.getElementById('clear-logs-btn');
const scanBadge     = document.getElementById('scan-state-badge');
const scanProgressWrap = document.getElementById('scan-progress-wrap');
const scanProgressFill = document.getElementById('scan-progress-fill');
const scanProgressLabel = document.getElementById('scan-progress-label');
const activityStream = document.getElementById('activity-stream');
const alertsGrid    = document.getElementById('alerts-grid');
const alertBadge    = document.getElementById('alert-badge');
const ahMeta        = document.getElementById('ah-meta');

// Stat fields
const totalFilesEl = document.getElementById('total-files');
const highRiskEl   = document.getElementById('high-risk');
const lowRiskEl    = document.getElementById('low-risk');
const lastScanEl   = document.getElementById('last-scan');
const highBarFill  = document.getElementById('high-bar-fill');
const lowBarFill   = document.getElementById('low-bar-fill');
const chartPct     = document.getElementById('chart-pct');
const legHigh      = document.getElementById('leg-high');
const legLow       = document.getElementById('leg-low');
const chipTotal    = document.getElementById('chip-total');
const chipHigh     = document.getElementById('chip-high');
const chipLow      = document.getElementById('chip-low');
const qsTotal      = document.getElementById('qs-total');
const qsHigh       = document.getElementById('qs-high');
const qsLow        = document.getElementById('qs-low');
const qsTime       = document.getElementById('qs-time');
const metaCase     = document.getElementById('meta-case');
const metaInvestigator = document.getElementById('meta-investigator');
const metaBreach   = document.getElementById('meta-breach');
const metaSystem   = document.getElementById('meta-system');
const sfScanState  = document.getElementById('sf-scan-state');

// ── STATE ─────────────────────────────────────────────────────
let allRecords = [];
let riskChart = null;
let categoryChart = null;
let threatNodesAnim = null;
let progressInterval = null;

// ── ANIMATED BACKGROUND ───────────────────────────────────────
(function initBackground() {
  const canvas = document.getElementById('bg-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  function resize() {
    canvas.width  = window.innerWidth;
    canvas.height = window.innerHeight;
  }
  resize();
  window.addEventListener('resize', resize);

  const particles = Array.from({ length: 80 }, () => ({
    x: Math.random() * canvas.width,
    y: Math.random() * canvas.height,
    vx: (Math.random() - 0.5) * 0.35,
    vy: (Math.random() - 0.5) * 0.35,
    r: Math.random() * 1.8 + 0.4,
    alpha: Math.random() * 0.45 + 0.05
  }));

  function draw() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    for (let i = 0; i < particles.length; i++) {
      const p = particles[i];
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0 || p.x > canvas.width)  p.vx *= -1;
      if (p.y < 0 || p.y > canvas.height) p.vy *= -1;

      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(0,245,255,${p.alpha})`;
      ctx.fill();

      // Draw connections
      for (let j = i + 1; j < particles.length; j++) {
        const q = particles[j];
        const dx = p.x - q.x, dy = p.y - q.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 130) {
          ctx.beginPath();
          ctx.moveTo(p.x, p.y);
          ctx.lineTo(q.x, q.y);
          ctx.strokeStyle = `rgba(0,245,255,${0.05 * (1 - dist / 130)})`;
          ctx.lineWidth = 0.5;
          ctx.stroke();
        }
      }
    }
    requestAnimationFrame(draw);
  }
  draw();
})();

// ── THREAT NODES CANVAS ───────────────────────────────────────
(function initThreatNodes() {
  const canvas = document.getElementById('threat-nodes-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.offsetWidth || 400;
  const H = canvas.offsetHeight || 280;
  canvas.width = W; canvas.height = H;

  const nodes = [];
  const nodeCount = 18;
  for (let i = 0; i < nodeCount; i++) {
    nodes.push({
      x: 40 + Math.random() * (W - 80),
      y: 30 + Math.random() * (H - 60),
      vx: (Math.random() - 0.5) * 0.6,
      vy: (Math.random() - 0.5) * 0.6,
      r: Math.random() * 8 + 5,
      isHigh: Math.random() > 0.65,
      pulse: Math.random() * Math.PI * 2,
      label: `NODE-${String(i + 1).padStart(2, '0')}`
    });
  }

  function drawNodes() {
    ctx.clearRect(0, 0, W, H);

    // Draw connections
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const dx = nodes[i].x - nodes[j].x;
        const dy = nodes[i].y - nodes[j].y;
        const dist = Math.sqrt(dx*dx + dy*dy);
        if (dist < 130) {
          const alpha = 0.15 * (1 - dist / 130);
          ctx.beginPath();
          ctx.moveTo(nodes[i].x, nodes[i].y);
          ctx.lineTo(nodes[j].x, nodes[j].y);
          ctx.strokeStyle = nodes[i].isHigh || nodes[j].isHigh
            ? `rgba(255,34,85,${alpha})`
            : `rgba(0,245,255,${alpha * 0.6})`;
          ctx.lineWidth = 0.8;
          ctx.stroke();
        }
      }
    }

    // Draw nodes
    nodes.forEach(n => {
      n.pulse += 0.04;
      n.x += n.vx; n.y += n.vy;
      if (n.x < n.r || n.x > W - n.r) n.vx *= -1;
      if (n.y < n.r || n.y > H - n.r) n.vy *= -1;

      const pulseR = n.r + Math.sin(n.pulse) * 3;
      const color = n.isHigh ? '#ff2255' : '#00f5ff';
      const glowColor = n.isHigh ? 'rgba(255,34,85,0.4)' : 'rgba(0,245,255,0.3)';

      // Outer glow ring
      ctx.beginPath();
      ctx.arc(n.x, n.y, pulseR + 5, 0, Math.PI * 2);
      ctx.strokeStyle = n.isHigh ? `rgba(255,34,85,${0.1 + 0.08 * Math.sin(n.pulse)})` : `rgba(0,245,255,${0.06 + 0.05 * Math.sin(n.pulse)})`;
      ctx.lineWidth = 2;
      ctx.stroke();

      // Node body
      const grad = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, pulseR);
      grad.addColorStop(0, color);
      grad.addColorStop(1, 'transparent');
      ctx.beginPath();
      ctx.arc(n.x, n.y, pulseR, 0, Math.PI * 2);
      ctx.fillStyle = grad;
      ctx.globalAlpha = 0.85;
      ctx.fill();
      ctx.globalAlpha = 1;

      // Center dot
      ctx.beginPath();
      ctx.arc(n.x, n.y, 3, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.shadowBlur = 12;
      ctx.shadowColor = color;
      ctx.fill();
      ctx.shadowBlur = 0;
    });

    requestAnimationFrame(drawNodes);
  }
  drawNodes();
})();

// ── CLOCK ─────────────────────────────────────────────────────
function updateClocks() {
  const now = new Date();
  const utc = now.toUTCString().slice(17, 25);
  const el = document.getElementById('live-clock');
  const sf = document.getElementById('sf-clock');
  if (el) el.textContent = utc + ' UTC';
  if (sf) sf.textContent = utc + ' UTC';
}
setInterval(updateClocks, 1000);
updateClocks();

// ── TAB NAVIGATION ────────────────────────────────────────────
const navTabs = document.querySelectorAll('.nav-tab-cyber');
const tabPanels = document.querySelectorAll('.tab-panel');

function switchTab(tabId) {
  navTabs.forEach(t => {
    const isActive = t.dataset.tab === tabId;
    t.classList.toggle('active', isActive);
    t.setAttribute('aria-selected', isActive ? 'true' : 'false');
  });
  tabPanels.forEach(p => {
    const isActive = p.id === `panel-${tabId}`;
    p.classList.toggle('active', isActive);
    if (isActive) p.style.animation = 'none';
    requestAnimationFrame(() => {
      if (isActive) { p.style.animation = ''; }
    });
  });
}

navTabs.forEach(tab => {
  tab.addEventListener('click', () => switchTab(tab.dataset.tab));
});

// ── STATUS / BADGE ────────────────────────────────────────────
function setStatus(message, tone = 'idle') {
  const textEl = document.getElementById('scan-status-text');
  if (textEl) textEl.textContent = message;
  if (statusBox) statusBox.dataset.tone = tone;

  const labels = { idle: 'IDLE', working: 'SCANNING', success: 'COMPLETE', error: 'ERROR' };
  if (scanBadge) {
    scanBadge.dataset.state = tone;
    const dotEl = scanBadge.querySelector('.badge-dot');
    const txtEl = scanBadge.querySelector('.badge-text');
    if (txtEl) txtEl.textContent = labels[tone] || tone;
  }
  if (sfScanState) sfScanState.textContent = (labels[tone] || tone);
}

// ── ANIMATED COUNTER ──────────────────────────────────────────
function animateCounter(el, target, duration = 700) {
  if (!el) return;
  const start = parseInt(el.textContent) || 0;
  const diff = target - start;
  if (diff === 0) return;
  const startTime = performance.now();
  function update(now) {
    const elapsed = now - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    el.textContent = Math.round(start + diff * eased);
    el.classList.add('updated');
    setTimeout(() => el.classList.remove('updated'), 400);
    if (progress < 1) requestAnimationFrame(update);
  }
  requestAnimationFrame(update);
}

// ── SCAN PROGRESS SIMULATION ──────────────────────────────────
function startProgress() {
  if (scanProgressWrap) scanProgressWrap.style.display = 'block';
  let pct = 0;
  if (progressInterval) clearInterval(progressInterval);
  progressInterval = setInterval(() => {
    pct = Math.min(pct + Math.random() * 8 + 2, 92);
    if (scanProgressFill) scanProgressFill.style.width = pct + '%';
    const phases = ['Indexing artifacts...', 'Computing SHA-256 hashes...', 'Classifying risk levels...', 'Analyzing breach timeline...', 'Generating evidence report...'];
    if (scanProgressLabel) scanProgressLabel.textContent = phases[Math.floor(pct / 20)] || 'Processing...';
  }, 200);
}

function finishProgress() {
  clearInterval(progressInterval);
  if (scanProgressFill) scanProgressFill.style.width = '100%';
  if (scanProgressLabel) scanProgressLabel.textContent = 'Scan complete.';
  setTimeout(() => { if (scanProgressWrap) scanProgressWrap.style.display = 'none'; }, 1200);
}

// ── TERMINAL LOGGER ───────────────────────────────────────────
function addLog(message, level = 'info') {
  if (!logConsole) return;
  // Remove placeholder cursor
  const cursor = logConsole.querySelector('.blink-cursor');
  if (cursor) cursor.remove();

  const line = document.createElement('div');
  line.className = `term-line ${level}`;

  const prompts = { info: '◈', warning: '⚠', error: '✖', success: '✔' };
  const prompt = document.createElement('span');
  prompt.className = 'term-prompt';
  prompt.textContent = prompts[level] || '▶';

  const text = document.createElement('span');
  text.className = 'term-text';

  const stamp = new Date().toLocaleTimeString();
  text.textContent = `[${stamp}] ${message}`;

  line.appendChild(prompt);
  line.appendChild(text);
  logConsole.appendChild(line);
  logConsole.scrollTop = logConsole.scrollHeight;

  // Re-add cursor
  const cur = document.createElement('div');
  cur.className = 'term-line blink-cursor';
  cur.innerHTML = '<span class="term-cursor">█</span>';
  logConsole.appendChild(cur);
}

function clearLogs() {
  if (!logConsole) return;
  logConsole.innerHTML = '';
  const line1 = document.createElement('div');
  line1.className = 'term-line';
  line1.innerHTML = '<span class="term-prompt">▶</span><span class="term-text">Terminal cleared — awaiting input...</span>';
  logConsole.appendChild(line1);
  const cur = document.createElement('div');
  cur.className = 'term-line blink-cursor';
  cur.innerHTML = '<span class="term-cursor">█</span>';
  logConsole.appendChild(cur);
}

// ── ACTIVITY FEED ─────────────────────────────────────────────
function addActivityItem(message, level = 'info') {
  if (!activityStream) return;
  // Remove placeholder
  const ph = activityStream.querySelector('.activity-placeholder');
  if (ph) ph.remove();

  const item = document.createElement('div');
  item.className = `activity-item ${level}`;

  const stamp = document.createElement('span');
  stamp.className = 'activity-time';
  stamp.textContent = new Date().toLocaleTimeString();

  const msg = document.createElement('span');
  msg.textContent = message;

  item.appendChild(stamp);
  item.appendChild(msg);
  activityStream.insertBefore(item, activityStream.firstChild);

  // Keep max 30 items
  while (activityStream.children.length > 30) {
    activityStream.removeChild(activityStream.lastChild);
  }
}

// ── CHARTS ────────────────────────────────────────────────────
function initOrUpdateRiskChart(high, low) {
  const canvas = document.getElementById('risk-chart');
  if (!canvas) return;

  const total = high + low;
  const pct = total > 0 ? Math.round((high / total) * 100) : 0;
  if (chartPct) chartPct.textContent = pct + '%';
  if (legHigh) legHigh.textContent = high;
  if (legLow) legLow.textContent = low;

  const data = {
    labels: ['High Risk', 'Low Risk'],
    datasets: [{
      data: [high || 0.01, low || 0.01],
      backgroundColor: ['rgba(255,34,85,0.85)', 'rgba(0,255,136,0.75)'],
      borderColor: ['#ff2255', '#00ff88'],
      borderWidth: 1.5,
      hoverOffset: 8,
    }]
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    cutout: '68%',
    animation: { duration: 800, easing: 'easeOutQuart' },
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: 'rgba(5,8,16,0.95)',
        borderColor: 'rgba(0,245,255,0.3)',
        borderWidth: 1,
        titleColor: '#00f5ff',
        bodyColor: '#94a3b8',
        titleFont: { family: 'Orbitron', size: 10 },
        bodyFont:  { family: 'JetBrains Mono', size: 11 },
        padding: 12,
      }
    }
  };

  if (!riskChart) {
    riskChart = new Chart(canvas, { type: 'doughnut', data, options });
  } else {
    riskChart.data.datasets[0].data = [high || 0.01, low || 0.01];
    riskChart.update('active');
  }
}

function initOrUpdateCategoryChart(records) {
  const canvas = document.getElementById('category-chart');
  if (!canvas) return;

  // Build category counts
  const counts = {};
  records.forEach(r => {
    const cat = r['Category'] || 'Unknown';
    counts[cat] = (counts[cat] || 0) + 1;
  });
  const labels = Object.keys(counts);
  const values = Object.values(counts);

  const neonColors = [
    'rgba(0,245,255,0.75)', 'rgba(255,34,85,0.75)', 'rgba(0,255,136,0.75)',
    'rgba(77,159,255,0.75)', 'rgba(255,140,0,0.75)', 'rgba(168,85,247,0.75)',
  ];
  const borderColors = ['#00f5ff','#ff2255','#00ff88','#4d9fff','#ff8c00','#a855f7'];

  const data = {
    labels,
    datasets: [{
      data: values,
      backgroundColor: labels.map((_, i) => neonColors[i % neonColors.length]),
      borderColor:     labels.map((_, i) => borderColors[i % borderColors.length]),
      borderWidth: 1.5,
      borderRadius: 4,
    }]
  };

  const options = {
    responsive: true,
    maintainAspectRatio: true,
    animation: { duration: 900, easing: 'easeOutQuart' },
    plugins: {
      legend: {
        labels: {
          color: '#94a3b8',
          font: { family: 'JetBrains Mono', size: 10 },
          boxWidth: 10, padding: 14
        }
      },
      tooltip: {
        backgroundColor: 'rgba(5,8,16,0.95)',
        borderColor: 'rgba(0,245,255,0.3)',
        borderWidth: 1,
        titleColor: '#00f5ff',
        bodyColor: '#94a3b8',
        titleFont: { family: 'Orbitron', size: 10 },
        bodyFont:  { family: 'JetBrains Mono', size: 11 },
        padding: 12,
      }
    },
    scales: {
      x: {
        ticks: { color: '#475569', font: { family: 'JetBrains Mono', size: 10 } },
        grid:  { color: 'rgba(255,255,255,0.04)' },
      },
      y: {
        ticks: { color: '#475569', font: { family: 'JetBrains Mono', size: 10 } },
        grid:  { color: 'rgba(0,245,255,0.04)' },
      }
    }
  };

  if (!categoryChart) {
    categoryChart = new Chart(canvas, { type: 'bar', data, options });
  } else {
    categoryChart.data.labels = labels;
    categoryChart.data.datasets[0].data = values;
    categoryChart.update('active');
  }
}

// ── EVIDENCE TABLE ────────────────────────────────────────────
function escapeHtml(val) {
  return String(val)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function shortHash(hash) {
  return hash ? `${hash.slice(0, 10)}…${hash.slice(-6)}` : '—';
}

function getFilteredRecords() {
  const q = (searchInput ? searchInput.value.trim().toLowerCase() : '');
  const rv = riskFilter ? riskFilter.value : 'all';
  return allRecords.filter(r => {
    const combined = `${r['File Name']} ${r['Category']} ${r['Status']}`.toLowerCase();
    return (!q || combined.includes(q)) && (rv === 'all' || r['Risk Level'] === rv);
  });
}

function renderTable(records) {
  if (!recordsBody) return;
  if (!records.length) {
    recordsBody.innerHTML = `
      <tr class="empty-row"><td colspan="6">
        <div class="empty-state"><div class="empty-icon">◎</div><div>No matching records</div><div class="empty-sub">Adjust filters or run a new scan</div></div>
      </td></tr>`;
    return;
  }
  recordsBody.innerHTML = records.map((r, idx) => {
    const risk = r['Risk Level'] || 'Low';
    const isHigh = risk === 'High';
    return `<tr style="animation-delay:${idx * 20}ms">
      <td style="font-family:'JetBrains Mono',monospace;font-size:11px">${escapeHtml(r['File Name'])}</td>
      <td>${escapeHtml(r['Category'])}</td>
      <td><span class="risk-badge ${isHigh ? 'high' : 'low'}">${isHigh ? '⚠' : '✓'} ${escapeHtml(risk)}</span></td>
      <td>${escapeHtml(r['Status'])}</td>
      <td style="font-family:'JetBrains Mono',monospace;font-size:10px">${escapeHtml(r['Modified Time'])}</td>
      <td style="font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--text-muted)">${escapeHtml(shortHash(r['SHA256 Hash']))}</td>
    </tr>`;
  }).join('');
}

function applyFilters() { renderTable(getFilteredRecords()); }

// ── ALERT ZONE ────────────────────────────────────────────────
function buildAlerts(records) {
  if (!alertsGrid) return;
  const highRecs = records.filter(r => r['Risk Level'] === 'High');
  alertBadge.textContent = highRecs.length;

  if (!records.length) {
    alertsGrid.innerHTML = `<div class="alert-placeholder"><div class="ap-icon">◎</div><div>Alert Zone Clear</div><div class="ap-sub">No records loaded — run a scan</div></div>`;
    if (ahMeta) ahMeta.textContent = 'No active alerts';
    return;
  }

  if (ahMeta) ahMeta.textContent = `${highRecs.length} HIGH • ${records.length - highRecs.length} LOW — ${new Date().toLocaleTimeString()}`;

  if (!records.length) {
    alertsGrid.innerHTML = `<div class="alert-placeholder"><div class="ap-icon">◎</div><div>Alert Zone Clear</div></div>`;
    return;
  }

  alertsGrid.innerHTML = records.slice(0, 30).map((r, i) => {
    const isHigh = r['Risk Level'] === 'High';
    return `<div class="alert-card ${isHigh ? '' : 'low'}" style="animation-delay:${i * 30}ms">
      <div class="alert-card-header">
        <div class="alert-filename">${escapeHtml(r['File Name'])}</div>
        <div class="alert-severity-badge ${isHigh ? 'high' : 'low'}">${isHigh ? '⚠ HIGH' : '✓ LOW'}</div>
      </div>
      <div class="alert-card-meta">
        <div class="alert-meta-item"><div class="alert-meta-label">CATEGORY</div><div class="alert-meta-val">${escapeHtml(r['Category'])}</div></div>
        <div class="alert-meta-item"><div class="alert-meta-label">STATUS</div><div class="alert-meta-val">${escapeHtml(r['Status'])}</div></div>
        <div class="alert-meta-item"><div class="alert-meta-label">MODIFIED</div><div class="alert-meta-val">${escapeHtml(r['Modified Time'])}</div></div>
        <div class="alert-meta-item"><div class="alert-meta-label">HASH</div><div class="alert-meta-val">${escapeHtml(shortHash(r['SHA256 Hash']))}</div></div>
      </div>
    </div>`;
  }).join('');
}

// ── RENDER ALL DATA ───────────────────────────────────────────
function renderAll(data) {
  const total = data.total_files ?? 0;
  const high  = data.high_risk  ?? 0;
  const low   = data.low_risk   ?? 0;
  const time  = new Date().toLocaleTimeString();

  // Stat cards with animation
  animateCounter(totalFilesEl, total);
  animateCounter(highRiskEl, high);
  animateCounter(lowRiskEl, low);
  if (lastScanEl) lastScanEl.textContent = time;

  // Progress bars
  if (high + low > 0) {
    if (highBarFill) highBarFill.style.width = ((high / (high + low)) * 100) + '%';
    if (lowBarFill)  lowBarFill.style.width  = ((low  / (high + low)) * 100) + '%';
  }

  // Side panel chips
  if (chipTotal) chipTotal.textContent = total;
  if (chipHigh)  chipHigh.textContent  = high;
  if (chipLow)   chipLow.textContent   = low;
  if (qsTotal) qsTotal.textContent = total;
  if (qsHigh)  qsHigh.textContent  = high;
  if (qsLow)   qsLow.textContent   = low;
  if (qsTime)  qsTime.textContent   = time;

  // Case meta
  if (metaCase)         metaCase.textContent         = data.case_id        ?? '—';
  if (metaInvestigator) metaInvestigator.textContent = data.investigator   ?? '—';
  if (metaBreach)       metaBreach.textContent       = data.breach_date    ?? '—';
  if (metaSystem)       metaSystem.textContent       = data.system_name    ?? '—';

  // Charts
  initOrUpdateRiskChart(high, low);
  if (allRecords.length) initOrUpdateCategoryChart(allRecords);

  // Table
  applyFilters();

  // Alerts
  buildAlerts(allRecords);

  // Activity feed
  addActivityItem(`Scan complete — ${total} artifacts indexed`, 'success');
  if (high > 0) addActivityItem(`${high} HIGH RISK files detected — immediate review required`, 'warning');
  addActivityItem(`Evidence report generated: evidence_report.csv`, 'info');
}

// ── LOGS PLAYBACK ─────────────────────────────────────────────
function playLogs(logs) {
  logs.forEach((log, i) => {
    setTimeout(() => {
      addLog(log.message, log.level || 'info');
      addActivityItem(log.message, log.level || 'info');
    }, i * 60);
  });
}

// ── SCAN ──────────────────────────────────────────────────────
async function runScan(dirPath) {
  setStatus('Initiating forensic scan...', 'working');
  scanButton.disabled = true;
  clearLogs();
  startProgress();

  addLog(`SCAN INITIATED: ${dirPath}`, 'info');
  addActivityItem(`Scan started — Target: ${dirPath}`, 'info');
  addLog('Loading forensic engine...', 'info');
  addLog('Enumerating evidence directory...', 'info');

  try {
    const resp = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ directory_path: dirPath })
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || 'Scan failed');

    allRecords = data.records || [];
    finishProgress();
    renderAll(data);
    setStatus(`SCAN COMPLETE — ${data.total_files} artifacts processed`, 'success');

    const logs = data.logs || [];
    playLogs(logs);

    // Switch to threats panel after a moment
    setTimeout(() => switchTab('threats'), 1200);

  } catch (err) {
    finishProgress();
    setStatus(err.message, 'error');
    addLog(`ERROR: ${err.message}`, 'error');
    addActivityItem(`Scan failed: ${err.message}`, 'error');
  } finally {
    scanButton.disabled = false;
  }
}

// ── EVENT LISTENERS ───────────────────────────────────────────
if (form) {
  form.addEventListener('submit', e => {
    e.preventDefault();
    const path = dirInput ? dirInput.value.trim() : '';
    if (!path) { setStatus('Target directory path required.', 'error'); return; }
    runScan(path);
  });
}

if (searchInput) searchInput.addEventListener('input', applyFilters);
if (riskFilter)  riskFilter.addEventListener('change', applyFilters);
if (clearLogsBtn) clearLogsBtn.addEventListener('click', clearLogs);

// ── INIT ──────────────────────────────────────────────────────
initOrUpdateRiskChart(0, 0);
renderTable([]);
buildAlerts([]);
switchTab('command');
