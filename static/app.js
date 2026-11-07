// Security Log Analyzer - Frontend Controller

let selectedFile = null;
let currentJobId = null;
let eventSource = null;
let currentReport = null;
let startTime = null;
let timerInterval = null;

// Track which "view" is active so the home link knows whether to navigate
let currentView = 'home'; // 'home' | 'progress' | 'report'

// DOM Elements
const fileInput = document.getElementById('fileInput');
const dropzone = document.getElementById('dropzone');
const fileInfo = document.getElementById('fileInfo');
const startBtn = document.getElementById('startBtn');
const cancelFileBtn = document.getElementById('cancelFileBtn');
const sampleBtn = document.getElementById('sampleBtn');
const uploadSection = document.getElementById('uploadSection');
const historySection = document.getElementById('historySection');
const progressSection = document.getElementById('progressSection');
const reportSection = document.getElementById('reportSection');
const progressStatusText = document.getElementById('progressStatusText');
const chunkFraction = document.getElementById('chunkFraction');
const progressBarFill = document.getElementById('progressBarFill');
const metricLines = document.getElementById('metricLines');
const metricTokens = document.getElementById('metricTokens');
const metricAlerts = document.getElementById('metricAlerts');
const metricTime = document.getElementById('metricTime');
const feedConsole = document.getElementById('feedConsole');
const exportBtn = document.getElementById('exportBtn');
const resetBtn = document.getElementById('resetBtn');
const procRamText = document.getElementById('procRamText');
const statusBadge = document.getElementById('statusBadge');
const navHomeLink = document.getElementById('navHomeLink');

// 1. Telemetry Polling
async function updateTelemetry() {
  try {
    const res = await fetch('/api/telemetry');
    if (!res.ok) return;
    const data = await res.json();
    if (procRamText) procRamText.textContent = `${data.process_ram_mb} MB`;
  } catch (err) {}
}
setInterval(updateTelemetry, 3000);
updateTelemetry();

// 2. Load Past Reports History
async function loadPastRuns() {
  const tbody = document.getElementById('runsTableBody');
  if (!tbody) return;
  try {
    const res = await fetch('/api/runs');
    if (!res.ok) return;
    const runs = await res.json();
    if (!runs || runs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="table-empty">No past reports found.</td></tr>';
      return;
    }

    tbody.innerHTML = '';
    runs.slice().reverse().forEach(run => {
      const sum = run.summary || {};
      const threats = sum.total_incidents_found || 0;
      const tagClass = threats > 0 ? 'run-threat-alert' : 'run-threat-clean';
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><code>${run.job_id}</code></td>
        <td>${sum.total_lines_analyzed || '--'}</td>
        <td><span class="run-threat-tag ${tagClass}">${threats}</span></td>
        <td>${sum.total_analysis_time_seconds ? sum.total_analysis_time_seconds + 's' : '--'}</td>
        <td style="text-align: right;"><button class="btn-view-run" onclick="viewPastReport('${run.job_id}')">View</button></td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    tbody.innerHTML = '<tr><td colspan="5" class="table-empty">Could not load history.</td></tr>';
  }
}
loadPastRuns();

// View past report directly
window.viewPastReport = async function(jobId) {
  try {
    const res = await fetch(`/api/report/${jobId}`);
    if (!res.ok) throw new Error('Report file not found');
    const report = await res.json();
    currentJobId = jobId;
    currentReport = report;

    uploadSection.style.display = 'none';
    historySection.style.display = 'none';
    progressSection.style.display = 'none';
    reportSection.style.display = 'block';
    currentView = 'report';

    renderReport(report);
  } catch (err) {
    alert('Error loading report: ' + err.message);
  }
};

// 3. File Selection & Drag-and-Drop
dropzone.addEventListener('click', () => fileInput.click());

dropzone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropzone.classList.add('dragover');
});

dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));

dropzone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropzone.classList.remove('dragover');
  if (e.dataTransfer.files.length > 0) {
    handleFileSelected(e.dataTransfer.files[0]);
  }
});

fileInput.addEventListener('change', (e) => {
  if (e.target.files.length > 0) {
    handleFileSelected(e.target.files[0]);
  }
});

function handleFileSelected(file) {
  if (!file.name.endsWith('.log') && !file.name.endsWith('.txt')) {
    alert('Please select a .log or .txt file.');
    return;
  }
  selectedFile = file;
  fileInfo.textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
  startBtn.disabled = false;
  if (cancelFileBtn) cancelFileBtn.style.display = 'inline-block';
}

function clearSelectedFile() {
  selectedFile = null;
  fileInput.value = '';
  fileInfo.textContent = '';
  startBtn.disabled = true;
  if (cancelFileBtn) cancelFileBtn.style.display = 'none';
}

if (cancelFileBtn) {
  cancelFileBtn.addEventListener('click', clearSelectedFile);
}

// 4. Start Analysis Actions
startBtn.addEventListener('click', async () => {
  if (!selectedFile) return;
  const formData = new FormData();
  formData.append('file', selectedFile);

  try {
    startBtn.disabled = true;
    const res = await fetch('/api/upload', {
      method: 'POST',
      body: formData
    });
    if (!res.ok) throw new Error('Upload failed');
    const data = await res.json();
    beginAnalysisStream(data.job_id, data.line_count);
  } catch (err) {
    alert('Error starting analysis: ' + err.message);
    startBtn.disabled = false;
  }
});

sampleBtn.addEventListener('click', async () => {
  try {
    sampleBtn.disabled = true;
    const res = await fetch('/api/use-sample', { method: 'POST' });
    if (!res.ok) throw new Error('Failed to load sample');
    const data = await res.json();
    beginAnalysisStream(data.job_id, data.line_count);
  } catch (err) {
    alert('Error loading sample log: ' + err.message);
    sampleBtn.disabled = false;
  }
});

// 5. Stream Live Analysis Progress via SSE
function beginAnalysisStream(jobId, lineCount) {
  currentJobId = jobId;
  currentView = 'progress';
  uploadSection.style.display = 'none';
  historySection.style.display = 'none';
  progressSection.style.display = 'block';
  reportSection.style.display = 'none';

  metricLines.textContent = lineCount;
  metricTokens.textContent = '0';
  metricAlerts.textContent = '0';
  startTime = Date.now();
  timerInterval = setInterval(() => {
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    metricTime.textContent = `${elapsed}s`;
  }, 200);

  feedConsole.innerHTML = `<div class="feed-entry system">Job ${jobId} initialized (${lineCount} lines)</div>`;

  eventSource = new EventSource(`/api/stream/${jobId}`);

  let totalTokensAccum = 0;
  let totalAlertsAccum = 0;

  eventSource.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      if (msg.type === 'progress') {
        const percent = Math.round((msg.chunk_index / msg.total_chunks) * 100);
        progressBarFill.style.width = `${percent}%`;
        chunkFraction.textContent = `Chunk ${msg.chunk_index} / ${msg.total_chunks}`;
        progressStatusText.textContent = msg.status;
      } else if (msg.type === 'chunk_done') {
        totalTokensAccum += (msg.tokens_used || 0);
        metricTokens.textContent = totalTokensAccum;

        const findings = msg.new_findings || [];
        if (findings.length > 0) {
          totalAlertsAccum += findings.length;
          metricAlerts.textContent = totalAlertsAccum;
          findings.forEach((f) => {
            const entry = document.createElement('div');
            entry.className = 'feed-entry alert';
            entry.textContent = `Chunk ${msg.chunk_index}: ${f.attack_type || 'Threat'} detected (${f.target_identifier || 'Target'})`;
            feedConsole.appendChild(entry);
            feedConsole.scrollTop = feedConsole.scrollHeight;
          });
        }
      } else if (msg.type === 'completed') {
        clearInterval(timerInterval);
        eventSource.close();
        currentReport = msg.report;
        renderReport(currentReport);
        loadPastRuns();
      } else if (msg.type === 'error') {
        clearInterval(timerInterval);
        eventSource.close();
        alert('Analysis error: ' + msg.error);
      }
    } catch (e) {
      console.error('Error handling SSE message', e);
    }
  };

  eventSource.onerror = () => {
    setTimeout(async () => {
      try {
        const res = await fetch(`/api/report/${jobId}`);
        if (res.ok) {
          clearInterval(timerInterval);
          if (eventSource) eventSource.close();
          currentReport = await res.json();
          renderReport(currentReport);
          loadPastRuns();
        }
      } catch (err) {}
    }, 2000);
  };
}

// 6. Render Final Report
function renderReport(report) {
  currentView = 'report';
  progressSection.style.display = 'none';
  reportSection.style.display = 'block';

  const sum = report.summary || {};
  document.getElementById('kpiCritical').textContent = sum.severity_counts?.Critical || 0;
  document.getElementById('kpiHigh').textContent = sum.severity_counts?.High || 0;
  document.getElementById('kpiMedium').textContent = sum.severity_counts?.Medium || 0;
  document.getElementById('kpiLow').textContent = sum.severity_counts?.Low || 0;

  document.getElementById('reportSubtitle').textContent = 
    `${sum.total_lines_analyzed || 0} lines • ${sum.total_chunks_processed || 0} chunks • ${sum.total_analysis_time_seconds || 0}s`;

  const listContainer = document.getElementById('incidentsList');
  listContainer.innerHTML = '';

  const incidents = report.incidents || [];
  if (incidents.length === 0) {
    listContainer.innerHTML = '<p class="empty-state">No security threats detected in this log file.</p>';
    return;
  }

  incidents.forEach((inc) => {
    const card = document.createElement('div');
    card.className = `incident-card sev-${inc.severity}`;

    const lineBadges = (inc.line_numbers || []).map(ln => `<span class="line-tag">Line ${ln}</span>`).join('');

    card.innerHTML = `
      <div class="incident-card-top">
        <div class="incident-headline">
          <span class="sev-badge sev-${inc.severity}">${inc.severity}</span>
          <h4 class="incident-title">${inc.attack_type}</h4>
        </div>
        <div class="incident-target-badge">
          <span class="target-label">Target</span>
          <code class="target-val">${inc.target_identifier}</code>
        </div>
      </div>

      <p class="incident-reason">${inc.reason}</p>

      <div class="incident-evidence-panel">
        <div class="evidence-header">
          <span class="evidence-title">Log Evidence (${inc.evidence_count} ${inc.evidence_count === 1 ? 'event' : 'events'})</span>
        </div>
        <div class="evidence-lines">
          ${lineBadges}
        </div>
      </div>

      <div class="incident-action-panel">
        <span class="action-label">Recommendation:</span>
        <span class="action-text">${inc.suggested_action}</span>
      </div>
    `;

    listContainer.appendChild(card);
  });
}

function returnToHome() {
  if (eventSource) eventSource.close();
  clearInterval(timerInterval);
  clearSelectedFile();
  sampleBtn.disabled = false;
  uploadSection.style.display = 'block';
  historySection.style.display = 'block';
  progressSection.style.display = 'none';
  reportSection.style.display = 'none';
  currentView = 'home';
  loadPastRuns();
}

// Nav link handler: only return home if NOT already on home page
if (navHomeLink) {
  navHomeLink.addEventListener('click', (e) => {
    e.preventDefault();
    if (currentView !== 'home') {
      returnToHome();
    }
  });
}

// 7. Export and Reset Actions
exportBtn.addEventListener('click', () => {
  if (!currentReport) return;
  const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(currentReport, null, 2));
  const dlAnchor = document.createElement('a');
  dlAnchor.setAttribute("href", dataStr);
  dlAnchor.setAttribute("download", `security_report_${currentJobId || 'export'}.json`);
  document.body.appendChild(dlAnchor);
  dlAnchor.click();
  dlAnchor.remove();
});

resetBtn.addEventListener('click', returnToHome);
