// Security Log Analyzer - Frontend Controller

let selectedFile = null;
let currentJobId = null;
let eventSource = null;
let currentReport = null;
let startTime = null;
let timerInterval = null;

// DOM Elements
const fileInput = document.getElementById('fileInput');
const dropzone = document.getElementById('dropzone');
const fileInfo = document.getElementById('fileInfo');
const startBtn = document.getElementById('startBtn');
const sampleBtn = document.getElementById('sampleBtn');
const uploadSection = document.getElementById('uploadSection');
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

// 1. Telemetry Polling
async function updateTelemetry() {
  try {
    const res = await fetch('/api/telemetry');
    if (!res.ok) return;
    const data = await res.json();
    if (procRamText) {
      procRamText.textContent = `${data.process_ram_mb} MB`;
    }
  } catch (err) {}
}
setInterval(updateTelemetry, 3000);
updateTelemetry();

// 2. File Selection & Drag-and-Drop
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
}

// 3. Start Analysis Actions
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

// 4. Stream Analysis Progress via SSE
function beginAnalysisStream(jobId, lineCount) {
  currentJobId = jobId;
  uploadSection.style.display = 'none';
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
        }
      } catch (err) {}
    }, 2000);
  };
}

// 5. Render Deduplicated Final Report
function renderReport(report) {
  progressSection.style.display = 'none';
  reportSection.style.display = 'block';

  const sum = report.summary || {};
  document.getElementById('kpiCritical').textContent = sum.severity_counts?.Critical || 0;
  document.getElementById('kpiHigh').textContent = sum.severity_counts?.High || 0;
  document.getElementById('kpiMedium').textContent = sum.severity_counts?.Medium || 0;
  document.getElementById('kpiLow').textContent = sum.severity_counts?.Low || 0;

  document.getElementById('reportSubtitle').textContent = 
    `${sum.total_lines_analyzed || 0} lines • ${sum.total_chunks_processed || 0} chunks • ${sum.total_analysis_time_seconds || 0}s • ${sum.total_tokens_used || 0} tokens`;

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

    const lineBadges = (inc.line_numbers || []).map(ln => `<span class="line-tag">L${ln}</span>`).join(' ');

    card.innerHTML = `
      <div class="incident-header">
        <span class="incident-title">${inc.attack_type}</span>
        <span class="sev-badge sev-${inc.severity}">${inc.severity}</span>
      </div>
      <div class="incident-meta">
        Target: <span class="incident-target">${inc.target_identifier}</span>
      </div>
      <div class="incident-reason">
        ${inc.reason}
      </div>
      <div class="incident-evidence">
        <strong>Lines (${inc.evidence_count}):</strong>
        ${lineBadges}
      </div>
      <div class="incident-action">
        <strong>Action:</strong> ${inc.suggested_action}
      </div>
    `;

    listContainer.appendChild(card);
  });
}

// 6. Export and Reset Actions
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

resetBtn.addEventListener('click', () => {
  if (eventSource) eventSource.close();
  clearInterval(timerInterval);
  selectedFile = null;
  fileInput.value = '';
  fileInfo.textContent = '';
  startBtn.disabled = true;
  sampleBtn.disabled = false;
  uploadSection.style.display = 'block';
  progressSection.style.display = 'none';
  reportSection.style.display = 'none';
});
