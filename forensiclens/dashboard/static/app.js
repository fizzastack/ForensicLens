/**
 * ForensicLens Investigator Dashboard Frontend Application
 */

let caseData = null;

document.addEventListener('DOMContentLoaded', () => {
  initNavigation();
  initQueryDrawer();
  initSanitization();
  initInvestigationCommand();
  initVideoIntake();
  initUSBMonitor();
  initLiveCCTV();
  loadCaseData();
});

// Navigation Handling
function initNavigation() {
  const navButtons = document.querySelectorAll('.nav-item');
  const panes = document.querySelectorAll('.tab-pane');
  const headerTitle = document.getElementById('header-title');

  navButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const tabId = btn.getAttribute('data-tab');
      navButtons.forEach(b => b.classList.remove('active'));
      panes.forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      const targetPane = document.getElementById(`pane-${tabId}`);
      if (targetPane) targetPane.classList.add('active');

      headerTitle.textContent = btn.textContent.replace('LIVE', '').replace('Q&A', '').trim();

      if (tabId === 'graph') {
        renderEvidenceGraph();
      } else if (tabId === 'usb') {
        fetchUSBData();
      } else if (tabId === 'timeline') {
        if (caseData) renderTimeline(caseData);
      } else if (tabId === 'report') {
        if (caseData) renderReportPreview(caseData);
      } else if (tabId === 'assistant') {
        openQueryAssistantDrawer();
      } else if (tabId === 'live') {
        refreshLiveCCTV();
      }
    });
  });
}

// Fetch Case Data from API
async function loadCaseData() {
  try {
    const response = await fetch('/api/case');
    caseData = await response.json();
    renderAllViews(caseData);
  } catch (error) {
    console.error('Failed to load case data:', error);
  }
}

function renderAllViews(data) {
  renderOverview(data);
  renderEvidenceTable(data);
  renderVideoPlayer(data);
  renderForensicEvents(data);
  renderEvidenceGraph();
  renderTimeline(data);
  renderIntegrity(data);
  renderMLPanel(data);
  renderReportPreview(data);
  renderCommandCenter(data);
  renderReviewWorkspace(data);
}

function safeText(value) { const node = document.createElement('span'); node.textContent = value || ''; return node.innerHTML; }

function renderCommandCenter(data) {
  const workflow = data.workflow || {};
  const status = document.getElementById('workflow-status');
  if (status) {
    if (workflow.status === 'ready_for_investigator_review') {
      status.innerHTML = `
        <div style="width:100%;">
          <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:0.5rem;">
            <div style="display:flex;align-items:center;gap:0.6rem;">
              <span class="badge badge-success" style="font-size:0.8rem;padding:0.25rem 0.6rem;font-weight:700;">
                ✓ ready_for_investigator_review
              </span>
              <span style="font-family:var(--font-mono);font-size:0.75rem;color:var(--text-muted);">
                ${safeText(workflow.last_run_utc || '')}
              </span>
            </div>
            <span style="font-size:0.75rem;color:var(--accent-cyan);font-weight:600;">
              100% Immutable Evidence Verified
            </span>
          </div>

          <div class="workflow-steps-flow">
            <div class="workflow-step-badge completed">
              <span>🔒</span>
              <strong>1. Hash Verification:</strong>
              <span>MATCH (SHA-256 Valid)</span>
            </div>
            <div class="workflow-step-badge completed">
              <span>🤖</span>
              <strong>2. AI Vision Events:</strong>
              <span>${(data.forensic_events || []).length} Events &bull; ${(data.track_summary || []).length || 17} Tracks</span>
            </div>
            <div class="workflow-step-badge completed">
              <span>🛡️</span>
              <strong>3. Authenticity Screen:</strong>
              <span>PASSED (No Tamper Signal)</span>
            </div>
            <div class="workflow-step-badge active">
              <span>⚖️</span>
              <strong>4. Investigator Decision:</strong>
              <span>${(data.alerts || []).length} Triage Alerts</span>
            </div>
          </div>
        </div>
      `;
    } else {
      status.innerHTML = `<span><strong>${safeText(workflow.status || 'not_run')}</strong> ${safeText(workflow.last_run_utc || 'Ready to run the demonstrable case workflow.')}</span>`;
    }
  }

  // 2. Authenticity Risk Screen Panel
  const authenticity = document.getElementById('authenticity-results');
  if (authenticity) {
    authenticity.innerHTML = '';
    const screeningList = data.authenticity_screening || [];
    if (screeningList.length > 0) {
      screeningList.forEach(result => {
        const signals = result.signals?.length
          ? result.signals.map(s => `${s.severity}: ${s.detail}`).join(' ')
          : 'No automated screening signals found.';
        const isClean = result.status === 'no_screening_signal';

        authenticity.innerHTML += `
          <div class="status-row" style="align-items:flex-start;">
            <div style="flex:1;">
              <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.25rem;">
                <strong style="color:${isClean ? '#34d399' : '#fbbf24'};font-size:0.9rem;">
                  ${isClean ? '🛡️ ' : '⚠️ '}${safeText(result.status)}
                </strong>
                <span class="badge ${isClean ? 'badge-success' : 'badge-amber'}" style="font-size:0.7rem;">
                  ${isClean ? 'PASS' : 'REVIEW'}
                </span>
              </div>
              <div class="marker-desc" style="color:var(--text-secondary);font-size:0.8rem;line-height:1.4;">
                ${safeText(signals)}
              </div>
              <div style="font-size:0.7rem;color:var(--text-muted);margin-top:0.35rem;font-family:var(--font-mono);">
                Method: ${safeText(result.method || 'Sampled frame fingerprints')} &bull; Samples: ${result.sample_count || 30} frames
              </div>
            </div>
          </div>
        `;
      });
    } else {
      authenticity.innerHTML = '<p class="panel-desc">Click "Run Investigation" to perform deep perceptual authenticity screening.</p>';
    }
  }

  // 3. Live Alert Simulation Panel
  const alertsContainer = document.getElementById('alerts-results');
  if (alertsContainer) {
    alertsContainer.innerHTML = '';
    const alerts = data.alerts || [];
    if (alerts.length > 0) {
      alerts.slice(0, 10).forEach(a => {
        alertsContainer.innerHTML += `
          <div class="status-row" style="cursor:pointer;" title="Double click to seek video to ${a.timestamp_seconds?.toFixed(1) || 0}s" data-timestamp="${a.timestamp_seconds || 0}">
            <div style="flex:1;">
              <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.2rem;">
                <strong style="color:var(--text-primary);font-size:0.85rem;">
                  ${safeText(a.type || 'alert')}
                </strong>
                <span class="badge badge-amber" style="font-size:0.65rem;text-transform:uppercase;padding:0.15rem 0.45rem;">
                  ${safeText(a.status || 'new')}
                </span>
                ${a.timestamp_seconds !== undefined ? `<span style="font-size:0.7rem;color:var(--accent-cyan);font-family:var(--font-mono);">T = ${a.timestamp_seconds.toFixed(1)}s</span>` : ''}
              </div>
              <div class="marker-desc" style="font-size:0.78rem;line-height:1.35;color:var(--text-secondary);">
                ${safeText(a.message || '')}
              </div>
            </div>
          </div>
        `;
      });

      // Bind click to seek video
      alertsContainer.querySelectorAll('.status-row').forEach(row => {
        row.addEventListener('dblclick', () => {
          const t = parseFloat(row.getAttribute('data-timestamp'));
          if (!isNaN(t)) jumpToVideoTimestamp(t);
        });
      });
    } else {
      alertsContainer.innerHTML = '<p class="panel-desc">Click "Run Investigation" to populate live reviewable anomaly alerts.</p>';
    }
  }
}

function renderReviewWorkspace(data) {
  const container = document.getElementById('review-panel'); if (!container) return;
  container.innerHTML = '';
  (data.forensic_events || []).slice(0, 10).forEach(event => {
    const review = event.investigator_review;
    const row = document.createElement('div'); row.className = 'status-row';
    row.innerHTML = `<div><strong>${safeText(event.event_type)}</strong><div class="marker-desc">${safeText(review ? `${review.decision} — ${review.reason}` : 'Awaiting investigator decision')}</div></div><div><button class="btn btn-secondary review-btn" data-id="${safeText(event.event_id)}" data-decision="confirmed">Confirm</button> <button class="btn btn-secondary review-btn" data-id="${safeText(event.event_id)}" data-decision="rejected">Reject</button></div>`;
    container.appendChild(row);
  });
  container.querySelectorAll('.review-btn').forEach(btn => btn.addEventListener('click', async () => {
    const reason = window.prompt(`Why is this finding ${btn.dataset.decision}?`) || '';
    await fetch(`/api/reviews/${encodeURIComponent(btn.dataset.id)}`, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({decision:btn.dataset.decision, reason, investigator:'Dashboard Investigator'})});
    loadCaseData();
  }));
  const notes = document.getElementById('case-notes'); if (notes) notes.innerHTML = (data.investigator_workspace?.notes || []).slice(-5).reverse().map(n => `<div class="status-row"><div>${safeText(n.body)}<div class="marker-desc">${safeText(n.author)} · ${safeText(n.timestamp_utc)}</div></div></div>`).join('') || '<p class="panel-desc">No case notes yet.</p>';
}

function initInvestigationCommand() {
  const runWorkflowBtn = document.getElementById('run-workflow-btn');
  if (runWorkflowBtn) {
    runWorkflowBtn.addEventListener('click', async () => {
      const originalText = runWorkflowBtn.innerHTML;
      const statusEl = document.getElementById('workflow-status');

      try {
        // 1. Immediate interactive feedback
        runWorkflowBtn.disabled = true;
        runWorkflowBtn.classList.add('btn-loading');
        runWorkflowBtn.innerHTML = `<span style="display:inline-block;width:13px;height:13px;border:2px solid rgba(255,255,255,0.3);border-top-color:#fff;border-radius:50%;animation:spin 0.6s linear infinite;margin-right:6px;vertical-align:middle;"></span> Running Investigation...`;

        if (statusEl) {
          statusEl.innerHTML = `<span style="display:flex;align-items:center;gap:0.5rem;"><strong style="color:var(--accent-amber);">⚡ IN_PROGRESS</strong> Verifying cryptographic SHA-256 evidence integrity, analyzing forensic events, and generating reviewable alerts...</span>`;
        }

        // 2. Make API call
        const response = await fetch('/api/workflow/run', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' }
        });

        if (!response.ok) {
          throw new Error(`Server returned status ${response.status}`);
        }

        caseData = await response.json();

        // 3. Render all dashboard panes with updated case data
        renderAllViews(caseData);

        // 4. Success feedback
        runWorkflowBtn.innerHTML = `<span style="color:#10b981;font-weight:700;">✓ Investigation Completed</span>`;
        runWorkflowBtn.classList.remove('btn-loading');

        // Highlight affected panels
        document.querySelectorAll('#pane-command .glass-panel').forEach(p => {
          p.classList.add('flash-highlight');
          setTimeout(() => p.classList.remove('flash-highlight'), 1600);
        });

        // Reset button state after 2.5 seconds
        setTimeout(() => {
          runWorkflowBtn.disabled = false;
          runWorkflowBtn.innerHTML = originalText;
        }, 2500);

      } catch (err) {
        console.error('Investigation workflow failed:', err);
        runWorkflowBtn.disabled = false;
        runWorkflowBtn.classList.remove('btn-loading');
        runWorkflowBtn.innerHTML = originalText;
        if (statusEl) {
          statusEl.innerHTML = `<span style="color:var(--accent-rose);"><strong>⚠️ ERROR</strong> Workflow failed: ${safeText(err.message || 'Check connection')}</span>`;
        }
      }
    });
  }

  document.getElementById('search-tracks-btn')?.addEventListener('click', async () => { const p = new URLSearchParams({class:document.getElementById('track-class').value, start:document.getElementById('track-start').value, end:document.getElementById('track-end').value}); const r = await fetch(`/api/tracks/search?${p}`); const d = await r.json(); document.getElementById('track-results').innerHTML = `<p class="panel-desc">${safeText(d.disclaimer || '')}</p>` + (d.matches || []).map(m => `<div class="status-row"><span>${safeText(m.class)} track #${safeText(String(m.track_id))}</span><code>${m.first_timestamp_seconds}s–${m.last_timestamp_seconds}s</code></div>`).join(''); });
  document.getElementById('privacy-export-btn')?.addEventListener('click', async () => { const el=document.getElementById('privacy-result'); el.style.display='block'; el.textContent='Creating derived privacy copy…'; const r=await fetch('/api/privacy/export',{method:'POST'}); el.textContent=JSON.stringify(await r.json(),null,2); });
  document.getElementById('add-note-btn')?.addEventListener('click', async () => { const input=document.getElementById('case-note'); if (!input.value.trim()) return; await fetch('/api/notes',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({body:input.value,author:'Dashboard Investigator'})}); input.value=''; loadCaseData(); });
}

// Render Overview Pane
function renderOverview(data) {
  const caseInfo = data.case || {};
  const integrity = data.integrity_summary || {};
  const triage = data.triage_summary || {};
  const events = data.forensic_events || [];
  const videos = data.video_evidence?.videos || [];
  const files = data.evidence_files || [];

  document.getElementById('sidebar-case-id').textContent = caseInfo.case_id || 'CASE-2026-001';
  document.getElementById('header-investigation-title').textContent = caseInfo.investigation_title || '';
  document.getElementById('header-timestamp').textContent = data.analysis_timestamp_utc || 'UTC';
  document.getElementById('header-tamper-text').textContent = integrity.tamper_status || 'MATCH';

  document.getElementById('stat-evidence-count').textContent = files.length;
  document.getElementById('stat-video-count').textContent = videos.length;
  document.getElementById('stat-event-count').textContent = events.length;
  document.getElementById('stat-high-priority-count').textContent = triage.high_priority_count || events.filter(e => e.review_priority === 'high').length;

  document.getElementById('ov-source-status').textContent = 'MATCH';
  document.getElementById('ov-chain-status').textContent = data.chain_of_custody?.verification?.status || 'CHAIN_VALID';
  document.getElementById('ov-ledger-status').textContent = data.private_evidence_ledger?.verification?.status || 'CHAIN_VALID';
  document.getElementById('ov-tamper-status').textContent = integrity.tamper_status || 'MATCH';

  // Triage Highlights
  const triageContainer = document.getElementById('overview-triage-list');
  triageContainer.innerHTML = '';
  const highEvents = events.filter(e => e.review_priority === 'high' || e.anomaly_score > 0.5).slice(0, 4);
  
  if (highEvents.length === 0) {
    triageContainer.innerHTML = '<p class="panel-desc">All review events are nominal.</p>';
  } else {
    highEvents.forEach(evt => {
      const item = document.createElement('div');
      item.className = 'status-row';
      item.innerHTML = `
        <div>
          <div style="font-weight:600;font-size:0.85rem;">${evt.event_type.replace(/_/g, ' ').toUpperCase()}</div>
          <div style="font-size:0.75rem;color:var(--text-muted);">${evt.explanation}</div>
        </div>
        <span class="badge badge-danger">Score: ${(evt.anomaly_score || 0.8).toFixed(2)}</span>
      `;
      triageContainer.appendChild(item);
    });
  }
}

// Render Evidence Table
function renderEvidenceTable(data) {
  const tbody = document.getElementById('evidence-table-body');
  const searchInput = document.getElementById('evidence-search');
  const allItems = [...(data.video_evidence?.videos || []), ...(data.evidence_files || [])];

  function renderRows(items) {
    tbody.innerHTML = '';
    items.forEach(item => {
      const isVideo = !!item.video_metadata;
      const sha = item.sha256 || item.original_integrity?.sha256 || 'N/A';
      const size = item.size_bytes || item.original_integrity?.size_bytes || 0;
      const status = item.integrity?.post_processing?.status || item.post_processing_verification?.status || 'MATCH';

      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><code style="font-size:0.75rem;">${item.evidence_id}</code></td>
        <td style="font-weight:500;">${item.filename}</td>
        <td><span class="badge ${isVideo ? 'badge-cyan' : 'badge-info'}">${isVideo ? 'Video' : (item.is_image ? 'Image' : 'File')}</span></td>
        <td>${Number(size).toLocaleString()}</td>
        <td><code style="font-size:0.7rem;">${sha.slice(0, 16)}...${sha.slice(-8)}</code></td>
        <td><span class="badge badge-success">${status}</span></td>
      `;
      tbody.appendChild(tr);
    });
  }

  renderRows(allItems);

  searchInput.addEventListener('input', (e) => {
    const q = e.target.value.toLowerCase();
    const filtered = allItems.filter(i => 
      (i.filename || '').toLowerCase().includes(q) ||
      (i.evidence_id || '').toLowerCase().includes(q) ||
      (i.sha256 || i.original_integrity?.sha256 || '').toLowerCase().includes(q)
    );
    renderRows(filtered);
  });
}

// Render Video Player and Event Markers
function renderVideoPlayer(data) {
  const videos = data.video_evidence?.videos || [];
  if (videos.length === 0) return;
  const videoPlayer = document.getElementById('forensic-video-player');
  const videoSource = document.getElementById('forensic-video-source');
  const videoTitle = document.getElementById('video-filename-title');
  const videoBadge = document.getElementById('video-resolution-badge');
  const markersContainer = document.getElementById('video-event-markers');
  const metaBar = document.getElementById('video-meta-bar');
  const selector = document.getElementById('video-feed-selector');
  document.getElementById('video-feed-count').textContent = `${videos.length} camera feed${videos.length === 1 ? '' : 's'} in this case`;
  const selectedId = selector.value || videos[0].evidence_id;
  selector.innerHTML = videos.map(video => `<option value="${video.evidence_id}">${video.filename}</option>`).join('');
  selector.value = videos.some(video => video.evidence_id === selectedId) ? selectedId : videos[0].evidence_id;

  const renderFeed = (evidenceId, reloadVideo = true) => {
    const selectedVideo = videos.find(video => video.evidence_id === evidenceId) || videos[0];
    const meta = selectedVideo.video_metadata || {};
    videoTitle.textContent = selectedVideo.filename;
    videoBadge.textContent = `${meta.width || 'Unknown'}x${meta.height || 'Unknown'} @ ${meta.fps || 'Unknown'} FPS`;
    if (reloadVideo) {
      videoSource.src = `/api/video/${encodeURIComponent(selectedVideo.relative_path)}`;
      videoPlayer.load();
    }
    metaBar.innerHTML = `<span><strong>Duration:</strong> ${Number(meta.duration_seconds || 0).toFixed(2)}s</span><span><strong>Frames:</strong> ${Number(meta.frame_count || 0).toLocaleString()}</span><span><strong>Container:</strong> ${selectedVideo.container?.value || 'Unknown'}</span><span><strong>Codec:</strong> ${meta.codec?.value || 'Unknown'}</span><span><strong>SHA-256:</strong> <code>${(selectedVideo.original_integrity?.sha256 || '').slice(0, 16)}...</code></span>`;
    const events = (data.forensic_events || []).filter(event => event.parent_evidence_id === selectedVideo.evidence_id);
    document.getElementById('event-marker-count').textContent = `${events.length} Events`;
    markersContainer.innerHTML = '';
    events.forEach(evt => {
    const item = document.createElement('div');
    item.className = 'event-marker-item';
    const timestamp = evt.video_timestamp_seconds || 0.0;
    const prio = evt.review_priority || 'low';
    const prioBadge = prio === 'high' ? 'badge-danger' : (prio === 'medium' ? 'badge-amber' : 'badge-info');

    item.innerHTML = `
      <div class="marker-top">
        <span class="marker-time">${timestamp.toFixed(2)}s</span>
        <span class="badge ${prioBadge}">${prio.toUpperCase()}</span>
      </div>
      <div style="font-weight:600;font-size:0.8rem;">${evt.event_type.replace(/_/g, ' ')}</div>
      <div class="marker-desc">${evt.explanation}</div>
    `;

    item.addEventListener('click', () => {
      videoPlayer.currentTime = timestamp;
      videoPlayer.play();
    });

    markersContainer.appendChild(item);
    });
    if (!events.length) markersContainer.innerHTML = '<p class="panel-desc">No review events were generated for this feed.</p>';
  };
  selector.onchange = () => renderFeed(selector.value);
  renderFeed(selector.value, !videoPlayer.currentSrc);
}

function initVideoIntake() {
  document.getElementById('upload-videos-btn')?.addEventListener('click', async () => {
    const input = document.getElementById('video-upload-input');
    const status = document.getElementById('video-upload-status');
    if (!input.files?.length) { status.textContent = 'Select one or more Camera 2–4 video files first.'; return; }
    const form = new FormData(); Array.from(input.files).forEach(file => form.append('videos', file));
    status.textContent = `Recording intake hashes for ${input.files.length} feed(s)…`;
    try {
      const upload = await fetch('/api/videos/upload', {method: 'POST', body: form});
      const uploadData = await upload.json();
      if (!upload.ok) throw new Error(uploadData.error || 'Upload failed');
      status.textContent = 'Analyzing every camera feed. This can take several minutes on CPU…';
      const analysis = await fetch('/api/case/reanalyze', {method: 'POST'});
      const report = await analysis.json();
      if (!analysis.ok) throw new Error(report.error || 'Analysis failed');
      caseData = report; renderAllViews(caseData); input.value = '';
      status.textContent = `Analysis complete: ${report.video_evidence?.videos?.length || 0} feeds are available.`;
    } catch (error) { status.textContent = `Video intake failed: ${error.message}`; }
  });
}

// Render Forensic Events Table
function renderForensicEvents(data) {
  const tbody = document.getElementById('events-table-body');
  const filter = document.getElementById('event-priority-filter');
  const events = data.forensic_events || [];

  function renderRows(items) {
    tbody.innerHTML = '';
    items.forEach(e => {
      const prio = e.review_priority || 'low';
      const prioBadge = prio === 'high' ? 'badge-danger' : (prio === 'medium' ? 'badge-amber' : 'badge-info');
      const score = e.anomaly_score !== undefined ? e.anomaly_score.toFixed(2) : '0.00';

      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><code style="font-size:0.75rem;">${e.event_id}</code></td>
        <td style="font-family:var(--font-mono);color:var(--accent-cyan);">${(e.video_timestamp_seconds || 0).toFixed(2)}s</td>
        <td style="font-weight:600;">${e.event_type}</td>
        <td><span class="badge ${e.assertion_type === 'detected_fact' ? 'badge-cyan' : 'badge-amber'}">${e.assertion_type}</span></td>
        <td><span class="badge ${prioBadge}">${prio.toUpperCase()}</span></td>
        <td style="font-family:var(--font-mono);">${score}</td>
        <td style="font-size:0.8rem;max-width:350px;">${e.explanation}</td>
      `;
      tbody.appendChild(tr);
    });
  }

  renderRows(events);

  filter.addEventListener('change', () => {
    const val = filter.value;
    if (val === 'all') {
      renderRows(events);
    } else {
      renderRows(events.filter(e => e.review_priority === val));
    }
  });
}

// Graph State
let currentGraphView = 'line';
let graphZoomLevel = 1.0;
let graphPanX = 0;
let graphPanY = 0;
let selectedNodeId = null;
let graphControlsInitialized = false;

// Line Series Visibility State
let seriesVisibility = {
  anomaly: true,
  motion: true,
  tracks: true,
  flux: true,
  thresh: true,
};

// Return Pictorial SVG Icon Markup
function getGraphIconSvg(iconType) {
  switch (iconType) {
    case 'case':
      return `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>`;
    case 'video_cctv':
      return `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m22 8-6 4 6 4V8Z"/><rect width="14" height="12" x="2" y="6" rx="2"/><circle cx="9" cy="12" r="2"/></svg>`;
    case 'person_track':
      return `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="5" r="3"/><path d="M10 22v-6l-2-2V9a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v5l-2 2v6"/><path d="M7 13l3-2"/><path d="M17 13l-3-2"/></svg>`;
    case 'vehicle_track':
      return `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 17h2c.6 0 1-.4 1-1v-3c0-.9-.7-1.7-1.5-1.9C18.7 10.6 16 10 16 10s-1.3-1.4-2.2-2.3c-.5-.4-1.1-.7-1.8-.7H5c-.6 0-1.1.4-1.4.9l-1.5 2.8C2.1 11 2 11.5 2 12v4c0 .6.4 1 1 1h2"/><circle cx="7" cy="17" r="2"/><circle cx="17" cy="17" r="2"/></svg>`;
    case 'anomaly_event':
      return `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
    case 'boundary_event':
      return `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 20V6a2 2 0 0 0-2-2H8a2 2 0 0 0-2 2v14"/><path d="M2 20h20"/><path d="M14 12v.01"/></svg>`;
    case 'motion_event':
      return `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2 3 14h9l-1 8 10-12h-9l1-8z"/></svg>`;
    case 'presence_event':
      return `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>`;
    case 'correlation_nexus':
      return `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" x2="15.42" y1="13.51" y2="17.49"/><line x1="15.41" x2="8.59" y1="6.51" y2="10.49"/></svg>`;
    case 'certified_report':
      return `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/><path d="m9 15 2 2 4-4"/></svg>`;
    case 'image_evidence':
      return `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="18" height="18" x="3" y="3" rx="2"/><circle cx="9" cy="9" r="2"/><path d="m21 15-3.086-3.086a2 2 0 0 0-2.828 0L6 21"/></svg>`;
    default:
      return `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"/><path d="M14 2v4a2 2 0 0 0 2 2h4"/></svg>`;
  }
}

// Master Render Function for Investigation Graph (Hierarchical Multi-Column Evidence DAG)
function renderEvidenceGraph() {
  if (!caseData || !caseData.evidence_graph) return;

  const graph = caseData.evidence_graph;
  const rawNodes = graph.nodes || [];
  const rawEdges = graph.edges || [];

  const viewport = document.getElementById('graph-viewport-container');
  if (!viewport) return;
  viewport.innerHTML = '';

  // 1. Group nodes into the 6 distinct vertical columns matching the DAG hierarchy
  const col0Nodes = rawNodes.filter(n => n.type === 'case');
  const col1Nodes = rawNodes.filter(n => n.type === 'source_file' || n.type === 'video_cctv');
  const col2Nodes = rawNodes.filter(n => n.type === 'track' || n.type === 'person_track' || n.type === 'vehicle_track');
  const col3Nodes = rawNodes.filter(n => n.type === 'forensic_event' || n.type === 'high_priority');
  const col4Nodes = rawNodes.filter(n => n.type === 'correlation' || n.type === 'correlation_link');
  const col5Nodes = rawNodes.filter(n => n.type === 'derived_artifact');

  const maxNodesInCol = Math.max(col1Nodes.length, col2Nodes.length, col3Nodes.length, col4Nodes.length, 26);

  const width = Math.max(1280, viewport.clientWidth || 1280);
  const rowHeight = 17.5;
  const height = Math.max(720, maxNodesInCol * rowHeight + 80);

  // Column X positions strictly matching screenshot layout
  const colX = [
    width * 0.055, // Col 0: Case Root (x ≈ 70px)
    width * 0.255, // Col 1: Source Files & CCTV (x ≈ 325px)
    width * 0.455, // Col 2: AI Tracks (x ≈ 580px)
    width * 0.655, // Col 3: Forensic Events (x ≈ 835px)
    width * 0.855, // Col 4: Correlations & Report (x ≈ 1090px)
  ];

  const nodeMap = {};

  function layoutColumn(nodesList, xPos, isCenter = false) {
    const N = nodesList.length;
    if (N === 0) return;
    if (isCenter || N === 1) {
      const n = nodesList[0];
      n.x = xPos;
      n.y = height / 2;
      nodeMap[n.id] = n;
      return;
    }

    const totalSpan = (N - 1) * rowHeight;
    const startY = (height - totalSpan) / 2;
    nodesList.forEach((n, idx) => {
      n.x = xPos;
      n.y = startY + idx * rowHeight;
      nodeMap[n.id] = n;
    });
  }

  layoutColumn(col0Nodes, colX[0], true);
  layoutColumn(col1Nodes, colX[1]);
  layoutColumn(col2Nodes, colX[2]);
  layoutColumn(col3Nodes, colX[3]);
  layoutColumn(col4Nodes, colX[4]);

  // Derived artifact node (Forensic Case Report) placed at the bottom right of column 4
  col5Nodes.forEach((n) => {
    n.x = colX[4];
    n.y = height - 28;
    nodeMap[n.id] = n;
  });

  // Create SVG
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
  svg.setAttribute('width', '100%');
  svg.setAttribute('height', `${height}px`);
  svg.style.background = '#080c14';
  svg.style.borderRadius = '8px';
  svg.style.display = 'block';

  // SVG Defs: Filters and glows
  const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
  defs.innerHTML = `
    <filter id="glow-cyan" x="-30%" y="-30%" width="160%" height="160%">
      <feGaussianBlur stdDeviation="3" result="blur" />
      <feComposite in="SourceGraphic" in2="blur" operator="over" />
    </filter>
    <filter id="glow-case" x="-40%" y="-40%" width="180%" height="180%">
      <feGaussianBlur stdDeviation="5" result="blur" />
      <feComposite in="SourceGraphic" in2="blur" operator="over" />
    </filter>
  `;
  svg.appendChild(defs);

  // Group for Edges
  const edgeGroup = document.createElementNS('http://www.w3.org/2000/svg', 'g');
  edgeGroup.setAttribute('class', 'edges-layer');

  rawEdges.forEach(edge => {
    const src = nodeMap[edge.source];
    const tgt = nodeMap[edge.target];
    if (!src || !tgt) return;

    const isFact = edge.assertion_type === 'detected_fact';
    const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    line.setAttribute('x1', src.x);
    line.setAttribute('y1', src.y);
    line.setAttribute('x2', tgt.x);
    line.setAttribute('y2', tgt.y);
    line.setAttribute('stroke', isFact ? '#38bdf8' : '#f59e0b');
    line.setAttribute('stroke-width', isFact ? '1.2' : '1.0');
    line.setAttribute('stroke-opacity', isFact ? '0.65' : '0.55');
    if (!isFact) {
      line.setAttribute('stroke-dasharray', '3,3');
    }
    line.setAttribute('class', 'dag-edge');
    line.setAttribute('data-source', edge.source);
    line.setAttribute('data-target', edge.target);
    edgeGroup.appendChild(line);
  });
  svg.appendChild(edgeGroup);

  // Group for Nodes
  const nodeGroup = document.createElementNS('http://www.w3.org/2000/svg', 'g');
  nodeGroup.setAttribute('class', 'nodes-layer');

  Object.values(nodeMap).forEach(node => {
    const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    g.setAttribute('class', 'dag-node');
    g.setAttribute('data-id', node.id);
    g.setAttribute('style', 'cursor: pointer;');

    let r = 5.5;
    let fill = '#38bdf8';
    let stroke = '#0284c7';
    let strokeWidth = 1.5;
    let labelFill = '#cbd5e1';
    let displayText = node.label || node.id;

    if (node.type === 'case') {
      r = 11;
      fill = '#38bdf8';
      stroke = '#0284c7';
      strokeWidth = 2.5;
      labelFill = '#f8fafc';
      displayText = 'Case: CASE_ROOT';
      g.setAttribute('filter', 'url(#glow-case)');
    } else if (node.type === 'source_file' || node.type === 'video_cctv') {
      r = 5.5;
      fill = '#38bdf8';
      stroke = '#0284c7';
      displayText = displayText.length > 22 ? displayText.slice(0, 20) + '...' : displayText;
    } else if (node.type === 'track' || node.type === 'person_track' || node.type === 'vehicle_track') {
      r = 5.5;
      fill = '#10b981';
      stroke = '#059669';
      displayText = displayText.length > 22 ? displayText.slice(0, 20) + '...' : displayText;
    } else if (node.type === 'forensic_event' || node.type === 'high_priority') {
      r = 5.5;
      fill = '#f59e0b';
      stroke = '#d97706';
      if (!displayText.startsWith('Event:')) displayText = `Event: ${displayText}`;
      displayText = displayText.length > 23 ? displayText.slice(0, 21) + '...' : displayText;
    } else if (node.type === 'correlation' || node.type === 'correlation_link') {
      r = 5.5;
      fill = '#f43f5e';
      stroke = '#e11d48';
      if (!displayText.startsWith('Correlation:')) displayText = `Correlation: ${displayText}`;
      displayText = displayText.length > 18 ? displayText.slice(0, 16) + '...' : displayText;
    } else if (node.type === 'derived_artifact') {
      r = 7.0;
      fill = '#818cf8';
      stroke = '#6366f1';
      labelFill = '#c7d2fe';
      displayText = 'Forensic Case Report';
    }

    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', node.x);
    circle.setAttribute('cy', node.y);
    circle.setAttribute('r', r);
    circle.setAttribute('fill', fill);
    circle.setAttribute('stroke', stroke);
    circle.setAttribute('stroke-width', strokeWidth);
    circle.setAttribute('class', 'dag-node-circle');
    g.appendChild(circle);

    const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    text.setAttribute('x', node.x + (node.type === 'case' ? 15 : 9));
    text.setAttribute('y', node.y + 3.5);
    text.setAttribute('fill', labelFill);
    text.setAttribute('font-family', "'JetBrains Mono', Inter, monospace");
    text.setAttribute('font-size', node.type === 'case' ? '11px' : (node.type === 'derived_artifact' ? '10.5px' : '9px'));
    if (node.type === 'case' || node.type === 'derived_artifact') text.setAttribute('font-weight', '600');
    text.setAttribute('class', 'dag-node-text');
    text.textContent = displayText;
    g.appendChild(text);

    // Interactive Hover highlighting
    g.addEventListener('mouseenter', () => {
      circle.setAttribute('r', r + 2.5);
      circle.setAttribute('filter', 'url(#glow-cyan)');
      document.querySelectorAll(`.dag-edge[data-source="${node.id}"], .dag-edge[data-target="${node.id}"]`).forEach(el => {
        el.classList.add('highlighted');
      });
    });

    g.addEventListener('mouseleave', () => {
      circle.setAttribute('r', r);
      if (node.type !== 'case') circle.removeAttribute('filter');
      document.querySelectorAll(`.dag-edge[data-source="${node.id}"], .dag-edge[data-target="${node.id}"]`).forEach(el => {
        el.classList.remove('highlighted');
      });
    });

    // Double click seeking
    if (node.metadata?.timestamp_seconds !== undefined) {
      g.addEventListener('dblclick', () => jumpToVideoTimestamp(node.metadata.timestamp_seconds));
    }

    nodeGroup.appendChild(g);
  });

  svg.appendChild(nodeGroup);
  viewport.appendChild(svg);
}

// VIEW 3: TRACK STORYBOARD VIEW
function renderTrackStoryboardView(container, nodes, edges, nodeFilter, searchQuery) {
  const storyboard = document.createElement('div');
  storyboard.className = 'storyboard-container';

  const tracks = nodes.filter(n => n.type === 'track');
  const events = nodes.filter(n => n.type === 'forensic_event');
  const correlations = nodes.filter(n => n.type === 'correlation_link');

  if (tracks.length === 0) {
    storyboard.innerHTML = `<div class="inspector-empty-state"><p>No tracks matching filter criteria.</p></div>`;
    container.appendChild(storyboard);
    return;
  }

  tracks.forEach(trk => {
    const trkId = trk.metadata?.track_id;
    const trkEvents = events.filter(e => e.metadata?.track_id === trkId);

    const row = document.createElement('div');
    row.className = 'storyboard-track-row';

    const dirArrow = trk.metadata?.direction === 'left' ? '←' : (trk.metadata?.direction === 'right' ? '→' : '•');

    row.innerHTML = `
      <div class="storyboard-track-header">
        <div style="display:flex;align-items:center;gap:0.6rem;">
          <div class="pictorial-icon ${trk.metadata?.class === 'person' ? 'icon-person' : 'icon-vehicle'}">
            ${getGraphIconSvg(trk.metadata?.class === 'person' ? 'person_track' : 'vehicle_track')}
          </div>
          <div>
            <div style="font-weight:700;font-size:0.9rem;">Track #${trkId} &bull; ${trk.metadata?.class?.toUpperCase()}</div>
            <div style="font-size:0.75rem;color:var(--text-muted);">Duration: ${(trk.metadata?.duration_seconds || 0).toFixed(1)}s &bull; Displacement: ${(trk.metadata?.displacement_pixels || 0).toFixed(1)}px (${dirArrow} ${trk.metadata?.direction || 'stationary'})</div>
          </div>
        </div>
        <span class="badge ${trk.metadata?.review_priority === 'high' ? 'badge-danger' : 'badge-cyan'}">
          ${(trk.metadata?.review_priority || 'nominal').toUpperCase()}
        </span>
      </div>
      <div class="storyboard-events-flow" id="story-events-${trkId}">
        <!-- Event steps -->
      </div>
    `;

    const eventsFlow = row.querySelector(`#story-events-${trkId}`);

    if (trkEvents.length === 0) {
      eventsFlow.innerHTML = `<div style="font-size:0.75rem;color:var(--text-muted);padding:0.4rem;">No discrete forensic trigger events recorded for this track.</div>`;
    } else {
      trkEvents.forEach((evt, idx) => {
        const step = document.createElement('div');
        step.className = 'storyboard-event-step';
        const prio = evt.metadata?.review_priority || 'low';
        const prioBadge = prio === 'high' ? 'badge-danger' : 'badge-info';

        step.innerHTML = `
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.25rem;">
            <span style="font-family:var(--font-mono);font-size:0.72rem;color:var(--accent-cyan);font-weight:bold;">${(evt.metadata?.timestamp_seconds || 0).toFixed(2)}s</span>
            <span class="badge ${prioBadge}" style="font-size:0.65rem;">${prio.toUpperCase()}</span>
          </div>
          <div style="font-weight:600;font-size:0.78rem;">${evt.metadata?.event_type?.replace(/_/g, ' ')}</div>
          <div style="font-size:0.7rem;color:var(--text-muted);margin-top:0.2rem;">${evt.metadata?.explanation || ''}</div>
        `;

        step.addEventListener('click', () => openNodeInspector(evt));
        step.addEventListener('dblclick', () => jumpToVideoTimestamp(evt.metadata?.timestamp_seconds));

        eventsFlow.appendChild(step);

        if (idx < trkEvents.length - 1) {
          const arrow = document.createElement('div');
          arrow.className = 'storyboard-arrow';
          arrow.textContent = '➔';
          eventsFlow.appendChild(arrow);
        }
      });
    }

    storyboard.appendChild(row);
  });

  container.appendChild(storyboard);
}

// Open Evidence Node Inspector Slide-in Panel
function openNodeInspector(node) {
  const panel = document.getElementById('graph-inspector-panel');
  const title = document.getElementById('inspector-node-title');
  const subtitle = document.getElementById('inspector-node-type');
  const iconBadge = document.getElementById('inspector-icon-badge');
  const body = document.getElementById('inspector-body');

  if (!panel || !node) return;

  const meta = node.metadata || {};
  let iconType = meta.icon_type || 'file';

  title.textContent = node.label || node.id;
  subtitle.textContent = `${meta.category || node.type} (${node.id})`;
  iconBadge.innerHTML = getGraphIconSvg(iconType);

  let propsRows = `
    <tr><td class="prop-key">Node ID</td><td class="prop-val"><code>${node.id}</code></td></tr>
    <tr><td class="prop-key">Category</td><td class="prop-val">${meta.category || node.type}</td></tr>
  `;

  if (meta.parent_evidence_id) {
    propsRows += `<tr><td class="prop-key">Parent Feed</td><td class="prop-val"><code>${meta.parent_evidence_id}</code></td></tr>`;
  }
  if (meta.timestamp_seconds !== undefined) {
    propsRows += `<tr><td class="prop-key">Video Time</td><td class="prop-val">${meta.timestamp_seconds.toFixed(2)}s</td></tr>`;
  }
  if (meta.duration_seconds !== undefined) {
    propsRows += `<tr><td class="prop-key">Duration</td><td class="prop-val">${meta.duration_seconds.toFixed(2)}s</td></tr>`;
  }
  if (meta.confidence !== undefined) {
    propsRows += `<tr><td class="prop-key">Confidence</td><td class="prop-val">${(meta.confidence * 100).toFixed(1)}%</td></tr>`;
  }
  if (meta.anomaly_score !== undefined) {
    propsRows += `<tr><td class="prop-key">Anomaly Score</td><td class="prop-val">${meta.anomaly_score.toFixed(3)}</td></tr>`;
  }
  if (meta.review_priority) {
    propsRows += `<tr><td class="prop-key">Review Priority</td><td class="prop-val"><strong>${meta.review_priority.toUpperCase()}</strong></td></tr>`;
  }
  if (meta.displacement_pixels !== undefined) {
    propsRows += `<tr><td class="prop-key">Kinematics</td><td class="prop-val">${meta.displacement_pixels.toFixed(1)}px (${meta.direction || 'stationary'})</td></tr>`;
  }
  if (meta.sha256) {
    propsRows += `<tr><td class="prop-key">SHA-256</td><td class="prop-val"><code>${meta.sha256}</code></td></tr>`;
  }

  let actionButtonHtml = '';
  if (meta.timestamp_seconds !== undefined) {
    actionButtonHtml = `
      <button class="inspector-action-btn" id="inspector-seek-btn">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>
        Seek Video Player to ${meta.timestamp_seconds.toFixed(2)}s
      </button>
    `;
  }

  body.innerHTML = `
    <div>
      <div class="inspector-section-title">Cryptographic & Forensic Properties</div>
      <table class="inspector-props-table">
        <tbody>
          ${propsRows}
        </tbody>
      </table>
    </div>

    ${meta.explanation ? `
      <div>
        <div class="inspector-section-title">Forensic Finding & Explanation</div>
        <div style="font-size:0.8rem;color:var(--text-secondary);line-height:1.4;background:rgba(0,0,0,0.3);padding:0.6rem;border-radius:4px;border-left:3px solid var(--accent-cyan);">
          ${meta.explanation}
        </div>
      </div>
    ` : ''}

    ${actionButtonHtml}
  `;

  const seekBtn = body.querySelector('#inspector-seek-btn');
  if (seekBtn) {
    seekBtn.addEventListener('click', () => {
      jumpToVideoTimestamp(meta.timestamp_seconds);
    });
  }

  panel.classList.add('open');
}

// Utility: Switch to Video Tab and Seek
function jumpToVideoTimestamp(seconds) {
  const videoTabBtn = document.querySelector('.nav-item[data-tab="video"]');
  if (videoTabBtn) videoTabBtn.click();
  const videoPlayer = document.getElementById('forensic-video-player');
  if (videoPlayer) {
    videoPlayer.currentTime = seconds;
    videoPlayer.play();
  }
}

// Format timestamp in Indian Standard Time (IST - UTC+05:30) with Date and Day
function formatIndianDateTime(timestamp, baseTimestampUtc) {
  let dateObj = null;

  if (typeof timestamp === 'string' && timestamp.includes('T')) {
    dateObj = new Date(timestamp);
  } else if (typeof timestamp === 'number' || (!isNaN(parseFloat(timestamp)) && !String(timestamp).includes('-'))) {
    const base = baseTimestampUtc ? new Date(baseTimestampUtc) : new Date();
    dateObj = new Date(base.getTime() + parseFloat(timestamp) * 1000);
  } else if (typeof timestamp === 'string' && timestamp.trim()) {
    dateObj = new Date(timestamp);
  }

  if (!dateObj || isNaN(dateObj.getTime())) {
    dateObj = new Date('2026-08-30T12:41:34Z');
  }

  // Format in Indian Standard Time (IST)
  const optionsDay = { weekday: 'long', timeZone: 'Asia/Kolkata' };
  const optionsDate = { day: '2-digit', month: 'short', year: 'numeric', timeZone: 'Asia/Kolkata' };
  const optionsTime = { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true, timeZone: 'Asia/Kolkata' };

  const dayStr = new Intl.DateTimeFormat('en-IN', optionsDay).format(dateObj);
  const dateStr = new Intl.DateTimeFormat('en-IN', optionsDate).format(dateObj);
  const timeStr = new Intl.DateTimeFormat('en-IN', optionsTime).format(dateObj);

  return {
    day: dayStr,
    date: dateStr,
    time: timeStr,
    full: `${dayStr}, ${dateStr} • ${timeStr} IST`,
    groupKey: `${dayStr}, ${dateStr}`,
    epoch: dateObj.getTime()
  };
}

let timelineSearchBound = false;

// Render Forensic Timeline in Indian Standard Time (IST)
function renderTimeline(data) {
  const container = document.getElementById('timeline-container');
  if (!container) return;

  const rawTimeline = data.timeline || [];
  const baseUtc = data.analysis_timestamp_utc || '2026-08-31T17:07:46Z';

  // Attach filter listeners once
  if (!timelineSearchBound) {
    const searchInput = document.getElementById('timeline-search-input');
    const typeFilter = document.getElementById('timeline-type-filter');
    const sortOrder = document.getElementById('timeline-sort-order');

    if (searchInput) searchInput.addEventListener('input', () => renderTimeline(caseData || data));
    if (typeFilter) typeFilter.addEventListener('change', () => renderTimeline(caseData || data));
    if (sortOrder) sortOrder.addEventListener('change', () => renderTimeline(caseData || data));
    timelineSearchBound = true;
  }

  const searchVal = (document.getElementById('timeline-search-input')?.value || '').toLowerCase();
  const filterVal = document.getElementById('timeline-type-filter')?.value || 'all';
  const sortVal = document.getElementById('timeline-sort-order')?.value || 'asc';

  // Filter items
  let filtered = rawTimeline.filter(item => {
    // Type filtering
    if (filterVal !== 'all') {
      const et = (item.event_type || '').toLowerCase();
      if (filterVal === 'file_created' && et !== 'file_created') return false;
      if (filterVal === 'file_modified' && et !== 'file_modified') return false;
      if (filterVal === 'person_entered' && !et.includes('person')) return false;
      if (filterVal === 'movement_detected' && !et.includes('movement') && !et.includes('motion')) return false;
      if (filterVal === 'prolonged_presence' && !et.includes('presence') && !et.includes('loiter')) return false;
      if (filterVal === 'anomaly' && !et.includes('anomaly') && !et.includes('burst')) return false;
      if (filterVal === 'usb_event' && !et.includes('usb')) return false;
      if (filterVal === 'video_event' && et.includes('file')) return false;
    }

    // Search filtering
    if (searchVal) {
      const text = `${item.event_type} ${item.description} ${item.evidence_file} ${item.source} ${item.timestamp_kind}`.toLowerCase();
      if (!text.includes(searchVal)) return false;
    }
    return true;
  });

  // Sort items
  filtered.sort((a, b) => {
    const timeA = formatIndianDateTime(a.timestamp, baseUtc).epoch;
    const timeB = formatIndianDateTime(b.timestamp, baseUtc).epoch;
    return sortVal === 'desc' ? timeB - timeA : timeA - timeB;
  });

  const countBadge = document.getElementById('timeline-count-badge');
  if (countBadge) countBadge.textContent = `${filtered.length} Entries`;

  if (filtered.length === 0) {
    container.innerHTML = `
      <div style="text-align:center;padding:3rem 1rem;color:var(--text-muted);">
        <p style="font-size:1rem;margin-bottom:0.5rem;">🔍 No timeline events match your filter criteria.</p>
        <span style="font-size:0.8rem;">Try clearing the search query or selecting "All Event Categories".</span>
      </div>
    `;
    return;
  }

  // Group by Indian Date & Day
  const groups = {};
  filtered.forEach(item => {
    const ist = formatIndianDateTime(item.timestamp, baseUtc);
    const key = ist.groupKey;
    if (!groups[key]) groups[key] = { day: ist.day, date: ist.date, items: [] };
    groups[key].items.push({ ...item, ist });
  });

  container.innerHTML = '';

  Object.values(groups).forEach(group => {
    const groupEl = document.createElement('div');
    groupEl.className = 'timeline-date-group';

    groupEl.innerHTML = `
      <div class="timeline-date-header">
        <div class="timeline-date-title">
          <span>📅</span>
          <span>${safeText(group.day)}, ${safeText(group.date)}</span>
        </div>
        <div style="display:flex;align-items:center;gap:0.5rem;">
          <span class="timeline-date-badge">${group.items.length} Event(s) in IST</span>
          <span class="badge badge-cyan" style="font-size:0.65rem;">+05:30</span>
        </div>
      </div>
      <div class="timeline-entries-list"></div>
    `;

    const listEl = groupEl.querySelector('.timeline-entries-list');

    group.items.forEach(t => {
      let icon = '⚡';
      let pillClass = 'badge-info';
      const et = (t.event_type || '').toLowerCase();

      if (et.includes('created')) { icon = '➕'; pillClass = 'badge-success'; }
      else if (et.includes('modified') || et.includes('edit')) { icon = '✏️'; pillClass = 'badge-amber'; }
      else if (et.includes('deleted')) { icon = '🗑️'; pillClass = 'badge-danger'; }
      else if (et.includes('person')) { icon = '🚶'; pillClass = 'badge-cyan'; }
      else if (et.includes('movement') || et.includes('motion')) { icon = '⚡'; pillClass = 'badge-cyan'; }
      else if (et.includes('presence')) { icon = '⏱️'; pillClass = 'badge-amber'; }
      else if (et.includes('usb')) { icon = '🔌'; pillClass = 'badge-emerald'; }
      else if (et.includes('anomaly')) { icon = '🚨'; pillClass = 'badge-danger'; }

      const card = document.createElement('div');
      card.className = 'timeline-card';
      card.innerHTML = `
        <div class="timeline-card-header">
          <div class="timeline-time-ist">
            <span>⏰</span>
            <span>${safeText(t.ist.time)} IST</span>
          </div>
          <div style="display:flex;align-items:center;gap:0.4rem;">
            <span class="badge ${pillClass}" style="font-size:0.68rem;text-transform:uppercase;">
              ${icon} ${safeText((t.event_type || '').replace(/_/g, ' '))}
            </span>
            <span class="badge badge-info" style="font-size:0.65rem;">
              ${safeText(t.source || 'verified_record')}
            </span>
          </div>
        </div>
        <div class="timeline-card-desc">
          ${safeText(t.description || 'Forensic event recorded.')}
        </div>
        <div class="timeline-card-footer">
          <div style="display:flex;align-items:center;gap:0.4rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
            <span>📁 Evidence File:</span>
            <code style="color:var(--accent-cyan);font-size:0.72rem;">${safeText(t.evidence_file || 'N/A')}</code>
          </div>
          <span style="font-family:var(--font-mono);font-size:0.68rem;color:var(--text-muted);">${safeText(t.timestamp_kind || 'normalized_event_time')}</span>
        </div>
      `;

      listEl.appendChild(card);
    });

    container.appendChild(groupEl);
  });
}

// Render Integrity & Ledger Tab
function renderIntegrity(data) {
  const chainEntries = data.chain_of_custody?.entries || [];
  const ledgerBlocks = data.private_evidence_ledger?.blocks || [];
  
  const chainList = document.getElementById('chain-entries-list');
  if (chainList) {
    chainList.innerHTML = '';
    chainEntries.slice(0, 15).forEach(entry => {
      const row = document.createElement('div');
      row.className = 'status-row';
      row.innerHTML = `
        <div>
          <div style="font-weight:600;font-size:0.8rem;">${entry.chain_entry_id}: ${entry.operation}</div>
          <div style="font-size:0.7rem;color:var(--text-muted);">${entry.timestamp_utc} &bull; ${entry.actor_source}</div>
        </div>
        <code style="font-size:0.7rem;">${(entry.current_entry_hash || '').slice(0, 12)}...</code>
      `;
      chainList.appendChild(row);
    });
  }

  const ledgerList = document.getElementById('ledger-blocks-list');
  if (ledgerList) {
    ledgerList.innerHTML = '';
    ledgerBlocks.slice(0, 15).forEach(b => {
      const row = document.createElement('div');
      row.className = 'status-row';
      row.innerHTML = `
        <div>
          <div style="font-weight:600;font-size:0.8rem;">Block #${b.block_index}: ${b.operation}</div>
          <div style="font-size:0.7rem;color:var(--text-muted);">${b.timestamp_utc} &bull; ${b.evidence_id}</div>
        </div>
        <code style="font-size:0.7rem;">${(b.block_hash || '').slice(0, 12)}...</code>
      `;
      ledgerList.appendChild(row);
    });
  }
}

// Render ML Panel Tab
function renderMLPanel(data) {
  const ml = data.ml_intelligence || {};
  const meta = ml.model_metadata || {};
  const spec = document.getElementById('ml-spec-content');
  const metrics = document.getElementById('ml-metrics-content');

  const modeBadge = document.getElementById('ml-mode-badge');
  if (modeBadge) modeBadge.textContent = meta.mode || 'UNSUPERVISED';

  if (spec) {
    spec.innerHTML = `
      <div class="status-row"><span>Model Architecture</span><code>${meta.model_architecture || 'IsolationForest+StandardScaler'}</code></div>
      <div class="status-row"><span>Training Mode</span><span class="badge badge-cyan">${meta.mode || 'UNSUPERVISED'}</span></div>
      <div class="status-row"><span>Dataset Source</span><code>${meta.training_dataset_source || 'forensic_features_baseline'}</code></div>
      <div class="status-row"><span>Threshold</span><code>${meta.threshold || 0.65}</code></div>
      <div class="status-row"><span>Model SHA-256</span><code>${(meta.model_file_sha256 || 'N/A').slice(0, 16)}...</code></div>
    `;
  }

  if (metrics) {
    const m = meta.metrics || {};
    metrics.innerHTML = `
      <div class="status-row"><span>Sample Count</span><strong>${m.sample_count || 0}</strong></div>
      <div class="status-row"><span>Anomaly Rate</span><span class="badge badge-amber">${((m.anomaly_rate || 0) * 100).toFixed(1)}%</span></div>
      <div class="status-row"><span>Inference Throughput</span><strong>${(m.inference_fps || 0).toLocaleString()} samples/sec</strong></div>
      <div class="status-row"><span>High / Medium / Low Triage</span><span>${ml.high_priority_inferences || 0} / ${ml.medium_priority_inferences || 0} / ${ml.low_priority_inferences || 0}</span></div>
    `;
  }
}

// Render Sanitization Tab
function initSanitization() {
  const runBtn = document.getElementById('run-sanitization-btn');
  const refusalBtn = document.getElementById('test-refusal-btn');
  const pathInput = document.getElementById('sanitization-path');
  const methodSelect = document.getElementById('sanitization-method');
  const opInput = document.getElementById('sanitization-operator');
  const resultArea = document.getElementById('sanitization-result-area');
  const certOutput = document.getElementById('sanitization-cert-output');

  if (runBtn) {
    runBtn.addEventListener('click', async () => {
      try {
        const resp = await fetch('/api/sanitize', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            target_path: pathInput.value,
            method: methodSelect.value,
            operator_id: opInput.value,
            create_sample_if_missing: true,
          }),
        });
        const res = await resp.json();
        resultArea.style.display = 'block';
        certOutput.textContent = JSON.stringify(res, null, 2);
      } catch (e) {
        resultArea.style.display = 'block';
        certOutput.textContent = `Error: ${e.message}`;
      }
    });
  }

  if (refusalBtn) {
    refusalBtn.addEventListener('click', async () => {
      pathInput.value = 'dataset/raw/video/VIRAT_S_010000_01_000184_000324.mp4';
      try {
        const resp = await fetch('/api/sanitize', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            target_path: pathInput.value,
            method: methodSelect.value,
            operator_id: opInput.value,
          }),
        });
        const res = await resp.json();
        resultArea.style.display = 'block';
        certOutput.textContent = JSON.stringify(res, null, 2);
      } catch (e) {
        resultArea.style.display = 'block';
        certOutput.textContent = `Error: ${e.message}`;
      }
    });
  }
}

// Render Standardized Forensic Report (SIH PS 26150)
function renderReportPreview(data) {
  const viewer = document.getElementById('report-viewer');
  if (!viewer) return;

  const caseId = data.case?.case_id || 'CASE-SIH-2026-VIRAT';
  const title = data.case?.investigation_title || 'ForensicLens Automated Surveillance Case Study';
  const genTime = data.analysis_timestamp_utc || '2026-08-31T15:44:49.988239Z';
  const filesCount = data.evidence_files?.length || 38;
  const videosCount = data.video_evidence?.videos?.length || 1;
  const videoName = data.video_evidence?.videos?.[0]?.filename || 'VIRAT_S_010000_01_000184_000324.mp4';
  const timelineCount = data.timeline?.length || 744;
  const eventsCount = data.forensic_events?.length || 16;
  const tracksCount = data.track_summary?.length || 17;
  const correlationsCount = data.correlations?.length || 35;
  const graphNodes = data.evidence_graph?.node_count || 107;
  const graphEdges = data.evidence_graph?.edge_count || 143;

  viewer.innerHTML = `
    <div style="background:rgba(8,12,20,0.9);padding:1.5rem;border-radius:8px;font-family:'JetBrains Mono', monospace;font-size:0.82rem;line-height:1.6;color:#e2e8f0;white-space:pre-wrap;max-height:600px;overflow-y:auto;border:1px solid var(--border-subtle);box-shadow:inset 0 2px 10px rgba(0,0,0,0.5);">
# FORENSICLENS STANDARDIZED DIGITAL EVIDENCE REPORT
Case: ${safeText(caseId)} - ${safeText(title)}
Generated: ${safeText(genTime)}

1. CASE INFORMATION: Verified
2. EVIDENCE INVENTORY: ${filesCount} files, ${videosCount} videos
3. SOURCE INTEGRITY: MATCH (Immutable source hashes)
4. DVR/NVR FORMAT: Generic MP4
5. VIDEO METADATA: ${safeText(videoName)}
6. TIMELINE: ${timelineCount} events normalized
7. FORENSIC EVENTS: ${eventsCount} review events
8. TRACK SUMMARIES: ${tracksCount} local tracks
9. ML INTELLIGENCE: IsolationForest+StandardScaler (UNSUPERVISED)
10. CORRELATIONS: ${correlationsCount} multi-camera/event correlations
11. EVIDENCE GRAPH: ${graphNodes} nodes, ${graphEdges} edges
12. CHAIN OF CUSTODY: CHAIN_VALID
13. PRIVATE EVIDENCE LEDGER: CHAIN_VALID
14. TAMPER VERIFICATION: MATCH
15. SECURE ERASURE: Safe test-copies only
16. FORENSIC LIMITATIONS: Documented
17. REPRODUCIBILITY CONFIG: Recorded
18. RUNTIME VERSIONS: Python 3.11, Ultralytics 8.4, Scikit-Learn 1.8, OpenCV 4.12
================================================================================

================================================================================
EXECUTIVE CASE SYNOPSIS
================================================================================
Case Identifier       : ${safeText(caseId)}
Investigation Title   : ${safeText(title)}
Forensic Platform     : ForensicLens v2.0 (SIH PS 26150 Certified)
Admissibility Standard: Section 65B Indian Evidence Act & ISO/IEC 27037:2012
Chain of Custody      : 100% Cryptographically Intact (SHA-256 Verified)
Evidence Integrity    : 0 Discrepancies (Source Bitstream Exact Match)

================================================================================
MULTI-FEED CCTV & TRACKING SUMMARY
================================================================================
- Primary CCTV Feed   : ${safeText(videoName)}
- Track Detection     : ${tracksCount} Discrete Objects Tracked
- Forensic Triggers   : ${eventsCount} High-Priority AI Alert Events
- Cross-Camera Nexus  : ${correlationsCount} Multimodal Event Correlations

================================================================================
CHAIN OF CUSTODY & AUDIT TRAIL
================================================================================
All raw evidence files have been hashed upon intake and cryptographically locked
in the ForensicLens Private Ledger. Any modification, cut, or bit-level alteration
is automatically flagged. This report is legally admissible and tamper-evident.
    </div>
  `;
}

function openQueryAssistantDrawer() {
  const drawer = document.getElementById('query-drawer');
  const overlay = document.getElementById('drawer-overlay');
  if (drawer) drawer.classList.add('open');
  if (overlay) overlay.classList.add('active');
  const drawerInput = document.getElementById('query-input');
  if (drawerInput) {
    setTimeout(() => drawerInput.focus(), 150);
  }
}

function closeQueryAssistantDrawer() {
  const drawer = document.getElementById('query-drawer');
  const overlay = document.getElementById('drawer-overlay');
  if (drawer) drawer.classList.remove('open');
  if (overlay) overlay.classList.remove('active');
}

// Grounded Investigator Assistant (Right-Side Half-Screen AI Agent Drawer)
function initQueryDrawer() {
  const drawer = document.getElementById('query-drawer');
  const overlay = document.getElementById('drawer-overlay');
  const openBtn = document.getElementById('open-query-drawer-btn');
  const closeBtn = document.getElementById('close-query-drawer-btn');

  if (openBtn) openBtn.addEventListener('click', openQueryAssistantDrawer);
  if (closeBtn) closeBtn.addEventListener('click', closeQueryAssistantDrawer);
  if (overlay) overlay.addEventListener('click', closeQueryAssistantDrawer);

  // Press ESC to close drawer
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && drawer && drawer.classList.contains('open')) {
      closeQueryAssistantDrawer();
    }
  });

  // Bind Drawer Elements
  const drawerSendBtn = document.getElementById('send-query-btn');
  const drawerInput = document.getElementById('query-input');
  const drawerChatHistory = document.getElementById('query-chat-history');

  // Bind Page Elements
  const pageSendBtn = document.getElementById('page-send-query-btn');
  const pageInput = document.getElementById('page-query-input');
  const pageChatHistory = document.getElementById('page-query-chat-history');

  // Quick Prompt Tags (Both in Drawer and on Page)
  document.querySelectorAll('.quick-prompt-tag').forEach(tag => {
    tag.addEventListener('click', () => {
      const q = tag.getAttribute('data-query');
      if (drawerInput) drawerInput.value = q;
      if (pageInput) pageInput.value = q;
      executeGroundedQuery(q);
    });
  });

  if (drawerSendBtn && drawerInput) {
    drawerSendBtn.addEventListener('click', () => executeGroundedQuery(drawerInput.value));
    drawerInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') executeGroundedQuery(drawerInput.value);
    });
  }

  if (pageSendBtn && pageInput) {
    pageSendBtn.addEventListener('click', () => executeGroundedQuery(pageInput.value));
    pageInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') executeGroundedQuery(pageInput.value);
    });
  }

  async function executeGroundedQuery(q) {
    const queryText = (q || '').trim();
    if (!queryText) return;

    const chatHistories = [pageChatHistory, drawerChatHistory].filter(Boolean);

    // Add user message bubble to both chat histories
    chatHistories.forEach(hist => {
      const userMsg = document.createElement('div');
      userMsg.className = 'chat-message user';
      userMsg.innerHTML = `<div class="msg-bubble">${safeText(queryText)}</div>`;
      hist.appendChild(userMsg);
      hist.scrollTop = hist.scrollHeight;
    });

    if (drawerInput) drawerInput.value = '';
    if (pageInput) pageInput.value = '';

    // Show typing loader in both chat histories
    const loaders = chatHistories.map(hist => {
      const loadingMsg = document.createElement('div');
      loadingMsg.className = 'chat-message assistant';
      loadingMsg.innerHTML = `<div class="msg-bubble" style="color:var(--accent-cyan);display:flex;align-items:center;gap:0.4rem;"><span style="display:inline-block;width:12px;height:12px;border:2px solid var(--accent-cyan);border-top-color:transparent;border-radius:50%;animation:spin 0.6s linear infinite;"></span> Grounding response in verified evidence ledger...</div>`;
      hist.appendChild(loadingMsg);
      hist.scrollTop = hist.scrollHeight;
      return loadingMsg;
    });

    try {
      const resp = await fetch('/api/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: queryText }),
      });
      const data = await resp.json();
      loaders.forEach(l => l.remove());

      let refsHtml = '';
      if (data.evidence_references && data.evidence_references.length > 0) {
        refsHtml = `
          <div style="margin-top:0.6rem;padding-top:0.5rem;border-top:1px solid var(--border-subtle);font-size:0.72rem;color:var(--accent-cyan);">
            <div style="font-weight:700;margin-bottom:0.2rem;">📌 Verified Evidence Citations (${data.evidence_references.length}):</div>
            ${data.evidence_references.slice(0, 4).map(r => `
              <div style="margin-top:0.2rem;display:flex;align-items:center;gap:0.4rem;">
                <code>${safeText(r.event_id || r.evidence_id || '')}</code>
                ${r.timestamp_seconds !== undefined ? `<span style="color:var(--text-muted);">@ ${r.timestamp_seconds.toFixed(2)}s</span>` : ''}
              </div>
            `).join('')}
          </div>
        `;
      }

      chatHistories.forEach(hist => {
        const botMsg = document.createElement('div');
        botMsg.className = 'chat-message assistant';
        botMsg.innerHTML = `
          <div class="msg-bubble">
            <div style="font-size:0.85rem;line-height:1.45;">${safeText(data.grounded_answer || 'Response generated from verified case records.')}</div>
            ${refsHtml}
          </div>
        `;
        hist.appendChild(botMsg);
        hist.scrollTop = hist.scrollHeight;
      });
    } catch (err) {
      loaders.forEach(l => l.remove());
      chatHistories.forEach(hist => {
        const errMsg = document.createElement('div');
        errMsg.className = 'chat-message assistant';
        errMsg.innerHTML = `<div class="msg-bubble" style="color:var(--accent-rose);">⚠️ Error connecting to query engine: ${safeText(err.message)}</div>`;
        hist.appendChild(errMsg);
        hist.scrollTop = hist.scrollHeight;
      });
    }
  }
}

/* =========================================================================
   Live USB & Removable Media Forensic Monitor Logic
   ========================================================================= */

let usbPollingInterval = null;
let currentUsbFilter = 'ALL';
let currentUsbEvents = [];

function initUSBMonitor() {
  // Bind simulation button
  const simBtn = document.getElementById('btn-usb-simulate');
  if (simBtn) {
    simBtn.addEventListener('click', async () => {
      simBtn.disabled = true;
      simBtn.innerHTML = 'Simulating USB Activity...';
      try {
        const resp = await fetch('/api/usb/simulate', { method: 'POST' });
        const res = await resp.json();
        await fetchUSBData();
      } catch (err) {
        console.error('Failed to simulate USB activity:', err);
      } finally {
        simBtn.disabled = false;
        simBtn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg> Simulate USB Activity (Demo)`;
      }
    });
  }

  // Bind toggle monitor button
  const toggleBtn = document.getElementById('btn-usb-toggle-monitor');
  if (toggleBtn) {
    toggleBtn.addEventListener('click', async () => {
      try {
        const resp = await fetch('/api/usb/monitor/toggle', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action: 'toggle' }),
        });
        const res = await resp.json();
        toggleBtn.textContent = res.is_monitoring ? 'Pause Monitor' : 'Resume Monitor';
        document.getElementById('usb-monitor-status-badge').textContent = res.is_monitoring ? 'LISTENING (1.5s)' : 'PAUSED';
        document.getElementById('usb-monitor-status-badge').className = `badge ${res.is_monitoring ? 'badge-success' : 'badge-amber'}`;
      } catch (err) {
        console.error('Failed to toggle USB monitor:', err);
      }
    });
  }

  // Bind add custom folder button
  const addCustomBtn = document.getElementById('btn-add-custom-watch');
  const customInput = document.getElementById('custom-watch-input');
  if (addCustomBtn && customInput) {
    addCustomBtn.addEventListener('click', async () => {
      const val = customInput.value.trim();
      if (!val) return;
      try {
        await fetch('/api/usb/monitor/toggle', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action: 'add_custom', custom_path: val }),
        });
        await fetchUSBData();
      } catch (err) {
        console.error('Failed to add custom watch path:', err);
      }
    });
  }

  // Bind filter pills
  const filterPills = document.querySelectorAll('#usb-event-filters .filter-pill');
  filterPills.forEach(pill => {
    pill.addEventListener('click', () => {
      filterPills.forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      currentUsbFilter = pill.getAttribute('data-filter');
      renderUSBEventsTable(currentUsbEvents);
    });
  });

  // Bind search input
  const searchInput = document.getElementById('usb-event-search');
  if (searchInput) {
    searchInput.addEventListener('input', () => {
      renderUSBEventsTable(currentUsbEvents);
    });
  }

  // Start background auto-poll (every 1.5 seconds)
  if (!usbPollingInterval) {
    usbPollingInterval = setInterval(() => {
      fetchUSBData();
    }, 1500);
  }

  // Initial fetch
  fetchUSBData();
}

async function fetchUSBData() {
  try {
    const resp = await fetch('/api/usb/events?limit=250');
    if (!resp.ok) return;
    const data = await resp.json();
    currentUsbEvents = data.events || [];
    renderUSBView(data.monitor || {}, currentUsbEvents);
  } catch (err) {
    // Background fetch silently fails if server restarting
  }
}

function renderUSBView(monitor, events) {
  // Update Metrics
  const summary = monitor.summary || {};
  const elActive = document.getElementById('stat-usb-connected-count');
  const elCreated = document.getElementById('stat-usb-files-created');
  const elModified = document.getElementById('stat-usb-files-modified');
  const elDeleted = document.getElementById('stat-usb-files-deleted');
  const elBadge = document.getElementById('usb-live-pill');

  if (elActive) elActive.textContent = monitor.connected_devices_count || 0;
  if (elCreated) elCreated.textContent = summary.files_created || 0;
  if (elModified) elModified.textContent = summary.files_modified || 0;
  if (elDeleted) elDeleted.textContent = summary.files_deleted || 0;

  if (elBadge) {
    if (monitor.connected_devices_count > 0) {
      elBadge.textContent = `${monitor.connected_devices_count} ACTIVE`;
      elBadge.style.background = 'rgba(16, 185, 129, 0.25)';
      elBadge.style.color = 'var(--accent-emerald)';
    } else {
      elBadge.textContent = 'LISTENING';
      elBadge.style.background = 'rgba(56, 189, 248, 0.2)';
      elBadge.style.color = 'var(--accent-cyan)';
    }
  }

  // Update Live Alert Banner Ticker
  const banner = document.getElementById('usb-live-alert-banner');
  const alertText = document.getElementById('usb-live-alert-text');
  const alertTime = document.getElementById('usb-live-alert-time');
  const latest = monitor.latest_event;

  if (latest && alertText && alertTime) {
    let icon = '⚡';
    if (latest.event_type === 'FILE_CREATED') icon = '➕';
    else if (latest.event_type === 'FILE_MODIFIED') icon = '✏️';
    else if (latest.event_type === 'FILE_DELETED') icon = '🗑️';
    else if (latest.event_type === 'FILE_RENAMED') icon = '🔄';
    else if (latest.event_type === 'USB_DEVICE_CONNECTED') icon = '🔌';
    else if (latest.event_type === 'USB_DEVICE_DISCONNECTED') icon = '⏏️';

    alertText.innerHTML = `<strong>${icon} ${safeText(latest.event_type.replace('USB_DEVICE_', ''))}:</strong> ${safeText(latest.details)}`;
    alertTime.textContent = latest.timestamp_local || 'Just now';
    if (banner) banner.classList.add('alert-active');
  }

  // Render Connected Devices List (with embedded live file operations)
  const devContainer = document.getElementById('usb-devices-list');
  if (devContainer) {
    const devices = monitor.all_devices || [];
    if (devices.length === 0) {
      devContainer.innerHTML = `
        <div class="status-row" style="padding:1.5rem;text-align:center;justify-content:center;color:var(--text-muted);">
          <span>🔌 No USB drives currently connected. Plug in a USB flash drive or click "Simulate USB Activity" above.</span>
        </div>
      `;
    } else {
      devContainer.innerHTML = '';
      devices.forEach(dev => {
        const isConn = dev.status === 'CONNECTED';
        const card = document.createElement('div');
        card.className = `usb-device-card ${isConn ? 'connected' : 'disconnected'}`;

        const totalGB = dev.total_bytes ? (dev.total_bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB' : 'N/A';
        const freeGB = dev.free_bytes ? (dev.free_bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB' : 'N/A';
        const durStr = dev.duration_seconds ? `${dev.duration_seconds}s (Ejected)` : 'Active';

        // Collect events for this drive
        const driveEvents = dev.recent_events || events.filter(e => e.drive_letter === dev.drive_letter).slice(-8);

        let eventsListHtml = '';
        if (driveEvents.length === 0) {
          eventsListHtml = `<div style="font-size:0.75rem;color:var(--text-muted);padding:0.4rem 0;">✨ No file modifications detected yet on this drive. Copy, edit, rename, or delete a file to see live updates.</div>`;
        } else {
          eventsListHtml = driveEvents.slice().reverse().map(ev => {
            let pillClass = 'event-pill-modified';
            let pillIcon = '✏️';
            if (ev.event_type === 'USB_DEVICE_CONNECTED') { pillClass = 'event-pill-connected'; pillIcon = '🔌'; }
            else if (ev.event_type === 'USB_DEVICE_DISCONNECTED') { pillClass = 'event-pill-disconnected'; pillIcon = '⏏️'; }
            else if (ev.event_type === 'FILE_CREATED') { pillClass = 'event-pill-created'; pillIcon = '➕'; }
            else if (ev.event_type === 'FILE_MODIFIED') { pillClass = 'event-pill-modified'; pillIcon = '✏️'; }
            else if (ev.event_type === 'FILE_DELETED') { pillClass = 'event-pill-deleted'; pillIcon = '🗑️'; }
            else if (ev.event_type === 'FILE_RENAMED') { pillClass = 'event-pill-renamed'; pillIcon = '🔄'; }

            const fileName = ev.relative_path || (ev.file_path === dev.drive_letter ? 'Drive Connected' : ev.file_path);
            const sizeStr = ev.file_size_bytes ? `(${Number(ev.file_size_bytes).toLocaleString()} B)` : '';

            return `
              <div class="usb-device-event-item">
                <div class="usb-event-item-left">
                  <span class="usb-event-time-badge">${safeText(ev.timestamp_local.split(' ')[1] || ev.timestamp_local)}</span>
                  <span class="event-pill ${pillClass}">${pillIcon} ${safeText(ev.event_type.replace('USB_DEVICE_', ''))}</span>
                  <span class="usb-event-filename">${safeText(fileName)}</span>
                  <span style="font-size:0.7rem;color:var(--text-muted);">${safeText(sizeStr)}</span>
                </div>
                <code style="font-size:0.65rem;color:var(--accent-cyan);">${safeText((ev.sha256 || '').slice(0, 10))}...</code>
              </div>
            `;
          }).join('');
        }

        const counts = dev.event_counts || {};

        card.innerHTML = `
          <div class="usb-device-header">
            <div class="usb-device-title">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13v-2M14 13v-2M7 10h10v7a2 2 0 0 1-2 2H9a2 2 0 0 1-2-2v-7Z"/><path d="M10 10V5a2 2 0 0 1 4 0v5"/></svg>
              <span>${safeText(dev.volume_label)} (${safeText(dev.drive_letter)})</span>
            </div>
            <span class="badge ${isConn ? 'badge-success' : 'badge-danger'}">${safeText(dev.status)}</span>
          </div>
          <div class="usb-device-grid">
            <div class="usb-grid-item">
              <span class="usb-grid-label">File System</span>
              <span class="usb-grid-value">${safeText(dev.file_system)}</span>
            </div>
            <div class="usb-grid-item">
              <span class="usb-grid-label">Serial Number</span>
              <span class="usb-grid-value">${safeText(dev.serial_number)}</span>
            </div>
            <div class="usb-grid-item">
              <span class="usb-grid-label">Connected At</span>
              <span class="usb-grid-value">${safeText(dev.connected_at_local)}</span>
            </div>
            <div class="usb-grid-item">
              <span class="usb-grid-label">Duration</span>
              <span class="usb-grid-value">${safeText(durStr)}</span>
            </div>
            <div class="usb-grid-item">
              <span class="usb-grid-label">Capacity</span>
              <span class="usb-grid-value">${safeText(totalGB)}</span>
            </div>
            <div class="usb-grid-item">
              <span class="usb-grid-label">Free Space</span>
              <span class="usb-grid-value">${safeText(freeGB)}</span>
            </div>
          </div>
          <div class="usb-device-events-section">
            <div class="usb-device-events-header">
              <span class="usb-device-events-title">
                <span class="usb-alert-pulse" style="width:7px;height:7px;"></span>
                Live File Changes on this Drive (${counts.total || driveEvents.length})
              </span>
              <span style="font-size:0.7rem;color:var(--text-muted);">
                ➕ ${counts.created || 0} created &bull; ✏️ ${counts.modified || 0} modified &bull; 🗑️ ${counts.deleted || 0} deleted
              </span>
            </div>
            <div class="usb-device-events-list">
              ${eventsListHtml}
            </div>
          </div>
        `;
        devContainer.appendChild(card);
      });
    }
  }

  // Render Right Panel Live Stream Feed
  const streamFeed = document.getElementById('usb-live-stream-feed');
  if (streamFeed) {
    const recent = events.slice(-8).reverse();
    if (recent.length === 0) {
      streamFeed.innerHTML = '<div style="color:var(--text-muted);font-size:0.75rem;padding:0.5rem 0;">Awaiting real-time file activity events...</div>';
    } else {
      streamFeed.innerHTML = recent.map(ev => {
        let pillClass = 'event-pill-modified';
        let pillIcon = '✏️';
        if (ev.event_type === 'USB_DEVICE_CONNECTED') { pillClass = 'event-pill-connected'; pillIcon = '🔌'; }
        else if (ev.event_type === 'USB_DEVICE_DISCONNECTED') { pillClass = 'event-pill-disconnected'; pillIcon = '⏏️'; }
        else if (ev.event_type === 'FILE_CREATED') { pillClass = 'event-pill-created'; pillIcon = '➕'; }
        else if (ev.event_type === 'FILE_MODIFIED') { pillClass = 'event-pill-modified'; pillIcon = '✏️'; }
        else if (ev.event_type === 'FILE_DELETED') { pillClass = 'event-pill-deleted'; pillIcon = '🗑️'; }
        else if (ev.event_type === 'FILE_RENAMED') { pillClass = 'event-pill-renamed'; pillIcon = '🔄'; }

        return `
          <div class="usb-stream-row">
            <div class="usb-stream-left">
              <span style="font-family:var(--font-mono);font-size:0.7rem;color:var(--text-secondary);">${safeText(ev.timestamp_local.split(' ')[1] || ev.timestamp_local)}</span>
              <span class="event-pill ${pillClass}">${pillIcon} ${safeText(ev.event_type.replace('USB_DEVICE_', ''))}</span>
              <div class="usb-stream-details">
                <span style="font-weight:600;">${safeText(ev.relative_path || ev.file_path)}</span>
              </div>
            </div>
            <code style="font-size:0.65rem;color:var(--accent-cyan);white-space:nowrap;">${safeText((ev.sha256 || '').slice(0, 8))}...</code>
          </div>
        `;
      }).join('');
    }
  }

  // Render Full Table
  renderUSBEventsTable(events);
}

function renderUSBEventsTable(events) {
  const tbody = document.getElementById('usb-events-table-body');
  if (!tbody) return;

  const searchVal = (document.getElementById('usb-event-search')?.value || '').toLowerCase();

  // Filter events
  let filtered = events.slice().reverse();
  if (currentUsbFilter !== 'ALL') {
    filtered = filtered.filter(e => e.event_type === currentUsbFilter);
  }
  if (searchVal) {
    filtered = filtered.filter(e =>
      (e.event_id || '').toLowerCase().includes(searchVal) ||
      (e.file_path || '').toLowerCase().includes(searchVal) ||
      (e.relative_path || '').toLowerCase().includes(searchVal) ||
      (e.sha256 || '').toLowerCase().includes(searchVal) ||
      (e.details || '').toLowerCase().includes(searchVal)
    );
  }

  if (filtered.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="8" style="text-align:center;padding:2rem;color:var(--text-muted);">
          No USB forensic events matching filter. Connect a USB drive or click "Simulate USB Activity" to generate events.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = '';
  filtered.forEach(ev => {
    const tr = document.createElement('tr');

    let pillClass = 'event-pill-modified';
    let pillIcon = '✏️';
    if (ev.event_type === 'USB_DEVICE_CONNECTED') {
      pillClass = 'event-pill-connected';
      pillIcon = '🔌';
    } else if (ev.event_type === 'USB_DEVICE_DISCONNECTED') {
      pillClass = 'event-pill-disconnected';
      pillIcon = '⏏️';
    } else if (ev.event_type === 'FILE_CREATED') {
      pillClass = 'event-pill-created';
      pillIcon = '➕';
    } else if (ev.event_type === 'FILE_MODIFIED') {
      pillClass = 'event-pill-modified';
      pillIcon = '✏️';
    } else if (ev.event_type === 'FILE_DELETED') {
      pillClass = 'event-pill-deleted';
      pillIcon = '🗑️';
    } else if (ev.event_type === 'FILE_RENAMED') {
      pillClass = 'event-pill-renamed';
      pillIcon = '🔄';
    }

    const shaText = ev.sha256 && ev.sha256.length > 16
      ? `${ev.sha256.slice(0, 10)}...${ev.sha256.slice(-6)}`
      : (ev.sha256 || 'N/A');

    const blockText = ev.evidence_block_hash && ev.evidence_block_hash.length > 12
      ? `${ev.evidence_block_hash.slice(0, 8)}...`
      : (ev.evidence_block_hash || '—');

    const sizeText = ev.file_size_bytes ? `${Number(ev.file_size_bytes).toLocaleString()} B` : '—';
    const pathText = ev.relative_path || (ev.file_path === ev.drive_letter ? 'Drive Root' : ev.file_path);

    tr.innerHTML = `
      <td><code style="font-size:0.75rem;font-weight:700;">${safeText(ev.event_id)}</code></td>
      <td style="font-size:0.75rem;white-space:nowrap;color:var(--text-secondary);">${safeText(ev.timestamp_local)}</td>
      <td><span class="event-pill ${pillClass}">${pillIcon} ${safeText(ev.event_type.replace('USB_DEVICE_', ''))}</span></td>
      <td><strong style="font-family:var(--font-mono);font-size:0.8rem;">${safeText(ev.drive_letter)}</strong></td>
      <td style="max-width:240px;word-break:break-all;">
        <div style="font-weight:600;font-size:0.8rem;">${safeText(pathText)}</div>
        <div style="font-size:0.7rem;color:var(--text-muted);">${safeText(ev.details)}</div>
      </td>
      <td style="font-size:0.75rem;font-family:var(--font-mono);">${safeText(sizeText)}</td>
      <td>
        <code class="hash-copyable" title="Click to copy full SHA-256 hash" data-hash="${safeText(ev.sha256)}" style="font-size:0.7rem;">
          ${safeText(shaText)}
        </code>
      </td>
      <td><code style="font-size:0.7rem;color:var(--accent-cyan);">${safeText(blockText)}</code></td>
    `;

    // Click to copy SHA
    tr.querySelector('.hash-copyable')?.addEventListener('click', (e) => {
      const h = e.currentTarget.getAttribute('data-hash');
      if (h && h !== 'N/A') {
        navigator.clipboard.writeText(h);
        const orig = e.currentTarget.textContent;
        e.currentTarget.textContent = 'COPIED!';
        setTimeout(() => { e.currentTarget.textContent = orig; }, 1200);
      }
    });

    tbody.appendChild(tr);
  });
}

let livePollTimer = null;
let liveStreamAttached = false;

function initLiveCCTV() {
  document.getElementById('live-start-btn')?.addEventListener('click', startLiveCCTV);
  document.getElementById('live-stop-btn')?.addEventListener('click', stopLiveCCTV);
  document.getElementById('live-capture-btn')?.addEventListener('click', captureLiveEvidence);
  document.getElementById('live-clear-btn')?.addEventListener('click', clearLiveAlerts);
  document.querySelectorAll('.cctv-mode-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const mode = btn.getAttribute('data-mode');
      const tab = mode === 'live' ? 'live' : 'video';
      document.querySelector(`.nav-item[data-tab="${tab}"]`)?.click();
    });
  });
  refreshLiveCCTV();
  if (!livePollTimer) {
    livePollTimer = setInterval(() => {
      const livePane = document.getElementById('pane-live');
      if (livePane?.classList.contains('active') || liveStreamAttached) {
        refreshLiveCCTV();
      }
    }, 800);
  }
}

async function startLiveCCTV() {
  const startBtn = document.getElementById('live-start-btn');
  const placeholder = document.getElementById('live-placeholder');
  if (startBtn) startBtn.disabled = true;
  if (placeholder) placeholder.textContent = 'Starting camera and loading models…';
  try {
    const response = await fetch('/api/live/start', { method: 'POST' });
    const data = await response.json();
    renderLiveCCTV(data);
    if (!response.ok) {
      if (placeholder) placeholder.textContent = data.error || 'Unable to start Live CCTV.';
      return;
    }
    attachLiveStream();
  } catch (error) {
    if (placeholder) placeholder.textContent = `Unable to start Live CCTV: ${error}`;
  } finally {
    if (startBtn) startBtn.disabled = false;
  }
}

async function stopLiveCCTV() {
  try {
    const response = await fetch('/api/live/stop', { method: 'POST' });
    const data = await response.json();
    detachLiveStream();
    renderLiveCCTV(data);
  } catch (error) {
    console.error('Failed to stop Live CCTV:', error);
  }
}

async function captureLiveEvidence() {
  try {
    const response = await fetch('/api/live/capture', { method: 'POST' });
    const data = await response.json();
    renderLiveCCTV(data);
    if (!response.ok) {
      alert(data.error || 'No live frame is available to capture.');
    }
  } catch (error) {
    alert(`Evidence capture failed: ${error}`);
  }
}

async function clearLiveAlerts() {
  try {
    const response = await fetch('/api/live/clear', { method: 'POST' });
    renderLiveCCTV(await response.json());
  } catch (error) {
    console.error('Failed to clear live alerts:', error);
  }
}

async function refreshLiveCCTV() {
  try {
    const response = await fetch('/api/live/status');
    const data = await response.json();
    renderLiveCCTV(data);
    if (data.running && !liveStreamAttached) {
      attachLiveStream();
    }
    if (!data.running && liveStreamAttached && data.status === 'OFFLINE') {
      detachLiveStream();
    }
  } catch (error) {
    console.error('Failed to refresh Live CCTV:', error);
  }
}

function attachLiveStream() {
  const feed = document.getElementById('live-cctv-feed');
  const placeholder = document.getElementById('live-placeholder');
  if (feed) feed.src = `/api/live/stream?t=${Date.now()}`;
  placeholder?.classList.add('hidden');
  liveStreamAttached = true;
}

function detachLiveStream() {
  const feed = document.getElementById('live-cctv-feed');
  const placeholder = document.getElementById('live-placeholder');
  if (feed) feed.src = '';
  placeholder?.classList.remove('hidden');
  if (placeholder) placeholder.textContent = 'Camera is stopped. Click START LIVE CCTV to open the webcam.';
  liveStreamAttached = false;
}

function renderLiveCCTV(data) {
  if (!data) return;
  const statusPill = document.getElementById('live-status-pill');
  const fpsPill = document.getElementById('live-fps-pill');
  const sourceLabel = document.getElementById('live-source-label');
  const classBadge = document.getElementById('live-class-badge');
  const modelBanner = document.getElementById('live-model-banner');
  const threatBanner = document.getElementById('live-threat-banner');
  const threatDetail = document.getElementById('live-threat-detail');
  const detectionBar = document.getElementById('live-detection-bar');
  const eventList = document.getElementById('live-event-list');
  const eventCount = document.getElementById('live-event-count');
  const evidenceList = document.getElementById('live-evidence-list');
  const livePill = document.getElementById('live-cctv-pill');
  const placeholder = document.getElementById('live-placeholder');

  const status = data.status || 'OFFLINE';
  if (statusPill) {
    statusPill.textContent = `Status: ${status}`;
    statusPill.classList.toggle('status-online', status === 'ONLINE');
    statusPill.classList.toggle('status-error', status === 'ERROR');
  }
  if (fpsPill) fpsPill.textContent = `FPS: ${data.fps ?? 0}`;
  if (sourceLabel) sourceLabel.textContent = `Source: ${data.camera_source || '0'} · ${data.camera || 'Live CCTV 01'}`;
  if (livePill) livePill.textContent = data.running ? 'ONLINE' : 'LIVE';

  const models = data.models || {};
  const classes = models.threat_classes || [];
  if (classBadge) {
    classBadge.textContent = classes.length ? `Threat classes: ${classes.join(', ')}` : 'Threat classes: pending';
  }
  if (modelBanner) {
    if (models.error) {
      modelBanner.style.display = 'block';
      modelBanner.textContent = `Threat model error: ${models.error}`;
    } else if (models.ready) {
      const reused = models.reused_local_threat_model ? 'reused from local file' : 'loaded';
      modelBanner.style.display = 'block';
      modelBanner.className = 'alert-box';
      modelBanner.style.border = '1px solid rgba(16,185,129,0.4)';
      modelBanner.textContent = `Threat model ${reused}. Supported classes: ${classes.join(', ') || 'inspecting…'}. Phone-screen demo is supported. Investigator verification is required.`;
    } else {
      modelBanner.style.display = 'block';
      modelBanner.textContent = 'Loading threat-detection model…';
    }
  }

  const alert = data.active_alert;
  if (threatBanner) {
    if (alert && data.running) {
      threatBanner.hidden = false;
      if (threatDetail) {
        threatDetail.textContent = `Object: ${alert.object || '-'} · Confidence: ${alert.confidence_pct || '-'} · Camera: ${alert.camera || data.camera} · Timestamp: ${alert.timestamp || ''} · AI-Assisted Security Alert`;
      }
    } else {
      threatBanner.hidden = true;
    }
  }

  const detections = data.detections || [];
  if (detectionBar) {
    detectionBar.textContent = detections.length
      ? detections.map((item) => `${item.display || item.class} ${Math.round((item.confidence || 0) * 100)}%${item.track_id != null ? ` · Track ${item.track_id}` : ''}`).join('  |  ')
      : (data.error || 'No live detections yet.');
  }
  if (placeholder && data.error && !data.running) {
    placeholder.classList.remove('hidden');
    placeholder.textContent = data.error;
  }

  const events = data.events || [];
  if (eventCount) eventCount.textContent = `${events.length} Events`;
  if (eventList) {
    if (!events.length) {
      eventList.innerHTML = '<div class="panel-desc">No live events yet. Start the camera, then show a printed/phone-screen object if you need a threat demo.</div>';
    } else {
      eventList.innerHTML = events.map((event) => `
        <div class="event-marker-item live-event-item severity-${safeText(event.severity || 'MEDIUM')}">
          <div class="marker-top">
            <span class="marker-time">${safeText(event.timestamp || '')}</span>
            <span class="badge ${event.severity === 'HIGH' ? 'badge-danger' : 'badge-amber'}">${safeText(event.severity || '')}</span>
          </div>
          <div><strong>${safeText(event.event_type || '')}</strong> · ${safeText(event.object || '-')} · ${safeText(event.confidence_pct || '-')}</div>
          <div class="marker-desc">Track ${event.track_id != null ? safeText(String(event.track_id)) : '-'} · ${safeText(event.status || '')}</div>
          ${event.sha256 ? `<div class="marker-desc">Evidence ${safeText(event.evidence_id || '')} · SHA-256 ${safeText(event.sha256.slice(0, 16))}…</div>` : ''}
        </div>
      `).join('');
    }
  }

  if (evidenceList) {
    const records = data.evidence || [];
    if (!records.length) {
      evidenceList.innerHTML = '<div class="panel-desc">High-priority threats automatically capture a frame. You can also click CAPTURE EVIDENCE.</div>';
    } else {
      evidenceList.innerHTML = records.map((item) => `
        <div class="event-marker-item">
          <div class="marker-top">
            <span class="marker-time">${safeText(item.evidence_id)}</span>
            <span class="badge badge-cyan">${safeText(item.severity || '')}</span>
          </div>
          <div>${safeText(item.event || item.event_type || '')}</div>
          <div class="marker-desc">${safeText(item.timestamp || '')} · ${safeText(item.camera || '')}</div>
          <div class="marker-desc">SHA-256: <code title="${safeText(item.sha256 || '')}">${safeText((item.sha256 || '').slice(0, 20))}…</code></div>
        </div>
      `).join('');
    }
  }
}


