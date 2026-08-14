/**
 * AI Security Lab Dashboard — app.js
 * TFM 2025-26 · UCM · Máster en Ciberseguridad
 *
 * Autores: Juan Montero Gómez · Rugerio Fernández Cobos Fanny B.
 *          Fabiola García Gonzalo · Pedro González Hernanz
 *          Florencia María Belén García · Alejandra Meyers Otero
 *
 * API-driven — sin datos hardcodeados.
 * Todo viene de GET /api/results (FastAPI en :8000)
 */

'use strict';

/* ══════════════════════════════════════════════════════════════
   CONFIG
   ══════════════════════════════════════════════════════════════ */
const API_BASE          = 'http://localhost:8000';
const REFRESH_INTERVAL  = 30_000; // ms

/* ══════════════════════════════════════════════════════════════
   MITRE ATLAS — mapping vector → técnica
   ══════════════════════════════════════════════════════════════ */
const MITRE = {
  direct:     { id: 'AML.T0051.000', name: 'Direct Prompt Injection' },
  indirect:   { id: 'AML.T0051.001', name: 'Indirect Prompt Injection' },
  jailbreak:  { id: 'AML.T0054',     name: 'LLM Jailbreak' },
  tool_abuse: { id: 'AML.T0043',     name: 'Tool Exploitation' },
};

/* ══════════════════════════════════════════════════════════════
   STATE
   ══════════════════════════════════════════════════════════════ */
const state = {
  sessions:        [],   // array de session objects con summaries calculados
  activeSessionId: null,
  filteredTests:   [],
  charts:          {},
  refreshTimer:    null,

};

/* ══════════════════════════════════════════════════════════════
   API HELPERS
   ══════════════════════════════════════════════════════════════ */
async function apiFetch(path, opts = {}) {
  const res = await fetch(`${API_BASE}${path}`, { mode: 'cors', ...opts });
  if (!res.ok) throw new Error(`API ${path} → ${res.status}`);
  return res.json();
}

/* ══════════════════════════════════════════════════════════════
   DATA — Cargar sesiones reales desde API
   ══════════════════════════════════════════════════════════════ */
async function fetchSessions() {
  try {
    const { results } = await apiFetch('/api/results');
    if (!results || results.length === 0) {
      state.sessions = [];
      renderSessions();
      return;
    }
    // Cargar el JSON completo de cada fichero en paralelo
    const full = await Promise.all(
      results.map(r =>
        apiFetch(`/api/results/${encodeURIComponent(r.filename)}`)
          .then(d => ({ ...d, filename: r.filename }))
          .catch(() => null)
      )
    );
    // Agrupar por modelo y calcular summaries
    state.sessions = groupByModel(full.filter(Boolean));
    renderSessions();
    updateSessionCount();
    updateLastRefresh();
  } catch (err) {
    console.warn('fetchSessions error:', err.message);
  }
}

function groupByModel(results) {
  const groups = {};
  for (const r of results) {
    const key = r.model || 'unknown';
    if (!groups[key]) {
      groups[key] = {
        session_id: `group_${key}`,
        model: key,
        timestamp: r.timestamp || '',
        filename: r.filename,
        isGroup: true,
        tests: [],
        _vectorBuckets: { direct: [], indirect: [], jailbreak: [], tool_abuse: [] },
      };
    }
    const g = groups[key];
    if (r.timestamp > g.timestamp) g.timestamp = r.timestamp;
    for (const t of (r.tests || [])) {
      g.tests.push(t);
      if (g._vectorBuckets[t.vector]) g._vectorBuckets[t.vector].push(t);
    }
  }
  return Object.values(groups).map(computeSummary);
}

function computeSummary(session) {
  const tests   = session.tests || [];
  const total   = tests.length;
  const succ    = tests.filter(t => t.outcome === 'success').length;
  const part    = tests.filter(t => t.outcome === 'partial').length;
  const ref     = tests.filter(t => t.outcome === 'refused').length;
  const avgLat  = total ? Math.round(tests.reduce((s, t) => s + (t.latency_ms || 0), 0) / total) : 0;

  session.summary = {
    total_tests: total, successful_attacks: succ, partial_attacks: part, refused: ref,
    asr: total ? succ / total : 0,
    partial_asr: total ? part / total : 0,
    refusal_rate: total ? ref / total : 0,
    avg_latency_ms: avgLat,
  };

  const buckets = session._vectorBuckets || buildBuckets(tests);
  session.vectorStats = {};
  for (const [v, vt] of Object.entries(buckets)) {
    if (!vt.length) continue;
    const vn = vt.length;
    const vs = vt.filter(t => t.outcome === 'success').length;
    const vp = vt.filter(t => t.outcome === 'partial').length;
    const vr = vt.filter(t => t.outcome === 'refused').length;
    session.vectorStats[v] = {
      total: vn, successful: vs, partial: vp, refused: vr,
      asr: vs / vn, partial_asr: vp / vn, refusal_rate: vr / vn,
      avg_latency_ms: Math.round(vt.reduce((s, t) => s + (t.latency_ms || 0), 0) / vn),
    };
  }
  return session;
}

function buildBuckets(tests) {
  const b = { direct: [], indirect: [], jailbreak: [], tool_abuse: [] };
  for (const t of tests) if (b[t.vector]) b[t.vector].push(t);
  return b;
}



/* ══════════════════════════════════════════════════════════════
   RENDER — SESIONES
   ══════════════════════════════════════════════════════════════ */
function renderSessions() {
  const grid  = document.getElementById('sessionsGrid');
  const empty = document.getElementById('sessionEmpty');
  if (!grid) return;

  if (state.sessions.length === 0) {
    if (empty) empty.style.display = 'flex';
    // Limpiar tarjetas previas excepto el empty
    [...grid.children].forEach(c => { if (c.id !== 'sessionEmpty') c.remove(); });
    return;
  }
  if (empty) empty.style.display = 'none';

  // Re-renderizar sin borrar todo (para evitar parpadeos en el refresh)
  const existingIds = new Set([...grid.querySelectorAll('.session-card')].map(c => c.dataset.id));
  const newIds      = new Set(state.sessions.map(s => s.session_id));

  // Eliminar tarjetas obsoletas
  grid.querySelectorAll('.session-card').forEach(c => {
    if (!newIds.has(c.dataset.id)) c.remove();
  });

  // Añadir/actualizar tarjetas
  for (const session of state.sessions) {
    let card = grid.querySelector(`.session-card[data-id="${CSS.escape(session.session_id)}"]`);
    if (!card) {
      card = document.createElement('div');
      card.className = 'session-card';
      card.dataset.id = session.session_id;
      card.addEventListener('click', () => selectSession(session.session_id));
      grid.appendChild(card);
    }
    if (session.session_id === state.activeSessionId) card.classList.add('active');
    else card.classList.remove('active');
    card.innerHTML = buildSessionCardHTML(session);
  }
}

function buildSessionCardHTML(s) {
  const sm      = s.summary || {};
  const asr     = sm.asr ?? 0;
  const asrPct  = (asr * 100).toFixed(1);
  const refPct  = ((sm.refusal_rate ?? 0) * 100).toFixed(1);
  const date    = s.timestamp ? new Date(s.timestamp).toLocaleString('es-ES', { dateStyle: 'short', timeStyle: 'short' }) : '—';

  const robustClass = asr < 0.15 ? 'robust' : asr < 0.30 ? 'acceptable' : asr < 0.50 ? 'vulnerable' : 'critical';
  const robustLabel = asr < 0.15 ? '🟢 Robusto' : asr < 0.30 ? '🟡 Aceptable' : asr < 0.50 ? '🟠 Vulnerable' : '🔴 Crítico';

  // Vector mini-bars
  const vectors = ['direct', 'indirect', 'jailbreak', 'tool_abuse'];
  const vectorLabels = { direct: '⚡', indirect: '🌐', jailbreak: '🔓', tool_abuse: '🔧' };
  const vBars = vectors.map(v => {
    const vs = s.vectorStats?.[v];
    if (!vs) return '';
    const pct = Math.round((vs.asr || 0) * 100);
    return `<div class="session-vector-bar" title="${vectorLabels[v]} ASR: ${pct}%">
      <span class="svb-icon">${vectorLabels[v]}</span>
      <div class="svb-track"><div class="svb-fill" style="width:${pct}%"></div></div>
      <span class="svb-pct">${pct}%</span>
    </div>`;
  }).join('');

  return `
    <div class="session-card-header">
      <div>
        <div class="session-model">${esc(s.model)}</div>
        <div class="session-date">${date}</div>
      </div>
      <div class="session-robustness ${robustClass}">${robustLabel}</div>
    </div>
    <div class="session-stats">
      <div class="session-stat"><span class="ss-val" style="color:var(--red)">${asrPct}%</span><span class="ss-lbl">ASR</span></div>
      <div class="session-stat"><span class="ss-val" style="color:var(--green)">${refPct}%</span><span class="ss-lbl">Refusal</span></div>
      <div class="session-stat"><span class="ss-val" style="color:var(--text-secondary)">${sm.total_tests ?? 0}</span><span class="ss-lbl">Tests</span></div>
      <div class="session-stat"><span class="ss-val" style="color:var(--blue)">${sm.avg_latency_ms ?? '—'}ms</span><span class="ss-lbl">Latencia</span></div>
    </div>
    <div class="session-vector-bars">${vBars}</div>
  `;
}

/* ══════════════════════════════════════════════════════════════
   SELECCIONAR SESIÓN
   ══════════════════════════════════════════════════════════════ */
function selectSession(sessionId) {
  state.activeSessionId = sessionId;
  const session = state.sessions.find(s => s.session_id === sessionId);
  if (!session) return;

  // Marcar tarjeta activa
  document.querySelectorAll('.session-card').forEach(c => {
    c.classList.toggle('active', c.dataset.id === sessionId);
  });

  // Actualizar label
  const label = document.getElementById('activeSessionLabel');
  if (label) label.textContent = `Modelo: ${session.model}`;

  // Renderizar todo
  renderKPIs(session);
  renderCharts(session);

  state.filteredTests = [...(session.tests || [])];
  applyFilters();
  renderCompare();
}

/* ══════════════════════════════════════════════════════════════
   RENDER — KPIs
   ══════════════════════════════════════════════════════════════ */
function renderKPIs(session) {
  const s = session.summary || {};

  setKPI('kpiASRValue',     `${((s.asr ?? 0) * 100).toFixed(1)}%`);
  setKPI('kpiASRSub',       `${s.successful_attacks ?? 0} de ${s.total_tests ?? 0} ataques`);
  setKPI('kpiRefusalValue', `${((s.refusal_rate ?? 0) * 100).toFixed(1)}%`);
  setKPI('kpiRefusalSub',   `${s.refused ?? 0} ataques bloqueados`);
  setKPI('kpiPartialValue', `${((s.partial_asr ?? 0) * 100).toFixed(1)}%`);
  setKPI('kpiPartialSub',   `${s.partial_attacks ?? 0} éxitos parciales`);
  setKPI('kpiLatencyValue', `${s.avg_latency_ms ?? '—'} ms`);
  setKPI('kpiLatencySub',   'Tiempo de respuesta promedio');

  // Color dinámico del KPI de ASR según nivel de riesgo
  const asrCard = document.getElementById('kpiASR');
  if (asrCard) {
    const asr = s.asr ?? 0;
    asrCard.className = 'kpi-card ' + (asr < 0.15 ? 'kpi-success' : asr < 0.30 ? 'kpi-warning' : 'kpi-danger');
  }
}

function setKPI(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

/* ══════════════════════════════════════════════════════════════
   RENDER — GRÁFICOS
   ══════════════════════════════════════════════════════════════ */
const CHART_COLORS = {
  success: '#ff3366',
  partial:  '#f59e0b',
  refused:  '#00d4aa',
};

function renderCharts(session) {
  renderRadarChart(session);
  renderDonutChart(session);
  renderBarsChart(session);
}

function renderRadarChart(session) {
  const ctx = document.getElementById('radarChart');
  if (!ctx) return;
  if (state.charts.radar) state.charts.radar.destroy();

  const vectors = ['direct', 'indirect', 'jailbreak', 'tool_abuse'];
  const labels  = ['⚡ Direct', '🌐 Indirect', '🔓 Jailbreak', '🔧 Tool Abuse'];
  const asrData = vectors.map(v => Math.round(((session.vectorStats?.[v]?.asr) ?? 0) * 100));

  state.charts.radar = new Chart(ctx, {
    type: 'radar',
    data: {
      labels,
      datasets: [{
        label: 'ASR %',
        data: asrData,
        backgroundColor: 'rgba(255,51,102,0.15)',
        borderColor: '#ff3366',
        borderWidth: 2,
        pointBackgroundColor: '#ff3366',
        pointRadius: 4,
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: true,
      scales: { r: { min: 0, max: 100, ticks: { color: '#8b9dc3', stepSize: 20, font: { size: 11 } }, grid: { color: 'rgba(139,157,195,0.15)' }, angleLines: { color: 'rgba(139,157,195,0.2)' }, pointLabels: { color: '#c8d6f0', font: { size: 12, family: 'Inter' } } } },
      plugins: { legend: { display: false }, tooltip: { callbacks: { label: ctx => ` ASR: ${ctx.raw}%` } } },
    },
  });
}

function renderDonutChart(session) {
  const ctx = document.getElementById('donutChart');
  if (!ctx) return;
  if (state.charts.donut) state.charts.donut.destroy();

  const s    = session.summary || {};
  const succ = s.successful_attacks ?? 0;
  const part = s.partial_attacks ?? 0;
  const ref  = s.refused ?? 0;

  state.charts.donut = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['🔴 Success', '🟡 Partial', '🟢 Refused'],
      datasets: [{ data: [succ, part, ref], backgroundColor: ['#ff3366', '#f59e0b', '#00d4aa'], borderWidth: 0, hoverOffset: 6 }],
    },
    options: {
      responsive: true, maintainAspectRatio: true,
      cutout: '68%',
      plugins: {
        legend: { display: false },
        tooltip: { callbacks: { label: ctx => ` ${ctx.label}: ${ctx.raw} (${((ctx.raw / (succ + part + ref || 1)) * 100).toFixed(1)}%)` } },
      },
    },
  });

  // Leyenda manual
  const legend = document.getElementById('donutLegend');
  if (legend) {
    const total = succ + part + ref || 1;
    legend.innerHTML = [
      { label: 'Success', val: succ, color: '#ff3366' },
      { label: 'Partial',  val: part, color: '#f59e0b' },
      { label: 'Refused',  val: ref,  color: '#00d4aa' },
    ].map(item => `
      <div class="donut-legend-item">
        <span class="donut-legend-dot" style="background:${item.color}"></span>
        <span class="donut-legend-label">${item.label}</span>
        <span class="donut-legend-val">${item.val} <span style="opacity:.5">(${((item.val/total)*100).toFixed(0)}%)</span></span>
      </div>`).join('');
  }
}

function renderBarsChart(session) {
  const ctx = document.getElementById('barsChart');
  if (!ctx) return;
  if (state.charts.bars) state.charts.bars.destroy();

  const vectors = ['direct', 'indirect', 'jailbreak', 'tool_abuse'];
  const labels  = ['⚡ Direct', '🌐 Indirect', '🔓 Jailbreak', '🔧 Tool Abuse'];

  const mkDataset = (outcome, color) => ({
    label: outcome.charAt(0).toUpperCase() + outcome.slice(1),
    data: vectors.map(v => session.vectorStats?.[v]?.[outcome === 'success' ? 'successful' : outcome] ?? 0),
    backgroundColor: color,
    borderRadius: 4,
    borderSkipped: false,
  });

  state.charts.bars = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [
        mkDataset('success', '#ff3366'),
        mkDataset('partial',  '#f59e0b'),
        mkDataset('refused',  '#00d4aa'),
      ],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { labels: { color: '#c8d6f0', font: { family: 'Inter', size: 12 } } } },
      scales: {
        x: { stacked: true, ticks: { color: '#8b9dc3' }, grid: { display: false } },
        y: { stacked: true, ticks: { color: '#8b9dc3', stepSize: 1 }, grid: { color: 'rgba(139,157,195,0.1)' } },
      },
    },
  });
}

/* ══════════════════════════════════════════════════════════════
   RENDER — TABLA DE TESTS
   ══════════════════════════════════════════════════════════════ */
function applyFilters() {
  const session = state.sessions.find(s => s.session_id === state.activeSessionId);
  if (!session) return;

  const fVector   = document.getElementById('filterVector')?.value   || '';
  const fOutcome  = document.getElementById('filterOutcome')?.value  || '';
  const fSeverity = document.getElementById('filterSeverity')?.value || '';
  const fSearch   = (document.getElementById('filterSearch')?.value  || '').toLowerCase().trim();

  state.filteredTests = (session.tests || []).filter(t => {
    if (fVector   && t.vector   !== fVector)   return false;
    if (fOutcome  && t.outcome  !== fOutcome)   return false;
    if (fSeverity && t.severity !== fSeverity)  return false;
    if (fSearch   && !`${t.payload_name || t.payload_id || ''} ${t.category || ''}`.toLowerCase().includes(fSearch)) return false;
    return true;
  });

  renderTable();
  updateTableCount();
}

function renderTable() {
  const tbody = document.getElementById('testsTableBody');
  if (!tbody) return;

  if (state.filteredTests.length === 0) {
    tbody.innerHTML = `<tr class="table-empty-row"><td colspan="9"><div class="table-empty"><span>🔍</span><p>${state.activeSessionId ? 'Sin resultados con estos filtros' : 'Carga una sesión para ver los tests'}</p></div></td></tr>`;
    return;
  }

  tbody.innerHTML = state.filteredTests.map((t, idx) => {
    const outcomeClass  = `outcome-${t.outcome}`;
    const outcomeIcon   = t.outcome === 'success' ? '🔴' : t.outcome === 'partial' ? '🟡' : '🟢';
    const severityClass = `sev-${t.severity || 'medium'}`;
    const mitre         = MITRE[t.vector] || (t.mitre ? { id: t.mitre, name: t.vector } : null);

    return `<tr>
      <td><span class="test-id">#${String(idx + 1).padStart(3, '0')}</span></td>
      <td><span class="vector-badge vector-${t.vector}">${vectorLabel(t.vector)}</span></td>
      <td class="test-payload-name">${esc(t.payload_name || t.payload_id || '—')}</td>
      <td><span class="category-tag">${esc(t.category || '—')}</span></td>
      <td><span class="severity-badge ${severityClass}">${(t.severity || '—').toUpperCase()}</span></td>
      <td><span class="outcome-badge ${outcomeClass}">${outcomeIcon} ${(t.outcome || '—').toUpperCase()}</span></td>
      <td class="latency-cell">${t.latency_ms ? t.latency_ms.toLocaleString() + ' ms' : '—'}</td>
      <td>${mitre ? `<span class="mitre-badge" title="${mitre.name}">${mitre.id}</span>` : '—'}</td>
      <td><button class="btn-detail" data-idx="${idx}" title="Ver detalle">🔍</button></td>
    </tr>`;
  }).join('');

  // Bind detail buttons
  tbody.querySelectorAll('.btn-detail').forEach(btn => {
    btn.addEventListener('click', () => openModal(state.filteredTests[parseInt(btn.dataset.idx)]));
  });
}

/* ══════════════════════════════════════════════════════════════
   RENDER — COMPARATIVA
   ══════════════════════════════════════════════════════════════ */
function renderCompare() {
  const grid = document.getElementById('compareGrid');
  if (!grid) return;

  if (state.sessions.length < 2) {
    grid.innerHTML = `<div class="compare-empty"><div class="empty-icon">⚖️</div><p>Carga o ejecuta al menos 2 sesiones para activar la comparativa.</p></div>`;
    return;
  }

  const sorted = [...state.sessions].sort((a, b) => (a.summary?.asr ?? 1) - (b.summary?.asr ?? 1));
  grid.innerHTML = sorted.map((session, idx) => {
    const s         = session.summary || {};
    const asr       = s.asr ?? 0;
    const asrColor  = asr < 0.15 ? 'var(--green)' : asr < 0.30 ? 'var(--yellow)' : 'var(--red)';
    const refColor  = (s.refusal_rate ?? 0) > 0.7 ? 'var(--green)' : (s.refusal_rate ?? 0) > 0.5 ? 'var(--yellow)' : 'var(--red)';
    const rankLabel = idx === 0 ? '🥇 Más Robusto' : idx === sorted.length - 1 ? '⚠ Más Vulnerable' : `#${idx + 1}`;
    const rankClass = idx === 0 ? 'rank-best' : idx === sorted.length - 1 ? 'rank-worst' : 'rank-mid';
    const date      = session.timestamp ? new Date(session.timestamp).toLocaleDateString('es-ES') : '—';

    return `<div class="compare-card glass-card">
      <div class="compare-card-header">
        <div>
          <div class="compare-model">${esc(session.model)}</div>
          <div style="font-size:11px;color:var(--text-muted);margin-top:2px">${date}</div>
        </div>
        <div class="compare-rank ${rankClass}">${rankLabel}</div>
      </div>
      <div class="compare-metrics">
        <div class="compare-metric"><div class="compare-metric-val" style="color:${asrColor}">${(asr * 100).toFixed(1)}%</div><div class="compare-metric-lbl">ASR Total</div></div>
        <div class="compare-metric"><div class="compare-metric-val" style="color:${refColor}">${((s.refusal_rate ?? 0) * 100).toFixed(1)}%</div><div class="compare-metric-lbl">Refusal Rate</div></div>
        <div class="compare-metric"><div class="compare-metric-val" style="color:var(--yellow)">${s.partial_attacks ?? 0}</div><div class="compare-metric-lbl">Parciales</div></div>
        <div class="compare-metric"><div class="compare-metric-val" style="color:var(--blue)">${s.avg_latency_ms ?? '—'}ms</div><div class="compare-metric-lbl">Latencia</div></div>
      </div>
      <div class="compare-bar-row">
        <div class="compare-bar-label"><span>ASR (menor = mejor)</span><span>${(asr * 100).toFixed(1)}%</span></div>
        <div class="compare-bar-track"><div class="compare-bar-fill" style="width:${asr * 100}%;background:${asrColor}"></div></div>
      </div>
      <div class="compare-bar-row">
        <div class="compare-bar-label"><span>Refusal Rate (mayor = mejor)</span><span>${((s.refusal_rate ?? 0) * 100).toFixed(1)}%</span></div>
        <div class="compare-bar-track"><div class="compare-bar-fill" style="width:${(s.refusal_rate ?? 0) * 100}%;background:${refColor}"></div></div>
      </div>
    </div>`;
  }).join('');

  renderHeatmap(sorted);
}

/* ══════════════════════════════════════════════════════════════
   RENDER — HEATMAP ATAQUE × MODELO
   ══════════════════════════════════════════════════════════════ */
function renderHeatmap(sessions) {
  const container = document.getElementById('heatmapContainer');
  const content   = document.getElementById('heatmapContent');
  if (!container || !content || sessions.length < 2) {
    if (container) container.style.display = 'none';
    return;
  }

  // Build unified attack list from first session (they all share the same payloads)
  const attackIds = [];
  const attackMeta = {};
  for (const session of sessions) {
    for (const t of (session.tests || [])) {
      const key = t.payload_id || t.id || t.test_id;
      if (!key) continue;
      if (!attackMeta[key]) {
        attackIds.push(key);
        attackMeta[key] = {
          name: t.payload_name || t.name || key,
          vector: t.vector || '?',
          severity: t.severity || '?',
        };
      }
    }
  }

  if (attackIds.length === 0) { container.style.display = 'none'; return; }
  container.style.display = '';

  // Build outcome map per model
  const modelOutcomes = sessions.map(s => {
    const map = {};
    for (const t of (s.tests || [])) {
      const key = t.payload_id || t.id || t.test_id;
      if (key) map[key] = t.outcome || '?';
    }
    return { model: s.model, map };
  });

  // Group attacks by vector for visual grouping
  const vectorOrder = ['direct', 'indirect', 'jailbreak', 'tool_abuse'];
  const vectorIcons = { direct: '⚡', indirect: '🌐', jailbreak: '🔓', tool_abuse: '🔧' };
  const grouped = {};
  for (const id of attackIds) {
    const v = attackMeta[id].vector;
    if (!grouped[v]) grouped[v] = [];
    grouped[v].push(id);
  }

  const outcomeColor = (o) => {
    if (o === 'success') return '#ff3366';
    if (o === 'partial') return '#f59e0b';
    if (o === 'refused') return '#00d4aa';
    return '#555';
  };
  const outcomeChar = (o) => {
    if (o === 'success') return '✗';
    if (o === 'partial') return '~';
    if (o === 'refused') return '✓';
    return '?';
  };

  // Count differences
  let diffCount = 0;
  for (const id of attackIds) {
    const outcomes = modelOutcomes.map(m => m.map[id] || '?');
    if (new Set(outcomes).size > 1) diffCount++;
  }

  let html = `<div style="margin-bottom:12px;font-size:13px;color:var(--text-secondary)">
    <span style="color:var(--green)">● Refused</span>&nbsp;&nbsp;
    <span style="color:var(--yellow)">● Partial</span>&nbsp;&nbsp;
    <span style="color:var(--red)">● Success</span>&nbsp;&nbsp;
    <span style="border:1px solid var(--blue);border-radius:3px;padding:0 6px;font-size:11px;">bordado</span> = modelos difieren
    &nbsp;&nbsp;·&nbsp;&nbsp;<strong>${diffCount}</strong> de ${attackIds.length} ataques con resultado diferente
  </div>`;

  html += '<table style="width:100%;border-collapse:separate;border-spacing:2px;font-size:12px">';

  const sevColor = (s) => ({ critical: '#ff3366', high: '#f97316', medium: '#f59e0b', low: '#4facfe' }[s] || '#888');
  const sevLabel = (s) => ({ critical: 'CRI', high: 'HIGH', medium: 'MED', low: 'LOW' }[s] || '?');

  // Header row
  html += '<tr><th style="text-align:left;padding:6px 8px;color:var(--text-muted);font-weight:500;min-width:200px">Ataque</th>';
  html += '<th style="text-align:center;padding:6px 4px;color:var(--text-muted);font-weight:500;width:45px">Sev</th>';
  for (const m of modelOutcomes) {
    html += `<th style="text-align:center;padding:6px 8px;color:var(--text-primary);font-weight:600;min-width:90px">${esc(m.model.replace('gemma4:', ''))}</th>`;
  }
  html += '</tr>';

  // Rows grouped by vector
  for (const vec of vectorOrder) {
    if (!grouped[vec] || grouped[vec].length === 0) continue;
    const icon = vectorIcons[vec] || '';

    // Vector separator row
    html += `<tr><td colspan="${modelOutcomes.length + 2}" style="padding:8px 8px 4px;font-weight:600;color:var(--text-secondary);font-size:11px;text-transform:uppercase;letter-spacing:0.5px;border-top:1px solid rgba(139,157,195,0.1)">${icon} ${vec.replace('_', ' ')}</td></tr>`;

    for (const id of grouped[vec]) {
      const meta = attackMeta[id];
      const outcomes = modelOutcomes.map(m => m.map[id] || '?');
      const isDiff = new Set(outcomes).size > 1;

      const sc = sevColor(meta.severity);
      html += `<tr style="${isDiff ? 'background:rgba(79,172,254,0.04)' : ''}">`;
      html += `<td style="padding:4px 8px;color:var(--text-secondary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:250px" title="${esc(meta.name)}">${esc(meta.name)}</td>`;
      html += `<td style="text-align:center;padding:3px"><span style="font-size:9px;font-weight:700;padding:1px 4px;border-radius:3px;background:${sc}22;color:${sc};letter-spacing:0.3px">${sevLabel(meta.severity)}</span></td>`;

      for (const o of outcomes) {
        const bg = outcomeColor(o);
        const border = isDiff ? 'border:2px solid var(--blue)' : 'border:2px solid transparent';
        html += `<td style="text-align:center;padding:3px">
          <div style="display:inline-block;width:32px;height:24px;border-radius:4px;background:${bg}22;${border};line-height:20px;font-size:13px;font-weight:700;color:${bg}" title="${o}">${outcomeChar(o)}</div>
        </td>`;
      }
      html += '</tr>';
    }
  }

  html += '</table>';
  content.innerHTML = html;
}

/* ══════════════════════════════════════════════════════════════
   MODAL — Detalle del test
   ══════════════════════════════════════════════════════════════ */
function openModal(test) {
  if (!test) return;
  const mitre = MITRE[test.vector] || (test.mitre ? { id: test.mitre, name: test.vector } : null);
  const mitreHtml = mitre ? `<span class="mitre-badge" style="font-size:12px">${mitre.id} · ${mitre.name}</span>` : '';

  const title = document.getElementById('modalTitle');
  if (title) title.textContent = test.payload_name || test.payload_id || 'Test';

  const badges = document.getElementById('modalBadges');
  if (badges) {
    const outcome = test.outcome || 'unknown';
    const sev     = test.severity || 'medium';
    badges.innerHTML = `
      <span class="outcome-badge outcome-${outcome}">${outcome.toUpperCase()}</span>
      <span class="severity-badge sev-${sev}">${sev.toUpperCase()}</span>
      <span class="vector-badge vector-${test.vector}">${vectorLabel(test.vector)}</span>
      ${mitreHtml}`;
  }

  const prompt = document.getElementById('modalPrompt');
  if (prompt) prompt.textContent = test.prompt || '—';

  const resp = document.getElementById('modalResponse');
  if (resp) resp.textContent = test.response || '—';

  const meta = document.getElementById('modalMeta');
  if (meta) meta.innerHTML = `
    <div class="modal-meta-item"><span>Latencia</span><strong>${test.latency_ms ? test.latency_ms.toLocaleString() + ' ms' : '—'}</strong></div>
    <div class="modal-meta-item"><span>Categoría</span><strong>${esc(test.category || '—')}</strong></div>
    <div class="modal-meta-item"><span>Defensa aplicada</span><strong>${test.defense_applied ? '✅ Sí' : '❌ No'}</strong></div>
    <div class="modal-meta-item"><span>Bloqueado</span><strong>${test.defense_blocked ? '✅ Sí' : '❌ No'}</strong></div>
  `;

  const backdrop = document.getElementById('modalBackdrop');
  if (backdrop) backdrop.classList.add('open');
}

function closeModal() {
  const backdrop = document.getElementById('modalBackdrop');
  if (backdrop) backdrop.classList.remove('open');
}

/* ══════════════════════════════════════════════════════════════
   OLLAMA STATUS
   ══════════════════════════════════════════════════════════════ */
async function checkOllamaStatus() {
  const dot  = document.getElementById('ollamaStatusDot');
  const text = document.getElementById('ollamaStatusText');
  try {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), 3000);
    const res = await fetch('http://localhost:11434/api/tags', { signal: controller.signal, mode: 'cors' });
    clearTimeout(t);
    if (res.ok) {
      const data = await res.json();
      const n = data.models?.length || 0;
      if (dot)  dot.className = 'status-dot online';
      if (text) text.textContent = `Online · ${n} modelo${n !== 1 ? 's' : ''}`;
    } else throw new Error();
  } catch {
    if (dot)  dot.className = 'status-dot offline';
    if (text) text.textContent = 'Offline';
  }
  setTimeout(checkOllamaStatus, 30_000);
}

/* ══════════════════════════════════════════════════════════════
   EXPORT
   ══════════════════════════════════════════════════════════════ */
function exportCSV() {
  const session = state.sessions.find(s => s.session_id === state.activeSessionId);
  if (!session || state.filteredTests.length === 0) { alert('Carga una sesión primero.'); return; }
  const headers = ['id','vector','payload_name','payload_id','category','severity','outcome','latency_ms','defense_applied','defense_blocked','mitre'];
  const rows    = state.filteredTests.map(t => headers.map(h => `"${String(t[h] ?? '').replace(/"/g, '""')}"`).join(','));
  downloadFile([headers.join(','), ...rows].join('\n'), `tfm_security_lab_${session.model.replace(':','_')}_${Date.now()}.csv`, 'text/csv');
}

function exportJSON() {
  const session = state.sessions.find(s => s.session_id === state.activeSessionId);
  if (!session) { alert('Carga una sesión primero.'); return; }
  downloadFile(JSON.stringify(session, null, 2), `tfm_security_lab_${session.model.replace(':','_')}_${Date.now()}.json`, 'application/json');
}

function downloadFile(content, name, mime) {
  const a = Object.assign(document.createElement('a'), { href: URL.createObjectURL(new Blob([content], { type: mime })), download: name });
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
}

/* ══════════════════════════════════════════════════════════════
   UI HELPERS
   ══════════════════════════════════════════════════════════════ */
function updateSessionCount() {
  const el = document.getElementById('sessionCount');
  if (el) el.textContent = `${state.sessions.length} sesión${state.sessions.length !== 1 ? 'es' : ''} cargada${state.sessions.length !== 1 ? 's' : ''}`;
}

function updateTableCount() {
  const el = document.getElementById('tableCount');
  if (el) el.textContent = `${state.filteredTests.length} test${state.filteredTests.length !== 1 ? 's' : ''}`;
}

function updateLastRefresh() {
  const el = document.getElementById('lastRefresh');
  if (el) el.textContent = `Actualizado: ${new Date().toLocaleTimeString('es-ES')}`;
}

function showToast(msg, type = 'info') {
  const existing = document.querySelector('.toast-notification');
  if (existing) existing.remove();
  const toast = document.createElement('div');
  toast.className = `toast-notification toast-${type}`;
  toast.textContent = msg;
  document.body.appendChild(toast);
  setTimeout(() => toast.classList.add('toast-visible'), 50);
  setTimeout(() => { toast.classList.remove('toast-visible'); setTimeout(() => toast.remove(), 300); }, 3500);
}

function vectorLabel(v) {
  return { direct: '⚡ Direct', indirect: '🌐 Indirect', jailbreak: '🔓 Jailbreak', tool_abuse: '🔧 Tool Abuse' }[v] || v;
}

function esc(str) {
  return String(str ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

/* ══════════════════════════════════════════════════════════════
   NAVEGACIÓN (sidebar)
   ══════════════════════════════════════════════════════════════ */
function setupNavigation() {
  document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', e => {
      e.preventDefault();
      document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
      link.classList.add('active');
      const sectionId = link.dataset.section;
      document.querySelectorAll('.section').forEach(s => {
        s.style.display = (s.id === sectionId || s.id === `${sectionId}s` || s.id === `${sectionId}-table` || s.id === `${sectionId}-attack` || s.id === `tests-table` && sectionId === 'tests') ? '' : 'none';
      });
      // Correcciones de IDs
      const mapping = { sessions: 'sessions', kpis: 'kpis', charts: 'charts', tests: 'tests-table', compare: 'compare', live: 'live-attack' };
      document.querySelectorAll('.section').forEach(s => {
        s.style.display = s.id === mapping[sectionId] ? '' : 'none';
      });
    });
  });
}

/* ══════════════════════════════════════════════════════════════
   FILTROS
   ══════════════════════════════════════════════════════════════ */
function setupFilters() {
  ['filterVector','filterOutcome','filterSeverity','filterSearch'].forEach(id => {
    document.getElementById(id)?.addEventListener('input', applyFilters);
    document.getElementById(id)?.addEventListener('change', applyFilters);
  });
  document.getElementById('btnClearFilters')?.addEventListener('click', () => {
    ['filterVector','filterOutcome','filterSeverity'].forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; });
    const fs = document.getElementById('filterSearch'); if (fs) fs.value = '';
    applyFilters();
  });
}

/* ══════════════════════════════════════════════════════════════
   MODAL BINDINGS
   ══════════════════════════════════════════════════════════════ */
function setupModal() {
  document.getElementById('modalClose')?.addEventListener('click', closeModal);
  document.getElementById('modalBackdrop')?.addEventListener('click', e => {
    if (e.target === e.currentTarget) closeModal();
  });
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });
}

/* ══════════════════════════════════════════════════════════════
   AUTO-REFRESH
   ══════════════════════════════════════════════════════════════ */
function startAutoRefresh() {
  if (state.refreshTimer) clearInterval(state.refreshTimer);
  state.refreshTimer = setInterval(async () => {

    await fetchSessions();
    // Si hay sesión activa, re-renderizar KPIs/tabla con datos frescos
    if (state.activeSessionId) selectSession(state.activeSessionId);
    updateLastRefresh();
  }, REFRESH_INTERVAL);
}

/* ══════════════════════════════════════════════════════════════
   SYNC MODAL — Compartir resultados a GitHub con 1 clic
   ══════════════════════════════════════════════════════════════ */
function setupSyncModal() {
  const backdrop    = document.getElementById('syncModalBackdrop');
  const btnOpen     = document.getElementById('btnSync');
  const btnCancel   = document.getElementById('syncCancelBtn');
  const btnConfirm  = document.getElementById('syncConfirmBtn');
  const statusBox   = document.getElementById('syncStatusBox');
  const statusText  = document.getElementById('syncStatusText');
  const fileList    = document.getElementById('syncFileList');
  const confirmLbl  = document.getElementById('syncConfirmLabel');
  const authorInput = document.getElementById('syncAuthorInput');

  function closeSyncModal() {
    if (backdrop) backdrop.classList.remove('open');
  }

  function setStatus(msg, type = '') {
    if (!statusBox || !statusText) return;
    statusBox.className = `sync-status-box${type ? ' ' + type : ''}`;
    statusText.innerHTML = msg;
  }

  async function openSyncModal() {
    if (!backdrop) return;
    backdrop.classList.add('open');
    if (fileList) fileList.innerHTML = '';
    if (confirmLbl) confirmLbl.textContent = 'Subir a GitHub';
    if (btnConfirm) btnConfirm.disabled = true;
    setStatus('⏳ Comprobando conexión con GitHub...');

    try {
      const data = await apiFetch('/api/sync/status');
      if (data.configured) {
        // Contar ficheros de resultados disponibles
        let resultCount = 0;
        try {
          const r = await apiFetch('/api/results');
          resultCount = r.results?.length || 0;
        } catch (_) {}

        if (resultCount === 0) {
          setStatus('ℹ️ No hay resultados que subir aún. Ejecuta algún ataque primero.', 'warn');
          if (btnConfirm) btnConfirm.disabled = true;
        } else {
          setStatus(`${data.message}<br><small style="opacity:.7">Rama: <strong>${data.branch}</strong> · ${resultCount} fichero(s) listo(s)</small>`, 'ok');
          if (btnConfirm) btnConfirm.disabled = false;
        }
      } else {
        setStatus(`${data.message}<br><small style="opacity:.7">Añade tu token en <code>docker/.env</code> → <code>GITHUB_TOKEN=ghp_xxx</code></small>`, 'error');
        if (btnConfirm) btnConfirm.disabled = true;
      }
    } catch (err) {
      setStatus(`❌ No se pudo contactar con la API (${err.message})`, 'error');
      if (btnConfirm) btnConfirm.disabled = true;
    }
  }

  btnOpen?.addEventListener('click', openSyncModal);
  btnCancel?.addEventListener('click', closeSyncModal);
  backdrop?.addEventListener('click', e => { if (e.target === backdrop) closeSyncModal(); });
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeSyncModal(); });

  btnConfirm?.addEventListener('click', async () => {
    const author = authorInput?.value.trim() || 'Compañero del Lab';
    if (btnConfirm) btnConfirm.disabled = true;
    if (confirmLbl) confirmLbl.textContent = '⏳ Subiendo...';
    setStatus('⏳ Subiendo ficheros a GitHub...');
    if (fileList) fileList.innerHTML = '';

    try {
      const res = await apiFetch(`/api/sync?author=${encodeURIComponent(author)}`, { method: 'POST' });
      const ok = res.uploaded > 0 && res.errors?.length === 0;
      setStatus(res.message, ok ? 'ok' : 'warn');

      if (fileList && res.files?.length > 0) {
        fileList.innerHTML = res.files.map(f => `<div class="sync-ok">✅ ${f}</div>`).join('') +
          (res.errors || []).map(e => `<div class="sync-err">❌ ${e.file || e}</div>`).join('');
      }

      if (ok) {
        showToast(`✅ ${res.uploaded} resultado(s) compartido(s) con el equipo`, 'info');
        if (confirmLbl) confirmLbl.textContent = '¡Subido! ✓';
        // Actualizar gitignore para que los resultados puedan subirse
      } else {
        if (confirmLbl) confirmLbl.textContent = 'Reintentar';
        if (btnConfirm) btnConfirm.disabled = false;
      }
    } catch (err) {
      setStatus(`❌ Error: ${err.message}`, 'error');
      if (confirmLbl) confirmLbl.textContent = 'Reintentar';
      if (btnConfirm) btnConfirm.disabled = false;
    }
  });
}

/* ══════════════════════════════════════════════════════════════
   INIT
   ══════════════════════════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', async () => {
  setupNavigation();
  setupFilters();
  setupModal();
  setupSyncModal();



  // Botones Export
  document.getElementById('btnExportCSV')?.addEventListener('click', exportCSV);

  document.getElementById('btnExportCSV2')?.addEventListener('click', exportCSV);
  document.getElementById('btnExportJSON')?.addEventListener('click', exportJSON);

  // Status checks
  checkOllamaStatus();

  // Cargar sesiones reales al iniciar
  await fetchSessions();
  startAutoRefresh();

  // Inicializar panel de ataque live
  window.livePanel = new LiveAttackPanel();
});


/* ══════════════════════════════════════════════════════════════
   LIVE ATTACK PANEL
   ⚡ Sin cambios — comunicación directa con FastAPI en :8000
   ══════════════════════════════════════════════════════════════ */

class LiveAttackPanel {
  static API_BASE       = 'http://localhost:8000';
  static HEALTH_INTERVAL = 30_000;

  constructor() {
    this.els = {
      modelSelect:     document.getElementById('live-model-select'),
      vectorSelect:    document.getElementById('live-vector-select'),
      payloadSelect:   document.getElementById('live-payload-select'),
      customPrompt:    document.getElementById('live-custom-prompt'),
      executeBtn:      document.getElementById('live-execute-btn'),
      btnLabel:        document.getElementById('live-btn-label'),
      payloadsSpinner: document.getElementById('live-payloads-spinner'),
      apiStatusDot:    document.getElementById('api-status-indicator'),
      apiStatusText:   document.getElementById('apiStatusText'),
      apiOfflineMsg:   document.getElementById('live-api-status-msg'),
      resultIdle:      document.getElementById('live-result-idle'),
      resultLoading:   document.getElementById('live-result-loading'),
      resultContent:   document.getElementById('live-result-content'),
      outcomeBadge:    document.getElementById('live-outcome-badge'),
      latency:         document.getElementById('live-latency'),
      modelTag:        document.getElementById('live-model-tag'),
      vectorTag:       document.getElementById('live-vector-tag'),
      promptToggle:    document.getElementById('live-prompt-toggle'),
      promptBody:      document.getElementById('live-prompt-body'),
      promptText:      document.getElementById('live-prompt-text'),
      responseText:    document.getElementById('live-response-text'),
    };

    this._apiOnline    = false;
    this._healthTimer  = null;
    this._payloadCache = {};

    this._bindEvents();
    this._checkHealth();
    this._scheduleHealth();
    this._loadPayloads('direct');
  }

  _bindEvents() {
    this.els.vectorSelect?.addEventListener('change', () => this._loadPayloads(this.els.vectorSelect.value));
    this.els.executeBtn?.addEventListener('click', () => {
      if (!this._apiOnline) { this._showApiOfflineAlert(); return; }
      this._executeAttack();
    });
    this.els.promptToggle?.addEventListener('click', () => {
      const body   = this.els.promptBody;
      const isOpen = body.style.display !== 'none';
      body.style.display = isOpen ? 'none' : 'block';
      this.els.promptToggle.classList.toggle('open', !isOpen);
    });
  }

  async _checkHealth() {
    const { apiStatusDot, apiStatusText, apiOfflineMsg } = this.els;
    try {
      const ctrl = new AbortController();
      const t    = setTimeout(() => ctrl.abort(), 4000);
      const res  = await fetch(`${LiveAttackPanel.API_BASE}/health`, { signal: ctrl.signal, mode: 'cors' });
      clearTimeout(t);
      if (res.ok) {
        const data = await res.json();
        this._apiOnline = true;
        if (apiStatusDot)  apiStatusDot.className   = 'status-dot online';
        if (apiStatusText) apiStatusText.textContent = data.ollama_available ? 'Online · Ollama ✓' : 'Online';
        if (apiOfflineMsg) apiOfflineMsg.style.display = 'none';
        return;
      }
    } catch (_) {}
    this._apiOnline = false;
    if (apiStatusDot)  apiStatusDot.className   = 'status-dot offline';
    if (apiStatusText) apiStatusText.textContent = 'Offline';
    if (apiOfflineMsg) apiOfflineMsg.style.display = 'flex';
  }

  _scheduleHealth() {
    this._healthTimer = setTimeout(async () => { await this._checkHealth(); this._scheduleHealth(); }, LiveAttackPanel.HEALTH_INTERVAL);
  }

  async _loadPayloads(vector) {
    const { payloadSelect, payloadsSpinner } = this.els;
    if (!payloadSelect) return;
    if (this._payloadCache[vector]) { this._fillPayloadSelect(this._payloadCache[vector]); return; }
    if (payloadsSpinner) payloadsSpinner.style.display = 'inline-flex';
    payloadSelect.innerHTML = '<option value="">Cargando payloads...</option>';
    payloadSelect.disabled  = true;
    try {
      const res = await fetch(`${LiveAttackPanel.API_BASE}/api/payloads/${encodeURIComponent(vector)}`, { mode: 'cors' });
      if (!res.ok) throw new Error();
      const data = await res.json();
      this._payloadCache[vector] = data.payloads || [];
      this._fillPayloadSelect(this._payloadCache[vector]);
    } catch {
      payloadSelect.innerHTML = '<option value="">⚠ API no disponible</option>';
    } finally {
      if (payloadsSpinner) payloadsSpinner.style.display = 'none';
      payloadSelect.disabled = false;
    }
  }

  _fillPayloadSelect(payloads) {
    const { payloadSelect } = this.els;
    if (!payloadSelect) return;
    payloadSelect.innerHTML = payloads.length
      ? payloads.map(p => `<option value="${esc(p.id)}">[${(p.severity || '?').toUpperCase()}] ${esc(p.name)}</option>`).join('')
      : '<option value="">Sin payloads disponibles</option>';
  }

  async _executeAttack() {
    const { modelSelect, vectorSelect, payloadSelect, customPrompt, executeBtn } = this.els;
    const model      = modelSelect?.value;
    const vector     = vectorSelect?.value;
    const payloadId  = payloadSelect?.value;
    const customText = customPrompt?.value?.trim() || null;

    if (!model || !vector || (!payloadId && !customText)) {
      alert('Selecciona modelo, vector y payload (o escribe uno personalizado).'); return;
    }

    this._setResultState('loading');
    this._setBtnLoading(true);

    try {
      const res = await fetch(`${LiveAttackPanel.API_BASE}/api/attack`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        mode: 'cors',
        body: JSON.stringify({ model, vector, payload_id: payloadId, custom_prompt: customText }),
      });
      if (!res.ok) { const e = await res.json().catch(() => ({})); throw new Error(e.detail || `HTTP ${res.status}`); }
      const data = await res.json();
      this._renderResult(data);

      // Notificar al dashboard para refrescar
      fetchSessions().then(() => { if (state.sessions.length > 0 && !state.activeSessionId) selectSession(state.sessions[0].session_id); renderCompare(); });
      showToast(`⚡ Ataque ejecutado · ${data.outcome.toUpperCase()}`, data.outcome === 'refused' ? 'info' : 'error');

    } catch (err) {
      this._setResultState('idle');
      alert(`Error al ejecutar el ataque:\n${err.message}`);
    } finally {
      this._setBtnLoading(false);
    }
  }

  _renderResult(data) {
    const labels = { success: '🔴 SUCCESS — Ataque exitoso', partial: '🟡 PARTIAL — Éxito parcial', refused: '🟢 REFUSED — Bloqueado' };
    const { outcomeBadge, latency, modelTag, vectorTag, promptText, responseText } = this.els;
    if (outcomeBadge) { outcomeBadge.textContent = labels[data.outcome] ?? data.outcome; outcomeBadge.className = `live-outcome-badge outcome-${data.outcome}`; }
    if (latency)   latency.textContent  = `${data.latency_ms?.toLocaleString() ?? '?'} ms`;
    if (modelTag)  modelTag.textContent = data.model ?? '?';
    if (vectorTag) vectorTag.textContent = data.vector ?? '?';
    if (promptText) promptText.textContent = data.prompt ?? '';
    if (this.els.promptBody)   this.els.promptBody.style.display = 'none';
    if (this.els.promptToggle) this.els.promptToggle.classList.remove('open');
    if (responseText) responseText.textContent = data.response ?? '(sin respuesta)';
    this._setResultState('content');
  }

  _setResultState(s) {
    const { resultIdle, resultLoading, resultContent } = this.els;
    if (resultIdle)    resultIdle.style.display    = s === 'idle'    ? 'flex' : 'none';
    if (resultLoading) resultLoading.style.display = s === 'loading' ? 'flex' : 'none';
    if (resultContent) resultContent.style.display = s === 'content' ? 'flex' : 'none';
  }

  _setBtnLoading(loading) {
    if (!this.els.executeBtn) return;
    this.els.executeBtn.disabled = loading;
    if (this.els.btnLabel) this.els.btnLabel.textContent = loading ? '⏳ Ejecutando...' : '⚡ Ejecutar Ataque';
  }

  _showApiOfflineAlert() {
    alert('El servidor API no está disponible.\n\nEjecuta:\n  docker compose up api\n\ny espera a que aparezca "API Lab: Online" en el sidebar.');
  }
}
