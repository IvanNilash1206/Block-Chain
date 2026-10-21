const $ = (id) => document.getElementById(id);
let selected = 'VP-1001';
let overview = null;

const escapeHtml = (value) => String(value).replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
const shortHash = (hash) => hash ? `${hash.slice(0, 21)}…${hash.slice(-13)}` : '—';
const stamp = (seconds) => new Date(seconds * 1000).toLocaleString(undefined, {dateStyle:'medium', timeStyle:'short'});

async function api(url, options = {}) {
  const response = await fetch(url, {headers: {'Content-Type':'application/json'}, ...options});
  const body = await response.json();
  if (!response.ok) throw new Error(body.detail?.message || body.detail || 'Request failed');
  return body;
}

function render() {
  const products = overview.products;
  const current = products.find(p => p.id === selected) || products[0];
  selected = current.id;
  $('metric-products').textContent = products.length;
  $('metric-scans').textContent = overview.authenticated_scans;
  $('metric-tamper').textContent = products.filter(p => p.tampered).length;
  $('metric-ledger').textContent = overview.ledger_height;
  $('ledger-integrity').textContent = overview.ledger_valid ? 'Hash links verified' : 'Integrity failure detected';
  $('ledger-pill').textContent = overview.ledger_valid ? '✓ VERIFIED' : '⚠ INVALID';
  $('ledger-pill').className = `ledger-pill ${overview.ledger_valid ? 'good' : 'bad'}`;
  $('latest-hash').textContent = shortHash(overview.latest_hash);
  $('latest-hash').title = overview.latest_hash;
  $('selected-name').textContent = current.name;
  $('selected-meta').textContent = `${current.id}  ·  ${current.uid}`;
  $('products').innerHTML = products.map(p => `<button class="product-card ${p.id === selected ? 'selected' : ''}" data-product="${escapeHtml(p.id)}" aria-label="Select ${escapeHtml(p.name)}"><div class="product-top"><span class="product-icon">▣</span><span class="status ${p.tampered ? 'alert' : ''}">${p.tampered ? 'SEAL TRIPPED' : 'SEAL INTACT'}</span></div><strong class="product-name">${escapeHtml(p.name)}</strong><span class="product-id">${escapeHtml(p.id)} · ${escapeHtml(p.sku)}</span><div class="product-divider"></div><div class="product-bottom"><span>${escapeHtml(p.batch)}</span><strong>VIEW PACKAGE ↗</strong></div></button>`).join('');
  document.querySelectorAll('[data-product]').forEach(button => button.addEventListener('click', () => { selected = button.dataset.product; render(); }));
  const events = overview.events.filter(e => e.product_id === selected);
  $('events').innerHTML = events.length ? events.map(e => `<div class="event"><span class="event-dot ${e.kind === 'TAMPER_DETECTED' ? 'tamper' : ''}">${e.kind === 'TAMPER_DETECTED' ? '△' : e.kind === 'PROVISIONED' ? '◇' : '✓'}</span><div><strong>${escapeHtml(e.kind.replaceAll('_',' '))}</strong><p>${escapeHtml(e.detail)}</p><time>${stamp(e.timestamp)} · #${e.sequence} · ${escapeHtml(e.hash.slice(0,12))}…</time></div></div>`).join('') : '<p class="panel-intro">No events for this package.</p>';
}

async function refresh() {
  overview = await api('/api/overview');
  render();
}

function showResult(result) {
  const tone = result.accepted ? (result.code === 'TAMPER_DETECTED' ? 'warn' : 'ok') : 'bad';
  const icon = result.accepted ? (tone === 'warn' ? '△' : '✓') : '×';
  const heading = result.code.replaceAll('_', ' ');
  $('result').innerHTML = `<div class="result-message ${tone}"><span>${icon}</span><div><strong>${escapeHtml(heading)}</strong><p>${escapeHtml(result.message)}</p></div></div>`;
}

document.querySelectorAll('[data-scenario]').forEach(button => button.addEventListener('click', async () => {
  const buttons = document.querySelectorAll('[data-scenario]');
  buttons.forEach(b => b.disabled = true);
  try {
    const result = await api('/api/demo/scan', {method:'POST', body:JSON.stringify({product_id:selected, scenario:button.dataset.scenario})});
    showResult(result);
    await refresh();
  } catch (error) {
    showResult({accepted:false, code:'REQUEST_FAILED', message:error.message});
  } finally {
    buttons.forEach(b => b.disabled = false);
  }
}));

$('reset').addEventListener('click', async () => {
  if (!confirm('Reset all local demo scans and create fresh virtual tag keys?')) return;
  try {
    await api('/api/demo/reset', {method:'POST'});
    $('result').innerHTML = '<div class="result-placeholder">Demo reset. Select a scenario to see the verification result.</div>';
    selected = 'VP-1001';
    await refresh();
  } catch (error) { showResult({accepted:false, code:'RESET_FAILED', message:error.message}); }
});

refresh().catch(error => showResult({accepted:false, code:'LOAD_FAILED', message:error.message}));
