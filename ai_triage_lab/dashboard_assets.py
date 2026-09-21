"""Trusted static assets embedded in the portable dashboard with CSP hashes."""

CSS = """
:root{color-scheme:light;--ink:#172b36;--muted:#4b5b64;--line:#cbd4d9;--paper:#fff;--ground:#f2f5f6;--accent:#075969;--danger:#982a29}
*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:1rem}body{margin:0;background:var(--ground);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
::selection{background:#c0e8ea;color:#102f37}a{color:var(--accent);text-underline-offset:.2em}a:hover{text-decoration-thickness:2px}
:focus-visible{outline:3px solid #087b91;outline-offset:4px}button,select{font:inherit;color:inherit}button{cursor:pointer;background:var(--paper);border:1px solid var(--line);padding:.55rem 1rem;border-radius:4px}button:hover{background:#e1ecee;border-color:var(--accent)}
header{padding:1.4rem clamp(1rem,4vw,4rem);background:var(--paper);border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;gap:1rem}header h1{font-size:1.35rem;margin:0;letter-spacing:-.025em}header p{margin:0;color:var(--muted);font-size:.9rem}header a{font-weight:600}
main{max-width:1700px;margin:auto;padding:2rem clamp(1rem,4vw,4rem) 3rem}h2{font-size:1.4rem;line-height:1.25;letter-spacing:-.025em;margin:0 0 .65rem}p{max-width:85ch;margin:.5rem 0 1rem;color:var(--muted)}.intro h2{font-size:clamp(1.65rem,3vw,2.3rem);max-width:32ch;text-wrap:balance}.notice{max-width:none;background:#e3eef0;padding:1rem 1.2rem;color:#23434a;border-radius:4px}.notice strong{display:block;margin-bottom:.25rem}
section{margin-bottom:2.8rem}form{margin:1.6rem 0 2.8rem;background:var(--paper);border:1px solid var(--line);padding:1rem 1.2rem;border-radius:5px}.filters{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:1rem}label{display:flex;flex-direction:column;gap:.35rem;font-size:.85rem;font-weight:600}select{width:100%;min-height:42px;border:1px solid #81949e;background:var(--paper);border-radius:3px;padding:.5rem;max-width:100%}.filter-actions{display:flex;align-items:center;gap:1rem;margin-top:1rem}.filter-actions p{margin:0;font-size:.9rem}
.table-wrap{overflow-x:auto;border:1px solid var(--line);background:var(--paper);border-radius:4px;scrollbar-color:#859ca7 #edf1f3}table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums;font-size:.85rem}caption{text-align:left;padding:.8rem 1rem;font-weight:600;background:#e8eef1}th,td{padding:.9rem 1rem;border-bottom:1px solid #dde4e7;text-align:left;vertical-align:top;min-width:130px}thead th{font-weight:600;color:#354c59;background:#f6f8f9;font-size:.8rem}tbody th{font-weight:600;max-width:250px;overflow-wrap:anywhere}tbody tr:last-child>*{border-bottom:0}tbody tr:hover{background:#f0f7f8}small{display:block;color:var(--muted);font-size:.78rem;font-weight:400;margin-top:.3rem;overflow-wrap:anywhere}td{overflow-wrap:anywhere}
.section-heading{display:flex;justify-content:space-between;align-items:center;gap:1rem;margin-bottom:.5rem}.section-heading h2{margin:0}.section-heading label{min-width:170px}.trial{border-top:1px solid var(--line);background:var(--paper)}.trial:last-child{border-bottom:1px solid var(--line)}summary{cursor:pointer;padding:.9rem 1rem}summary:hover{background:#eef4f5}.trial>summary{display:grid;grid-template-columns:minmax(240px,1fr) minmax(130px,.3fr) minmax(100px,.2fr);gap:1rem;align-items:center}.trial>summary>span:first-child:before{content:"+";font-weight:600;margin-right:.6rem;color:var(--accent)}.trial[open]>summary>span:first-child:before{content:"−"}.trial>summary small{margin-left:1.2rem}.danger{color:var(--danger);font-weight:600}.neutral{color:var(--muted)}.trial-body{padding:.4rem 1.2rem 1.2rem;border-top:1px solid var(--line)}.trial-body details{margin-top:.65rem;border:1px solid var(--line);border-radius:3px}.trial-body summary{font-weight:600;font-size:.9rem}.trial-body dl{display:grid;grid-template-columns:180px minmax(0,1fr);gap:.5rem 1rem;font-size:.9rem}dt{color:var(--muted)}dd{margin:0;overflow-wrap:anywhere}pre{margin:0;padding:1rem;background:#f4f7f8;max-height:32rem;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.6 Consolas,"Liberation Mono",monospace;tab-size:2}footer{border-top:1px solid var(--line);padding-top:1rem;font-size:.85rem}footer>details{border:1px solid var(--line)}.skip{position:absolute;top:-100px;left:1rem;background:white;padding:.8rem;z-index:5}.skip:focus{top:1rem}[hidden]{display:none!important}
@media(max-width:1000px){.filters{grid-template-columns:repeat(2,minmax(0,1fr))}.filters>label:last-child{grid-column:1/-1}}
@media(max-width:600px){header{align-items:flex-start}header a{font-size:.8rem;max-width:11ch}main{padding-top:1.5rem}.filters{grid-template-columns:1fr}.filters>label:last-child{grid-column:auto}.trial>summary{grid-template-columns:1fr;gap:.3rem}.trial>summary>span:not(:first-child){margin-left:1.2rem;font-size:.85rem}.trial-body dl{grid-template-columns:1fr;gap:.25rem}dd{margin-bottom:.6rem}.section-heading{align-items:flex-start;flex-direction:column}.section-heading label{width:100%}.filter-actions{align-items:flex-start;flex-direction:column}}
@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}}
@media print{body{background:white}header a,form,#sort-label{display:none}main{padding:1rem}.table-wrap{overflow:visible}table{font-size:8pt}th,td{min-width:0;padding:.3rem}.trial{break-inside:avoid}pre{max-height:none}}
"""

JS = """
(() => {
  'use strict';
  const form = document.getElementById('filters');
  const filters = Array.from(document.querySelectorAll('[data-filter]'));
  const trials = Array.from(document.querySelectorAll('.trial'));
  const matrix = Array.from(document.querySelectorAll('.scenario-row'));
  const groups = Array.from(document.querySelectorAll('.group-row'));
  const match = (node, overview) => filters.every(select =>
    !select.value || (overview && select.dataset.filter === 'scenario') ||
    node.dataset[select.dataset.filter] === select.value);
  function update() {
    trials.forEach(node => { node.hidden = !match(node, false); });
    matrix.forEach(node => { node.hidden = !match(node, false); });
    groups.forEach(node => { node.hidden = !match(node, true); });
    const shown = trials.filter(node => !node.hidden);
    const incomplete = shown.filter(node => node.dataset.status !== 'completed').length;
    document.getElementById('selection').textContent =
      shown.length + ' of ' + trials.length + ' trials shown · ' + incomplete + ' incomplete';
    document.getElementById('empty-matrix').hidden = matrix.some(node => !node.hidden);
    document.getElementById('empty-trials').hidden = shown.length !== 0;
  }
  filters.forEach(select => select.addEventListener('change', update));
  form.addEventListener('submit', event => event.preventDefault());
  form.addEventListener('reset', () => { setTimeout(update, 0); });
  const sort = document.getElementById('sort');
  sort.addEventListener('change', () => {
    const field = sort.value;
    const ordered = trials.slice().sort((a, b) =>
      a.dataset[field].localeCompare(b.dataset[field]) || Number(a.dataset.order) - Number(b.dataset.order));
    ordered.forEach(node => document.getElementById('trials').appendChild(node));
  });
  form.hidden = false;
  document.getElementById('sort-label').hidden = false;
  update();
})();
"""
