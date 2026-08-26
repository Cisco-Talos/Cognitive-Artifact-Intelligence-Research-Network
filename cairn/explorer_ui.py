# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CAIRN Explorer</title>
<link rel="icon" type="image/png" href="/favicon.png">
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg:        #0d0f14;
    --surface:   #13161e;
    --surface2:  #1a1e28;
    --border:    #252a38;
    --text:      #c8ccd8;
    --text-dim:  #5a6070;
    --accent:    #4f8ef7;
    --accent2:   #7c5aef;
    --danger:    #ef5a5a;
    --success:   #4fef8e;
    --warn:      #efb84f;

    --c-sample:   #3D93CE;
    --c-rule:     #9F7BB8;
    --c-filter:   #F5AD4E;
    --c-provider: #F28F52;
    --c-imphash:  #75B9E7;
    --c-domain:   #698999;
    --c-cert:     #B9A0CB;
    --c-submitter:#93A9B5;
  }

  html, body { height: 100%; background: var(--bg); color: var(--text); font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 13px; }

  #layout { display: flex; height: 100vh; overflow: hidden; }

  /* ── Sidebar ── */
  #sidebar {
    width: 340px; min-width: 280px; max-width: 420px;
    background: var(--surface);
    border-right: 1px solid var(--border);
    display: flex; flex-direction: column;
    overflow: hidden;
    transition: width .25s cubic-bezier(.4,0,.2,1),
                min-width .25s cubic-bezier(.4,0,.2,1);
  }
  #layout.sidebar-hidden #sidebar { width: 0; min-width: 0; }

  /* ── "HIDE PANEL" button inside the sidebar controls ── */
  #btn-sidebar-hide {
    width: 100%; padding: 5px 8px; border-radius: 4px; cursor: pointer;
    font-family: inherit; font-size: 11px; letter-spacing: .06em;
    border: 1px solid var(--border); background: var(--surface2); color: var(--text-dim);
    transition: border-color .15s, color .15s;
    text-align: center;
  }
  #btn-sidebar-hide:hover { border-color: var(--accent); color: var(--text); }

  /* ── Re-expand tab — only shown when sidebar is collapsed ── */
  #btn-collapse {
    display: none;
    position: absolute; left: 0; top: 50%; transform: translateY(-50%);
    z-index: 15;
    padding: 14px 6px;
    border: 1px solid var(--accent); border-left: none;
    border-radius: 0 5px 5px 0;
    background: rgba(19,22,30,.92); backdrop-filter: blur(4px);
    color: var(--accent); cursor: pointer;
    font-size: 11px; line-height: 1;
    transition: background .15s;
    user-select: none;
  }
  #btn-collapse:hover { background: rgba(79,142,247,.15); }
  #layout.sidebar-hidden #btn-collapse { display: block; }

  #sidebar-header {
    padding: 16px;
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
    display: flex; flex-direction: column; align-items: center; gap: 10px;
    background: linear-gradient(180deg, rgba(34, 50, 67, .58), rgba(19, 22, 30, .18));
    box-shadow: inset 0 -1px rgba(111, 153, 184, .12);
  }

  #sidebar-header img {
    width: 84%; max-width: 280px; height: auto; object-fit: contain; display: block;
    opacity: .9;
    filter: drop-shadow(0 1px 2px rgba(0, 0, 0, .9)) drop-shadow(0 0 6px rgba(135, 190, 235, .15));
  }

  #stats { display: flex; gap: 16px; margin-top: 0; justify-content: center; }
  .stat { min-width: 42px; text-align: center; }
  .stat .n { font-size: 18px; font-weight: 400; color: #e0e5f0; font-variant-numeric: tabular-nums; }
  .stat .l { margin-top: 2px; font-size: 9px; color: #6e7688; letter-spacing: .1em; }

  /* ── Controls ── */
  #controls {
    padding: 10px 16px;
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
    display: flex; flex-direction: column; gap: 7px;
  }

  .search-field { position: relative; }
  .search-icon {
    position: absolute; left: 11px; top: 50%; width: 10px; height: 10px;
    border: 1.5px solid var(--text-dim); border-radius: 50%; transform: translateY(-65%);
    pointer-events: none;
  }
  .search-icon::after { content: ''; position: absolute; width: 5px; height: 1.5px; right: -4px; bottom: -2px; background: var(--text-dim); transform: rotate(45deg); transform-origin: left center; }
  #search {
    background: var(--surface2); border: 1px solid var(--border);
    color: var(--text); padding: 6px 10px 6px 30px; border-radius: 4px;
    width: 100%; outline: none; font-family: inherit; font-size: 12px;
  }
  #search:focus { border-color: var(--accent); box-shadow: 0 0 0 2px rgba(79,142,247,.18); }

  .toggle-row { display: flex; flex-wrap: wrap; gap: 5px; }

  .tog {
    padding: 3px 9px; border-radius: 3px; cursor: pointer;
    font-size: 10px; letter-spacing: .06em; border: 1px solid transparent;
    transition: opacity .15s, transform .15s, box-shadow .15s;
  }
  .tog.active { opacity: 1; box-shadow: inset 0 -2px rgba(0,0,0,.48), 0 0 0 1px rgba(255,255,255,.16); }
  .tog.inactive { opacity: .35; }
  .tog:hover { transform: translateY(-1px); }
  .tog-sample   { background: var(--c-sample);   color: #000; }
  .tog-rule     { background: var(--c-rule);     color: #000; }
  .tog-filter   { background: var(--c-filter);   color: #000; }
  .tog-provider { background: var(--c-provider); color: #000; }
  .tog-imphash  { background: var(--c-imphash);  color: #000; }
  .tog-domain   { background: var(--c-domain);   color: #000; }
  .tog-cert      { background: var(--c-cert);      color: #000; }
  .tog-submitter { background: var(--c-submitter); color: #000; }

  .btn-row { display: flex; gap: 6px; }
  .btn {
    flex: 1; padding: 5px 8px; border-radius: 4px; cursor: pointer;
    font-family: inherit; font-size: 11px; letter-spacing: .06em;
    border: 1px solid var(--border); background: var(--surface2); color: var(--text);
    transition: border-color .15s, background .15s;
  }
  .btn:hover { border-color: var(--accent); background: var(--surface); }
  .btn.active { border-color: var(--accent); color: var(--accent); }
  .btn.primary { background: var(--accent); color: #000; border-color: var(--accent); }
  .btn.primary:hover { background: #6aa3ff; }
  #btn-clear-filters {
    background: #202631; border-color: #333c4d; color: #aeb7c8;
  }
  #btn-clear-filters:hover { background: #272f3d; border-color: #47546a; color: var(--text); }

  /* ── Editor sections (rules / filters / providers) ── */
  .editor-section {
    border-bottom: 1px solid #30384a;
    flex-shrink: 0;
  }
  .editor-section-header {
    padding: 9px 16px;
    font-size: 10px; letter-spacing: .12em; color: var(--text-dim);
    cursor: pointer; user-select: none;
    display: flex; justify-content: space-between; align-items: center;
  }
  .editor-section-header:hover { color: var(--text); }
  .chevron { font-size: 10px; transition: transform .2s; }
  .chevron.open { transform: rotate(90deg); }
  .editor-section-body {
    overflow-y: auto; max-height: 200px;
    padding: 4px 0;
  }

  .rule-item, .filter-item, .provider-item {
    padding: 4px 16px; cursor: pointer; font-size: 11px;
    display: flex; align-items: center; gap: 7px;
    white-space: nowrap; overflow: hidden;
    border-left: 2px solid transparent;
  }
  .rule-item:hover, .filter-item:hover, .provider-item:hover { background: var(--surface2); }
  .rule-item.rule-active  { background: var(--surface2); border-left-color: var(--accent); }
  .provider-item.prov-active { background: var(--surface2); border-left-color: var(--warn); }
  .rule-item span.rname, .filter-item span.fname, .provider-item span.pname {
    overflow: hidden; text-overflow: ellipsis; color: var(--text); flex: 1; min-width: 0;
  }
  .enabled-dot { width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; }
  .enabled-dot.on  { background: var(--success); }
  .enabled-dot.off { background: var(--text-dim); }

  /* Hit count badge */
  .hit-badge {
    flex-shrink: 0; font-size: 10px; padding: 1px 6px;
    border-radius: 8px; background: var(--surface2); color: var(--text-dim);
    border: 1px solid var(--border);
  }
  .hit-badge.zero { opacity: .3; }
  .hit-badge.t3   { border-color: var(--accent); color: var(--accent); }
  .hit-badge.prov { border-color: var(--warn); color: var(--warn); }

  /* ── Detail panel ── */
  #detail {
    flex: 1; overflow-y: auto; padding: 14px 16px;
    min-height: 0;
  }

  .detail-placeholder {
    color: var(--text-dim); font-size: 11px; margin-top: 20px; line-height: 1.7;
  }

  .detail-section { margin-bottom: 14px; }
  .detail-section h3 {
    font-size: 10px; letter-spacing: .12em; color: var(--text-dim);
    text-transform: uppercase; margin-bottom: 6px;
    border-bottom: 1px solid var(--border); padding-bottom: 4px;
  }
  details.detail-section summary {
    font-size: 10px; letter-spacing: .12em; color: var(--text-dim);
    text-transform: uppercase; margin-bottom: 6px; cursor: pointer;
    border-bottom: 1px solid var(--border); padding-bottom: 4px; list-style: none;
  }
  details.detail-section summary::before { content: '▸ '; }
  details.detail-section[open] summary::before { content: '▾ '; }

  .kv-grid { display: grid; grid-template-columns: max-content 1fr; gap: 2px 12px; }
  .kv-k { color: var(--text-dim); font-size: 11px; }
  .kv-v { color: var(--text); font-size: 11px; word-break: break-all; }

  .tag {
    display: inline-block; margin: 2px 3px 2px 0;
    padding: 1px 7px; border-radius: 3px; font-size: 10px;
    background: var(--surface2); color: var(--text-dim); border: 1px solid var(--border);
  }

  .pill {
    display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 10px; margin: 1px;
  }
  .pill-t1 { background: #2a2f3e; color: #8a9ab8; border: 1px solid #3a4060; }
  .pill-t2 { background: #2d2040; color: #9a7aef; border: 1px solid #4a3070; }
  .pill-t3 { background: #1a2040; color: var(--accent); border: 1px solid #2a4080; }

  .family-badge {
    display: inline-block; padding: 2px 10px; border-radius: 3px;
    font-size: 12px; letter-spacing: .08em; font-weight: bold;
    background: var(--accent); color: #000;
  }

  .url-list { font-size: 10px; line-height: 1.8; word-break: break-all; color: var(--text-dim); }

  .det-count { font-size: 22px; }
  .det-high { color: var(--danger); }
  .det-med  { color: var(--warn); }
  .det-low  { color: var(--success); }

  .raw-json-pre {
    background: var(--bg); border: 1px solid var(--border); border-radius: 4px;
    padding: 8px; font-size: 10px; max-height: 240px; overflow-y: auto;
    white-space: pre; word-break: break-all; margin-top: 6px;
  }

  /* ── Graph canvas ── */
  #graph-wrap {
    flex: 1; position: relative; overflow: hidden;
    background: radial-gradient(ellipse at 60% 40%, #111420 0%, #0d0f14 70%);
  }

  #graph-canvas { width: 100%; height: 100%; display: block; }
  #graph-3d { position: absolute; inset: 0; display: none; }
  #graph-3d canvas { display: block; }

  /* ── Family filter pills (graph overlay top-left) ── */
  #family-pills {
    position: absolute; top: 10px; left: 12px; z-index: 10;
    display: flex; flex-wrap: wrap; gap: 4px; max-width: 780px;
    pointer-events: none;
  }
  .fpill {
    padding: 2px 8px; border-radius: 10px; cursor: pointer; font-size: 10px;
    border: 1px solid; backdrop-filter: blur(4px);
    background: rgba(13,15,20,.85); transition: opacity .15s, background .15s;
    letter-spacing: .05em; pointer-events: all; white-space: nowrap;
  }
  .fpill.active { opacity: 1; }
  .fpill.inactive { opacity: .4; }
  .fpill.fpill-all { border-color: var(--text-dim); color: var(--text-dim); }
  .fpill.fpill-all.active { border-color: var(--text); color: var(--text); }

  #graph-legend {
    position: absolute; bottom: 12px; left: 12px; z-index: 10;
    max-width: 232px; padding: 6px 8px; border: 1px solid var(--border); border-radius: 4px;
    background: rgba(13,15,20,.82); color: var(--text-dim); font-size: 10px;
    backdrop-filter: blur(4px);
  }
  #graph-legend summary { cursor: pointer; color: var(--text); letter-spacing: .06em; }
  #graph-legend[open] summary { margin-bottom: 6px; }
  .legend-grid { display: grid; grid-template-columns: repeat(2, max-content); gap: 4px 10px; }
  .legend-item { display: flex; align-items: center; gap: 5px; }
  .legend-dot { width: 7px; height: 7px; border-radius: 50%; flex: 0 0 auto; }

  /* ── Toolbar ── */
  #toolbar {
    position: absolute; top: 12px; right: 14px;
    display: flex; gap: 8px; align-items: center; z-index: 10;
    transition: right .25s cubic-bezier(.4,0,.2,1);
  }
  #toolbar.panel-open { right: 494px; }

  .tb-btn {
    padding: 5px 12px; border-radius: 4px; cursor: pointer;
    font-family: inherit; font-size: 11px; letter-spacing: .06em;
    border: 1px solid var(--border); background: rgba(13,15,20,.85);
    color: var(--text); backdrop-filter: blur(4px);
    transition: border-color .15s;
  }
  .tb-btn:hover { border-color: var(--accent); background: rgba(26,30,40,.92); }
  .tb-btn.active { border-color: var(--accent); color: var(--accent); }

  /* ── UMAP cluster controls bar (below canvas, not overlaid) ── */
  #umap-controls {
    display: none;
    position: absolute; bottom: 0; left: 0; right: 0; z-index: 11;
    padding: 6px 12px; gap: 6px; align-items: center;
    background: rgba(13,15,20,.72); backdrop-filter: blur(4px);
    border-top: 1px solid var(--border);
  }
  #umap-controls.umap-visible { display: flex; }
  #umap-cluster-input {
    background: rgba(13,15,20,.88); border: 1px solid var(--border);
    color: var(--text); padding: 5px 10px; border-radius: 4px;
    font-family: inherit; font-size: 12px; width: 120px; outline: none;
    backdrop-filter: blur(4px);
  }
  #umap-cluster-input:focus { border-color: var(--accent); }
  #umap-cluster-input::placeholder { color: var(--text-dim); }
  #umap-labels-btn {
    padding: 5px 10px; border-radius: 4px; cursor: pointer;
    font-family: inherit; font-size: 11px; letter-spacing: .06em;
    border: 1px solid var(--border); background: rgba(13,15,20,.88);
    color: var(--text); backdrop-filter: blur(4px);
    transition: border-color .15s;
    white-space: nowrap;
  }
  #umap-labels-btn:hover { border-color: var(--accent); }
  #umap-labels-btn.active { border-color: var(--accent); color: var(--accent); }

  /* ── Loading overlay ── */
  #loading {
    position: absolute; inset: 0; display: flex;
    align-items: center; justify-content: center;
    background: var(--bg); z-index: 20; flex-direction: column; gap: 12px;
  }
  #loading .spinner {
    width: 36px; height: 36px; border: 3px solid var(--border);
    border-top-color: var(--accent); border-radius: 50%;
    animation: spin .8s linear infinite;
  }
  #loading p { color: var(--text-dim); font-size: 12px; }
  .state-message { padding: 12px 16px; color: var(--text-dim); font-size: 11px; line-height: 1.6; }
  .state-message strong { color: var(--text); font-weight: normal; }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* ── Editor modal ── */
  #editor-modal {
    display: none; position: fixed; inset: 0; z-index: 100;
    background: rgba(0,0,0,.72); align-items: center; justify-content: center;
  }
  #editor-modal.open { display: flex; }
  .modal-box {
    background: var(--surface); border: 1px solid var(--border); border-radius: 6px;
    width: 740px; max-width: 96vw; max-height: 82vh;
    display: flex; flex-direction: column; padding: 20px; gap: 12px;
  }
  #modal-title { font-size: 13px; color: var(--accent); letter-spacing: .06em; }
  #modal-subtitle { font-size: 10px; color: var(--text-dim); margin-top: -6px; }
  #modal-textarea {
    flex: 1; background: var(--bg); color: var(--text); font-family: inherit;
    font-size: 11px; border: 1px solid var(--border); border-radius: 4px;
    padding: 10px; resize: none; min-height: 320px; outline: none; line-height: 1.6;
    tab-size: 2;
  }
  #modal-textarea:focus { border-color: var(--border); }
  .modal-footer { display: flex; gap: 8px; justify-content: flex-end; align-items: center; }
  #modal-status { font-size: 11px; color: var(--text-dim); flex: 1; }

  /* ── Toast ── */
  #toast {
    position: fixed; bottom: 20px; right: 20px; z-index: 200;
    padding: 8px 16px; border-radius: 4px; font-size: 12px;
    background: var(--surface2); border: 1px solid var(--border); color: var(--text);
    opacity: 0; pointer-events: none;
    transition: opacity .2s;
  }
  #toast.visible { opacity: 1; }
  #toast.error { border-color: var(--danger); color: var(--danger); }

  button:focus-visible, input:focus-visible, textarea:focus-visible,
  [role="button"]:focus-visible, .fpill:focus-visible {
    outline: 2px solid var(--accent); outline-offset: 2px;
  }
  #stats, .hit-badge, .det-count, #node-count, .kv-v { font-variant-numeric: tabular-nums; }
  @media (prefers-reduced-motion: reduce) {
    *, *::before, *::after { transition-duration: .01ms !important; animation-duration: .01ms !important; }
  }

  /* scrollbar */
  ::-webkit-scrollbar { width: 5px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }

  /* ── Family report slide-in panel ── */
  #family-report-panel {
    position: absolute; top: 0; right: 0; bottom: 0;
    width: 480px; max-width: 50vw;
    background: rgba(19,22,30,.97);
    border-left: 1px solid var(--border);
    backdrop-filter: blur(8px);
    display: flex; flex-direction: column;
    transform: translateX(100%);
    transition: transform .25s cubic-bezier(.4,0,.2,1);
    z-index: 15; overflow: hidden;
  }
  #family-report-panel.open { transform: translateX(0); }

  #family-report-header {
    padding: 10px 16px; border-bottom: 1px solid var(--border);
    display: flex; align-items: center; justify-content: space-between;
    flex-shrink: 0;
  }
  #family-report-title { font-size: 13px; color: var(--accent); letter-spacing: .1em; }
  #family-report-close {
    background: none; border: none; color: var(--text-dim);
    cursor: pointer; font-size: 14px; padding: 2px 6px; line-height: 1;
  }
  #family-report-close:hover { color: var(--text); }

  #family-report-body {
    flex: 1; overflow-y: auto; padding: 16px 20px;
    font-size: 12px; line-height: 1.7; color: var(--text);
  }
  #family-report-body h1 { font-size: 15px; color: var(--accent); margin: 0 0 10px; }
  #family-report-body h2 { font-size: 13px; color: var(--text); margin: 16px 0 6px; border-bottom: 1px solid var(--border); padding-bottom: 3px; }
  #family-report-body h3 { font-size: 12px; color: var(--text-dim); margin: 12px 0 4px; }
  #family-report-body p  { margin: 0 0 8px; }
  #family-report-body code { background: var(--surface2); padding: 1px 5px; border-radius: 3px; font-family: inherit; font-size: 11px; }
  #family-report-body pre { background: var(--bg); border: 1px solid var(--border); border-radius: 4px; padding: 10px; overflow-x: auto; margin: 8px 0; }
  #family-report-body pre code { background: none; padding: 0; font-size: 10px; }
  #family-report-body table { border-collapse: collapse; width: 100%; margin: 8px 0; font-size: 11px; }
  #family-report-body th, #family-report-body td { border: 1px solid var(--border); padding: 4px 8px; text-align: left; }
  #family-report-body th { background: var(--surface2); color: var(--text-dim); }
  #family-report-body a  { color: var(--accent); text-decoration: none; }
  #family-report-body a:hover { text-decoration: underline; }
  #family-report-body hr { border: none; border-top: 1px solid var(--border); margin: 12px 0; }
  #family-report-body ul, #family-report-body ol { padding-left: 18px; margin: 0 0 8px; }
  #family-report-body li { margin: 2px 0; }
  #family-report-body blockquote { border-left: 3px solid var(--border); padding-left: 10px; color: var(--text-dim); margin: 8px 0; }
</style>
</head>
<body>
<div id="layout">

  <!-- ── Sidebar ── -->
  <div id="sidebar">
    <div id="sidebar-header">
      <img src="/logo.png" alt="CAIRN" onerror="this.style.display='none'">
      <div id="stats">
        <div class="stat"><div class="n" id="stat-samples">—</div><div class="l">SAMPLES</div></div>
        <div class="stat"><div class="n" id="stat-families">—</div><div class="l">FAMILIES</div></div>
        <div class="stat"><div class="n" id="stat-rules">—</div><div class="l">RULES</div></div>
        <div class="stat"><div class="n" id="stat-edges">—</div><div class="l">EDGES</div></div>
      </div>
    </div>

    <div id="controls">
      <div class="search-field">
        <span class="search-icon" aria-hidden="true"></span>
        <input id="search" type="text" placeholder="Search SHA256, family, rule, domain…" autocomplete="off">
      </div>
      <div class="toggle-row" id="type-toggles">
        <div class="tog tog-sample active"   data-type="sample" role="button" tabindex="0" aria-pressed="true">SAMPLE</div>
        <div class="tog tog-rule active"     data-type="yara_rule" role="button" tabindex="0" aria-pressed="true">RULE</div>
        <div class="tog tog-filter active"   data-type="acquisition_filter" role="button" tabindex="0" aria-pressed="true">FILTER</div>
        <div class="tog tog-provider active" data-type="provider" role="button" tabindex="0" aria-pressed="true">PROVIDER</div>
        <div class="tog tog-imphash active"  data-type="imphash" role="button" tabindex="0" aria-pressed="true">IMPHASH</div>
        <div class="tog tog-domain active"   data-type="domain" role="button" tabindex="0" aria-pressed="true">DOMAIN</div>
        <div class="tog tog-cert active"      data-type="cert" role="button" tabindex="0" aria-pressed="true">CERT</div>
        <div class="tog tog-submitter active" data-type="submitter" role="button" tabindex="0" aria-pressed="true">SUBMITTER</div>
      </div>
      <div style="display:flex;align-items:center;gap:8px;margin-top:4px">
        <label for="submitter-max" style="font-size:10px;color:var(--text-dim);white-space:nowrap;letter-spacing:.06em">SUBMITTER MAX</label>
        <input id="submitter-max" type="number" min="1" placeholder="∞"
          style="width:64px;background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:3px 6px;border-radius:3px;font-family:inherit;font-size:11px;outline:none">
      </div>
      <!-- Row 1: data filters + hull visualization -->
      <div class="btn-row">
        <button class="btn" id="btn-t3">T3 ONLY</button>
        <button class="btn" id="btn-substrate">SUBSTRATE</button>
        <button class="btn active" id="btn-hull">HULL</button>
      </div>
      <!-- Row 2: graph / navigation controls -->
      <div class="btn-row">
        <button class="btn" id="btn-reset">Reset</button>
        <button class="btn" id="btn-3d">3D</button>
        <button class="btn" id="btn-reheat">Reheat</button>
        <button class="btn" id="btn-umap">UMAP</button>
        <button class="btn" id="btn-table">TABLE</button>
      </div>
      <button class="btn" id="btn-clear-filters">CLEAR FILTERS</button>
      <button id="btn-sidebar-hide">◀ HIDE PANEL</button>
    </div>

    <!-- Rules section -->
    <!-- Filters editor section -->
    <div class="editor-section" id="filters-section">
      <div class="editor-section-header" id="filters-toggle">
        ACQ FILTERS <span class="chevron" id="filters-chevron">▸</span>
      </div>
      <div class="editor-section-body" id="filters-body" style="display:none">
        <div id="filters-list"></div>
      </div>
    </div>

    <div class="editor-section" id="rules-section">
      <div class="editor-section-header" id="rules-toggle">
        YARA RULES <span class="chevron" id="rules-chevron">▸</span>
      </div>
      <div class="editor-section-body" id="rules-body" style="display:none">
        <div id="rules-list"></div>
      </div>
    </div>

    <!-- Providers section -->
    <div class="editor-section" id="providers-section">
      <div class="editor-section-header" id="providers-toggle">
        PROVIDERS <span class="chevron" id="providers-chevron">▸</span>
      </div>
      <div class="editor-section-body" id="providers-body" style="display:none">
        <div id="providers-list"></div>
      </div>
    </div>

    <div id="detail">
      <div class="detail-placeholder">
        Click any node to inspect it.<br><br>
        Use the type toggles to show or hide node categories.<br><br>
        Click a family pill on the graph, a YARA rule, or a provider to isolate that subgraph.<br><br>
        <span style="color:var(--accent)">T3 ONLY</span> hides samples with no T3 rule match.
      </div>
    </div>
  </div>

  <!-- ── Graph area ── -->
  <div id="graph-wrap">
    <button id="btn-collapse" title="Toggle sidebar">◀</button>
    <div id="loading"><div class="spinner"></div><p>Loading graph…</p></div>
    <div id="graph-canvas"></div>
    <canvas id="umap-canvas" style="display:none;position:absolute;top:0;left:0;width:100%;height:100%;"></canvas>
    <div id="umap-controls">
      <input id="umap-cluster-input" type="text" placeholder="cluster #…" autocomplete="off">
      <button id="umap-labels-btn">LABELS</button>
    </div>
    <div id="umap-tooltip" style="display:none;position:fixed;background:var(--surface);border:1px solid var(--border);padding:4px 8px;font:11px monospace;pointer-events:none;z-index:30;max-width:320px;word-break:break-all;"></div>
    <div id="graph-3d"></div>
    <div id="family-pills"></div>
    <details id="graph-legend" open>
      <summary>LEGEND</summary>
      <div class="legend-grid">
        <span class="legend-item"><i class="legend-dot" style="background:var(--c-sample)"></i>sample</span>
        <span class="legend-item"><i class="legend-dot" style="background:var(--c-rule)"></i>rule</span>
        <span class="legend-item"><i class="legend-dot" style="background:var(--c-filter)"></i>filter</span>
        <span class="legend-item"><i class="legend-dot" style="background:var(--c-provider)"></i>provider</span>
        <span class="legend-item"><i class="legend-dot" style="background:var(--c-imphash)"></i>imphash</span>
        <span class="legend-item"><i class="legend-dot" style="background:var(--c-domain)"></i>domain</span>
        <span class="legend-item"><i class="legend-dot" style="background:var(--c-cert)"></i>certificate</span>
        <span class="legend-item"><i class="legend-dot" style="background:var(--c-submitter)"></i>submitter</span>
      </div>
    </details>

    <!-- ── Family report panel ── -->
    <div id="family-report-panel">
      <div id="family-report-header">
        <span id="family-report-title"></span>
        <button id="family-report-close">✕</button>
      </div>
      <div id="family-report-body"></div>
    </div>

    <div id="toolbar">
      <button class="tb-btn" id="btn-focus" style="display:none">Focus 2-hop</button>
      <span id="node-count" style="color:var(--text-dim);font-size:11px;"></span>
    </div>

    <div id="corpus-wrap" style="display:none;position:absolute;inset:0;overflow-y:auto;background:var(--bg);padding:16px 20px;z-index:5"></div>
  </div>

</div>

<!-- ── Editor modal ── -->
<div id="editor-modal">
  <div class="modal-box">
    <div id="modal-title"></div>
    <div id="modal-subtitle"></div>
    <textarea id="modal-textarea" spellcheck="false"></textarea>
    <div class="modal-footer">
      <span id="modal-status"></span>
      <button class="btn" id="modal-cancel">Cancel</button>
      <button class="btn primary" id="modal-save">Save to disk</button>
    </div>
  </div>
</div>

<!-- ── Toast ── -->
<div id="toast"></div>

<script src="https://unpkg.com/force-graph@1.43.5/dist/force-graph.min.js"></script>
<script src="https://unpkg.com/3d-force-graph@1.73.4/dist/3d-force-graph.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/marked@9/marked.min.js"></script>
<script>
// ── Palette ──────────────────────────────────────────────────────────────────
const NODE_COLOR = {
  sample:             '#3D93CE',
  yara_rule:          '#9F7BB8',
  acquisition_filter: '#F5AD4E',
  provider:           '#F28F52',
  imphash:            '#75B9E7',
  domain:             '#698999',
  cert:               '#B9A0CB',
  submitter:          '#93A9B5',
};

// Derive a stable, visually-distinct family color from the family name.
// Uses the full 360° hue range (so every family gets a different color) but at
// reduced saturation (~55–65%) vs node-type colors (~80–85%).  The saturation
// difference means a family sample node at hue 334° looks like "dusty rose"
// while the domain node at the same hue looks vivid pink — distinguishable in
// context, and labels "(N det)" vs domain hostname reinforce the difference.
function familyColorFromName(name) {
  let h = 5381;
  for (let i = 0; i < name.length; i++) h = ((h << 5) + h + name.charCodeAt(i)) >>> 0;
  const hue = h % 360;
  const sat = 55 + ((h >>> 8)  % 12); // 55–66 %  (node types: ~80–85 %)
  const lit = 58 + ((h >>> 16) % 10); // 58–67 %
  return `hsl(${hue}, ${sat}%, ${lit}%)`;
}

const EDGE_COLOR = {
  matched_rule:       'rgba(159,123,184,.45)',
  acquired_by:        'rgba(245,173,78,.30)',
  references_provider:'rgba(242,143,82,.40)',
  shares_imphash:     'rgba(117,185,231,.35)',
  communicates_with:  'rgba(105,137,153,.35)',
  shares_cert:        'rgba(185,160,203,.35)',
  submitted_by:       'rgba(147,169,181,.35)',
};

// ── State ────────────────────────────────────────────────────────────────────
let gData = { nodes: [], links: [] };
let graph2d, graph3d;
let is3d = false;
let activeTypes = new Set(['sample','yara_rule','acquisition_filter','provider','imphash','domain','cert','submitter']);
let familyColorMap = {};
let highlightNodes = new Set();
let highlightLinks = new Set();
let hoverNodes = new Set();
let hoverLinks = new Set();
let selectedNode = null;
let activeFamilyFilter = null;   // last-clicked (for report panel)
let activeFamilyFilters = new Set(); // all active families
let activeRuleFilter = null;
let activeProviderFilter = null;
let t3OnlyMode = false;
let substrateMode = false;
let focusMode = false;
let focusNodeId = null;
let hullVisible = true;
let submitterMaxCount = Infinity;
let isUmapMode = false;
let umapData = null;          // [{sha256, x, y, cluster_id, family}]
let umapRenderedPts = [];     // [{cx, cy, sha256, family, cluster_id}] for hit testing
let umapSelectedSha = null;   // sha256 of currently selected dot
let isTableMode = false;
let samplesCache = null;
let rulesLoaded = false, filtersLoaded = false, providersLoaded = false;
let reportPanelOpen = false;
let modalPostUrl = '', modalScrollTarget = '';

// Computed during processGraph
let ruleHitSamples = {};   // "rule:T3-X" → Set of sample ids
let providerSamples = {};  // "provider:x" → Set of sample ids

// ── Boot ─────────────────────────────────────────────────────────────────────
fetch('/api/graph')
  .then(r => r.json())
  .then(raw => {
    document.getElementById('loading').style.display = 'none';
    processGraph(raw);
    initGraph2d();
    updateStats();
    renderFamilyPills();
  })
  .catch(e => {
    document.getElementById('loading').innerHTML = `<div class="state-message"><strong style="color:var(--danger)">Graph unavailable</strong><br>${esc(e)}</div>`;
  });

function processGraph(raw) {
  ruleHitSamples = {};
  providerSamples = {};

  const nodeMap = {};
  for (const n of raw.nodes) {
    if (n.type === 'sample' && n.family) {
      if (!familyColorMap[n.family]) {
        familyColorMap[n.family] = familyColorFromName(n.family);
      }
      n._color = familyColorMap[n.family];
    } else {
      n._color = NODE_COLOR[n.type] || '#3a3f52';
    }
    nodeMap[n.id] = n;
  }

  const links = raw.edges.map(e => {
    // Accumulate rule and provider hit maps
    if (e.type === 'matched_rule') {
      if (!ruleHitSamples[e.target]) ruleHitSamples[e.target] = new Set();
      ruleHitSamples[e.target].add(e.source);
    }
    if (e.type === 'references_provider') {
      if (!providerSamples[e.target]) providerSamples[e.target] = new Set();
      providerSamples[e.target].add(e.source);
    }
    return {
      source: e.source, target: e.target,
      type: e.type, weight: e.weight || 1,
      _color: EDGE_COLOR[e.type] || 'rgba(255,255,255,.15)',
    };
  });

  // Stamp _hasT3 on sample nodes
  const t3SampleIds = new Set();
  for (const [ruleId, sids] of Object.entries(ruleHitSamples)) {
    if (ruleId.startsWith('rule:T3-')) for (const s of sids) t3SampleIds.add(s);
  }
  for (const n of raw.nodes) {
    if (n.type === 'sample') n._hasT3 = t3SampleIds.has(n.id);
  }

  gData = { nodes: raw.nodes, links };
}

// ── 2D graph ─────────────────────────────────────────────────────────────────
function initGraph2d() {
  const filtered = filteredData();
  graph2d = ForceGraph()(document.getElementById('graph-canvas'))
    .graphData(filtered)
    .nodeId('id')
    .nodeLabel(n => `${n.label || n.id}${n.type === 'sample' ? ` (${n.detections ?? '?'} det)` : ''}`)
    .nodeColor(nodeColorFn)
    .nodeRelSize(4)
    .nodeVal(nodeValFn)
    .linkColor(linkColorFn)
    .linkWidth(linkWidthFn)
    .linkDirectionalParticles(linkParticlesFn)
    .linkDirectionalParticleWidth(2)
    .linkDirectionalParticleColor(l => l._color)
    .onNodeClick(onNodeClick)
    .onNodeHover(onNodeHover)
    .onBackgroundClick(() => clearHighlight())
    .backgroundColor('#0d0f14')
    .width(document.getElementById('graph-wrap').clientWidth)
    .height(document.getElementById('graph-wrap').clientHeight)
    .onRenderFramePost(drawFamilyHulls);
  updateNodeCount(filtered);
}

// ── 3D graph ─────────────────────────────────────────────────────────────────
function initGraph3d() {
  const filtered = filteredData();
  const el = document.getElementById('graph-3d');
  el.style.display = 'block';
  document.getElementById('graph-canvas').style.display = 'none';
  graph3d = ForceGraph3D()(el)
    .graphData(filtered)
    .nodeId('id')
    .nodeLabel(n => `${n.label || n.id}${n.type === 'sample' ? ` (${n.detections ?? '?'} det)` : ''}`)
    .nodeColor(nodeColorFn)
    .nodeRelSize(4)
    .nodeVal(nodeValFn)
    .linkColor(linkColorFn)
    .linkWidth(linkWidthFn)
    .linkDirectionalParticles(linkParticlesFn)
    .linkDirectionalParticleWidth(2)
    .linkDirectionalParticleColor(l => l._color)
    .onNodeClick(onNodeClick)
    .onNodeHover(onNodeHover)
    .onBackgroundClick(() => clearHighlight())
    .backgroundColor('#0d0f14')
    .width(el.clientWidth)
    .height(el.clientHeight);
  updateNodeCount(filtered);
}

// ── Node / link accessor fns ──────────────────────────────────────────────────
function nodeColorFn(n) {
  if (highlightNodes.size && !highlightNodes.has(n.id)) return 'rgba(80,85,110,.4)';
  if (hoverNodes.has(n.id)) return '#ffffff';
  return n._color;
}
function nodeValFn(n) {
  const emphasis = hoverNodes.has(n.id) ? 1.28 : 1;
  if (n.type === 'sample') return Math.max(1, Math.log2((n.detections || 1) + 1)) * emphasis;
  if (n.type === 'yara_rule') return 3 * emphasis;
  if (n.type === 'submitter') return Math.max(1, Math.log2((n.corpus_sample_count || 1) + 1)) * emphasis;
  return 2 * emphasis;
}
function linkColorFn(l) {
  if (highlightLinks.size && !highlightLinks.has(l)) return 'rgba(255,255,255,.04)';
  if (hoverLinks.has(l)) return 'rgba(255,255,255,.82)';
  return l._color;
}
function linkWidthFn(l) { return highlightLinks.has(l) ? 2 : hoverLinks.has(l) ? 1.35 : 0.5; }
function linkParticlesFn(l) { return highlightLinks.has(l) ? 4 : hoverLinks.has(l) ? 2 : 0; }

function refreshGraphAccessors() {
  const g = currentGraph();
  if (!g) return;
  g.nodeColor(nodeColorFn).nodeVal(nodeValFn).linkColor(linkColorFn)
   .linkWidth(linkWidthFn).linkDirectionalParticles(linkParticlesFn);
}

// ── Family hull overlay ───────────────────────────────────────────────────────
function convexHull(pts) {
  if (pts.length < 3) return pts.slice();
  let start = 0;
  for (let i = 1; i < pts.length; i++)
    if (pts[i].x < pts[start].x) start = i;
  const hull = [];
  let cur = start;
  do {
    hull.push(pts[cur]);
    let next = (cur + 1) % pts.length;
    for (let i = 0; i < pts.length; i++) {
      const cross = (pts[next].x - pts[cur].x) * (pts[i].y - pts[cur].y)
                  - (pts[next].y - pts[cur].y) * (pts[i].x - pts[cur].x);
      if (cross < 0) next = i;
    }
    cur = next;
  } while (cur !== start && hull.length <= pts.length);
  return hull;
}

function inflateHull(hull, pad) {
  if (!hull.length) return hull;
  const cx = hull.reduce((s, p) => s + p.x, 0) / hull.length;
  const cy = hull.reduce((s, p) => s + p.y, 0) / hull.length;
  return hull.map(p => {
    const dx = p.x - cx, dy = p.y - cy;
    const len = Math.sqrt(dx*dx + dy*dy) || 1;
    return { x: p.x + (dx/len)*pad, y: p.y + (dy/len)*pad };
  });
}

function drawRoundedHull(ctx, pts) {
  if (!pts.length) return;
  ctx.beginPath();
  for (let i = 0; i < pts.length; i++) {
    const prev = pts[(i - 1 + pts.length) % pts.length];
    const cur  = pts[i];
    const next = pts[(i + 1) % pts.length];
    const mx0 = (prev.x + cur.x) / 2, my0 = (prev.y + cur.y) / 2;
    const mx1 = (cur.x + next.x) / 2, my1 = (cur.y + next.y) / 2;
    if (i === 0) ctx.moveTo(mx0, my0);
    else ctx.lineTo(mx0, my0);
    ctx.quadraticCurveTo(cur.x, cur.y, mx1, my1);
  }
  ctx.closePath();
}

function drawFamilyHulls(ctx, globalScale) {
  if (!hullVisible) return;
  const g = currentGraph();
  if (!g || is3d) return;

  // Determine which families to hull:
  //   • Family pill active → hull only the selected families
  //   • T3 ONLY or SUBSTRATE mode → hull all families visible in the current graph
  //   • Otherwise → nothing to hull
  let familiesToHull;
  if (activeFamilyFilters.size) {
    familiesToHull = activeFamilyFilters;
  } else if (t3OnlyMode || substrateMode) {
    familiesToHull = new Set(g.graphData().nodes.filter(n => n.family).map(n => n.family));
  } else {
    return;
  }
  if (!familiesToHull.size) return;

  const gd = g.graphData();
  const nodes = gd.nodes || [];
  const links = gd.links || [];
  const pad = 18 / globalScale;
  // Build id→node map for neighbour lookup
  const nodeById = {};
  nodes.forEach(n => { nodeById[n.id] = n; });
  // Expand hull to 1-hop neighbours only when a specific family pill is active.
  // In T3/substrate mode (all families visible) skip expansion — shared infrastructure
  // nodes (rules, imphash) are connected to multiple families, so expanding would cause
  // N overlapping fills that compound into an opaque dark rectangle.
  const expandToNeighbours = activeFamilyFilters.size > 0;

  ctx.save();
  for (const family of familiesToHull) {
    // Seed: all nodes directly tagged with this family
    const familyIds = new Set(nodes.filter(n => n.family === family).map(n => n.id));
    const hullIds = new Set(familyIds);
    if (expandToNeighbours) {
      links.forEach(l => {
        const srcId = typeof l.source === 'object' ? l.source.id : l.source;
        const tgtId = typeof l.target === 'object' ? l.target.id : l.target;
        if (familyIds.has(srcId)) hullIds.add(tgtId);
        if (familyIds.has(tgtId)) hullIds.add(srcId);
      });
    }
    const pts = [...hullIds]
      .map(id => nodeById[id])
      .filter(n => n && n.x != null)
      .map(n => ({ x: n.x, y: n.y }));
    if (!pts.length) continue;
    const color = familyColorMap[family] || 'hsl(200,60%,60%)';
    let hull;
    if (pts.length === 1) {
      hull = [{x:pts[0].x-pad,y:pts[0].y},{x:pts[0].x+pad,y:pts[0].y-pad},{x:pts[0].x+pad,y:pts[0].y+pad}];
    } else if (pts.length === 2) {
      const mx=(pts[0].x+pts[1].x)/2, my=(pts[0].y+pts[1].y)/2;
      const dx=pts[1].x-pts[0].x, dy=pts[1].y-pts[0].y;
      const len=Math.sqrt(dx*dx+dy*dy)||1;
      hull=[{x:pts[0].x,y:pts[0].y},{x:mx-dy/len*pad,y:my+dx/len*pad},{x:pts[1].x,y:pts[1].y},{x:mx+dy/len*pad,y:my-dx/len*pad}];
    } else {
      hull = inflateHull(convexHull(pts), pad);
    }
    drawRoundedHull(ctx, hull);
    // Use globalAlpha instead of rgba parsing — works with any CSS color format (hsl, hex, etc.)
    ctx.globalAlpha = 0.07; ctx.fillStyle = color; ctx.fill();
    ctx.globalAlpha = 0.5;
    ctx.strokeStyle = color; ctx.lineWidth = 1.5/globalScale;
    ctx.setLineDash([4/globalScale,3/globalScale]); ctx.stroke(); ctx.setLineDash([]);
    // Label at the topmost hull point
    const top = hull.reduce((a, b) => b.y < a.y ? b : a);
    const fontSize = 11 / globalScale;
    ctx.globalAlpha = 0.9;
    ctx.font = `600 ${fontSize}px 'Inter', sans-serif`;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'bottom';
    ctx.fillStyle = color;
    ctx.fillText(family, top.x, top.y - 14 / globalScale);
  }
  ctx.restore(); // restores globalAlpha to 1 along with all other saved state
}

// ── UMAP cluster view ─────────────────────────────────────────────────────────
const UMAP_UNKNOWN_PALETTE = ['#475569','#52525b','#57534e','#4b5563','#44403c','#404040'];
function umapUnknownColor(cid) {
  return UMAP_UNKNOWN_PALETTE[Math.abs(cid) % UMAP_UNKNOWN_PALETTE.length];
}

let umapShowLabels = false;
let umapHighlightCluster = null; // number or null
let umapViewScale = 1;
let umapViewOffX = 0; // canvas-space offset applied after scale
let umapViewOffY = 0;

async function loadAndRenderUmap() {
  if (!umapData) {
    try {
      const res = await fetch('/api/projections');
      umapData = await res.json();
    } catch (e) {
      umapData = [];
    }
  }
  if (!umapData.length) {
    const canvas = document.getElementById('umap-canvas');
    canvas.width = canvas.offsetWidth || 800; canvas.height = canvas.offsetHeight || 600;
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = '#5a6070'; ctx.font = '14px monospace'; ctx.textAlign = 'center';
    ctx.fillText('No projections — run: cairn project', canvas.width / 2, canvas.height / 2);
    return;
  }
  renderUmap();
}

function renderUmap() {
  const canvas = document.getElementById('umap-canvas');
  if (!canvas || canvas.style.display === 'none') return;
  canvas.width = canvas.offsetWidth || 800;
  canvas.height = canvas.offsetHeight || 600;
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  ctx.clearRect(0, 0, W, H);

  const pad = 48;
  // Base projection (no view transform) — used for hit testing
  const toCBase = (x, y) => ({
    cx: pad + (x + 1) / 2 * (W - 2 * pad),
    cy: pad + (1 - (y + 1) / 2) * (H - 2 * pad),
  });
  // Apply view transform for drawing
  ctx.save();
  ctx.translate(umapViewOffX, umapViewOffY);
  ctx.scale(umapViewScale, umapViewScale);
  const toC = (x, y) => toCBase(x, y);

  // Group by cluster_id
  const clusters = {};
  for (const pt of umapData) {
    const cid = pt.cluster_id != null ? pt.cluster_id : -1;
    (clusters[cid] = clusters[cid] || []).push(pt);
  }

  // Draw cluster hulls (skip noise cluster -1)
  for (const [cidStr, pts] of Object.entries(clusters)) {
    const cid = +cidStr;
    if (cid === -1) continue;
    const family = (pts.find(p => p.family) || {}).family;
    let color;
    if (family) {
      if (!familyColorMap[family]) familyColorMap[family] = familyColorFromName(family);
      color = familyColorMap[family];
    } else {
      color = umapUnknownColor(cid);
    }
    const cpts = pts.map(p => { const c = toC(p.x, p.y); return { x: c.cx, y: c.cy }; });
    if (cpts.length < 2) continue;
    let hull;
    if (cpts.length === 2) {
      const mx = (cpts[0].x + cpts[1].x) / 2, my = (cpts[0].y + cpts[1].y) / 2;
      hull = [{ x: cpts[0].x, y: cpts[0].y }, { x: mx, y: my - 12 }, { x: cpts[1].x, y: cpts[1].y }, { x: mx, y: my + 12 }];
    } else {
      hull = inflateHull(convexHull(cpts), 14);
    }
    drawRoundedHull(ctx, hull);
    const r = parseInt(color.slice(1, 3), 16), gg = parseInt(color.slice(3, 5), 16), b = parseInt(color.slice(5, 7), 16);
    ctx.fillStyle = `rgba(${r},${gg},${b},${family ? 0.10 : 0.04})`; ctx.fill();
    ctx.strokeStyle = `rgba(${r},${gg},${b},${family ? 0.55 : 0.20})`;
    ctx.lineWidth = family ? 1.5 : 0.75;
    ctx.setLineDash(family ? [4, 3] : [2, 5]); ctx.stroke(); ctx.setLineDash([]);
    if (family) {
      const cx = cpts.reduce((s, p) => s + p.x, 0) / cpts.length;
      const cy = cpts.reduce((s, p) => s + p.y, 0) / cpts.length - 14;
      ctx.fillStyle = color; ctx.font = 'bold 11px monospace'; ctx.textAlign = 'center';
      ctx.fillText(family, cx, cy);
    }
  }

  // Draw dots and build hit-test list
  umapRenderedPts = [];
  const hasHighlight = umapHighlightCluster !== null;
  for (const pt of umapData) {
    const { cx, cy } = toC(pt.x, pt.y);
    const cid = pt.cluster_id != null ? pt.cluster_id : -1;
    const isHighlit = hasHighlight && cid === umapHighlightCluster;
    let color;
    if (pt.family) {
      color = familyColorMap[pt.family] || '#4f8ef7';
    } else if (cid === -1) {
      color = '#2a2f42';
    } else {
      color = umapUnknownColor(cid);
    }
    const alpha = hasHighlight && !isHighlit ? 0.18 : 1;
    const r = parseInt(color.slice(1,3),16), gg = parseInt(color.slice(3,5),16), b = parseInt(color.slice(5,7),16);
    ctx.beginPath(); ctx.arc(cx, cy, isHighlit ? 5 : 4, 0, 2 * Math.PI);
    ctx.fillStyle = `rgba(${r},${gg},${b},${alpha})`; ctx.fill();
    umapRenderedPts.push({ cx, cy, sha256: pt.sha256, family: pt.family, cluster_id: cid });
  }

  // Draw cluster ID labels
  if (umapShowLabels || hasHighlight) {
    const clusters2 = {};
    for (const p of umapRenderedPts) {
      if (p.cluster_id === -1) continue;
      if (hasHighlight && p.cluster_id !== umapHighlightCluster) continue;
      (clusters2[p.cluster_id] = clusters2[p.cluster_id] || []).push(p);
    }
    for (const [cidStr, pts] of Object.entries(clusters2)) {
      const cid = +cidStr;
      const cx = pts.reduce((s,p) => s+p.cx, 0) / pts.length;
      const cy = pts.reduce((s,p) => s+p.cy, 0) / pts.length;
      const color = (pts[0].family && familyColorMap[pts[0].family]) || umapUnknownColor(cid);
      ctx.font = hasHighlight && cid === umapHighlightCluster ? 'bold 13px monospace' : '10px monospace';
      ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
      ctx.fillStyle = hasHighlight && cid === umapHighlightCluster ? '#ffffff' : `${color}cc`;
      ctx.fillText(String(cid), cx, cy);
    }
  }

  // Draw selection ring on top
  if (umapSelectedSha) {
    const sel = umapRenderedPts.find(p => p.sha256 === umapSelectedSha);
    if (sel) {
      ctx.beginPath(); ctx.arc(sel.cx, sel.cy, 8, 0, 2 * Math.PI);
      ctx.strokeStyle = '#fff'; ctx.lineWidth = 1.5; ctx.stroke();
      ctx.beginPath(); ctx.arc(sel.cx, sel.cy, 9.5, 0, 2 * Math.PI);
      ctx.strokeStyle = 'rgba(255,255,255,0.3)'; ctx.lineWidth = 1; ctx.stroke();
    }
  }

  // Draw highlight cluster bounding box
  if (hasHighlight) {
    const hpts = umapRenderedPts.filter(p => p.cluster_id === umapHighlightCluster);
    if (hpts.length) {
      const minX = Math.min(...hpts.map(p=>p.cx)) - 18;
      const maxX = Math.max(...hpts.map(p=>p.cx)) + 18;
      const minY = Math.min(...hpts.map(p=>p.cy)) - 18;
      const maxY = Math.max(...hpts.map(p=>p.cy)) + 18;
      ctx.strokeStyle = 'rgba(255,255,255,0.55)'; ctx.lineWidth = 1.5 / umapViewScale;
      ctx.setLineDash([5/umapViewScale, 4/umapViewScale]);
      ctx.strokeRect(minX, minY, maxX-minX, maxY-minY);
      ctx.setLineDash([]);
    }
  }

  ctx.restore();
}

// ── Highlight / selection ─────────────────────────────────────────────────────
function onNodeHover(node) {
  hoverNodes.clear();
  hoverLinks.clear();
  if (node) {
    hoverNodes.add(node.id);
    const g = currentGraph();
    if (g) (g.graphData().links || []).forEach(l => {
      const sid = typeof l.source === 'object' ? l.source.id : l.source;
      const tid = typeof l.target === 'object' ? l.target.id : l.target;
      if (sid === node.id || tid === node.id) {
        hoverLinks.add(l);
        hoverNodes.add(sid);
        hoverNodes.add(tid);
      }
    });
  }
  document.getElementById('graph-wrap').style.cursor = node ? 'pointer' : '';
  refreshGraphAccessors();
}

function onNodeClick(node) {
  selectedNode = node;
  highlightNodes.clear();
  highlightLinks.clear();
  highlightNodes.add(node.id);
  const g = currentGraph();
  if (g) {
    (g.graphData().links || []).forEach(l => {
      const sid = typeof l.source === 'object' ? l.source.id : l.source;
      const tid = typeof l.target === 'object' ? l.target.id : l.target;
      if (sid === node.id || tid === node.id) {
        highlightLinks.add(l);
        highlightNodes.add(sid);
        highlightNodes.add(tid);
      }
    });
    refreshGraphAccessors();
  }
  document.getElementById('btn-focus').style.display = 'block';
  if (focusMode) { focusNodeId = node.id; applyFilter(); }
  renderDetail(node);
}

function clearHighlight() {
  highlightNodes.clear();
  highlightLinks.clear();
  hoverNodes.clear();
  hoverLinks.clear();
  selectedNode = null;
  refreshGraphAccessors();
  renderDetailPlaceholder();
  document.getElementById('btn-focus').style.display = 'none';
  focusMode = false; focusNodeId = null;
}

function currentGraph() { return is3d ? graph3d : graph2d; }

// ── Stable graphData: freeze positions during filter-driven updates ───────────
// Calling g.graphData() reheats the simulation to alpha=1, scattering nodes.
// For filter-only changes every node already has a settled position — freeze it.
function stableGraphData(g, data, { zoom = false } = {}) {
  g.cooldownTicks(0);   // simulation stops after 0 ticks: positions preserved
  g.graphData(data);
  requestAnimationFrame(() => {
    g.cooldownTicks(Infinity); // restore for Reheat btn
    if (zoom) g.zoomToFit(400, 40);
  });
}

// ── Filter / search ───────────────────────────────────────────────────────────
function filteredData() {
  let nodes = gData.nodes.filter(n => {
    if (!activeTypes.has(n.type)) return false;
    if (n.type === 'submitter' && submitterMaxCount !== Infinity &&
        (n.corpus_sample_count || 1) > submitterMaxCount) return false;
    return true;
  });
  if (t3OnlyMode) {
    nodes = nodes.filter(n => n.type !== 'sample' || n._hasT3);
    // Drop non-sample nodes that are only connected to the removed samples
    const t3SampleIds = new Set(nodes.filter(n => n.type === 'sample').map(n => n.id));
    const connectedIds = new Set(t3SampleIds);
    for (const l of gData.links) {
      const sid = typeof l.source === 'object' ? l.source.id : l.source;
      const tid = typeof l.target === 'object' ? l.target.id : l.target;
      if (t3SampleIds.has(sid)) connectedIds.add(tid);
      if (t3SampleIds.has(tid)) connectedIds.add(sid);
    }
    nodes = nodes.filter(n => connectedIds.has(n.id));
  }
  if (substrateMode) {
    // Keep only confirmed-family sample nodes + their 1-hop connected non-sample nodes.
    // This removes extraneous non-family executables without losing the structural context.
    const familySampleIds = new Set(
      nodes.filter(n => n.type === 'sample' && n.family).map(n => n.id)
    );
    const connectedIds = new Set(familySampleIds);
    for (const l of gData.links) {
      const sid = typeof l.source === 'object' ? l.source.id : l.source;
      const tid = typeof l.target === 'object' ? l.target.id : l.target;
      if (familySampleIds.has(sid)) connectedIds.add(tid);
      if (familySampleIds.has(tid)) connectedIds.add(sid);
    }
    nodes = nodes.filter(n => connectedIds.has(n.id));
  }
  if (focusMode && focusNodeId) {
    const inFocus = new Set([focusNodeId]);
    let frontier = new Set([focusNodeId]);
    for (let hop = 0; hop < 2; hop++) {
      const next = new Set();
      for (const l of gData.links) {
        const sid = typeof l.source === 'object' ? l.source.id : l.source;
        const tid = typeof l.target === 'object' ? l.target.id : l.target;
        if (frontier.has(sid) && !inFocus.has(tid)) { inFocus.add(tid); next.add(tid); }
        if (frontier.has(tid) && !inFocus.has(sid)) { inFocus.add(sid); next.add(sid); }
      }
      frontier = next;
    }
    nodes = nodes.filter(n => inFocus.has(n.id));
  }
  const nodeIds = new Set(nodes.map(n => n.id));
  const links = gData.links.filter(l => {
    const sid = typeof l.source === 'object' ? l.source.id : l.source;
    const tid = typeof l.target === 'object' ? l.target.id : l.target;
    return nodeIds.has(sid) && nodeIds.has(tid);
  });
  return { nodes, links };
}

function applyFilter() {
  if (activeRuleFilter) {
    applyRuleFilter();
  } else if (activeProviderFilter) {
    applyProviderFilter();
  } else if (activeFamilyFilter) {
    applyFamilyFilter();
  } else {
    const filtered = filteredData();
    const g = currentGraph();
    if (g) { stableGraphData(g, filtered); updateNodeCount(filtered); }
  }
}

// ── Family pills ──────────────────────────────────────────────────────────────
function renderFamilyPills() {
  const wrap = document.getElementById('family-pills');
  wrap.innerHTML = '';

  const allPill = document.createElement('div');
  allPill.className = 'fpill fpill-all active';
  allPill.setAttribute('role', 'button');
  allPill.tabIndex = 0;
  allPill.setAttribute('aria-pressed', 'true');
  allPill.textContent = 'ALL';
  allPill.addEventListener('click', () => setFamilyFilter(null));
  wrap.appendChild(allPill);

  for (const [fam, color] of Object.entries(familyColorMap)) {
    const p = document.createElement('div');
    p.className = 'fpill inactive';
    p.setAttribute('role', 'button');
    p.tabIndex = 0;
    p.setAttribute('aria-pressed', 'false');
    p.textContent = fam;
    p.style.borderColor = color;
    p.style.color = color;
    p.dataset.family = fam;
    p.addEventListener('click', e => setFamilyFilter(fam, e.ctrlKey || e.metaKey));
    wrap.appendChild(p);
  }
}

function setFamilyFilter(family, multi = false) {
  activeRuleFilter = null;
  activeProviderFilter = null;
  _clearRuleItemActive();
  _clearProviderItemActive();

  if (!family) {
    // ALL clicked — clear everything
    activeFamilyFilters.clear();
    activeFamilyFilter = null;
  } else if (multi) {
    // Ctrl+click — toggle this family in/out of the set
    if (activeFamilyFilters.has(family)) {
      activeFamilyFilters.delete(family);
      if (activeFamilyFilter === family)
        activeFamilyFilter = activeFamilyFilters.size ? [...activeFamilyFilters].at(-1) : null;
    } else {
      activeFamilyFilters.add(family);
      activeFamilyFilter = family;
    }
  } else {
    // Plain click — replace selection with just this family (toggle off if already sole)
    if (activeFamilyFilters.size === 1 && activeFamilyFilters.has(family)) {
      activeFamilyFilters.clear();
      activeFamilyFilter = null;
    } else {
      activeFamilyFilters.clear();
      activeFamilyFilters.add(family);
      activeFamilyFilter = family;
    }
  }

  const anyActive = activeFamilyFilters.size > 0;
  document.querySelectorAll('.fpill').forEach(p => {
    if (p.classList.contains('fpill-all')) {
      p.classList.toggle('active', !anyActive);
      p.classList.toggle('inactive', anyActive);
      p.setAttribute('aria-pressed', String(!anyActive));
    } else {
      const active = activeFamilyFilters.has(p.dataset.family);
      p.classList.toggle('active', active);
      p.classList.toggle('inactive', !active);
      p.setAttribute('aria-pressed', String(active));
    }
  });

  if (activeFamilyFilter) showFamilyReport(activeFamilyFilter);
  else hideFamilyReport();

  applyFamilyFilter();
}

function showFamilyReport(family) {
  const panel = document.getElementById('family-report-panel');
  const title = document.getElementById('family-report-title');
  const body  = document.getElementById('family-report-body');
  title.textContent = family;
  body.innerHTML = '<div style="color:var(--text-dim);padding:20px 0">Loading…</div>';
  panel.classList.add('open');
  reportPanelOpen = true;
  document.getElementById('toolbar').classList.add('panel-open');
  fetch('/api/family/' + encodeURIComponent(family))
    .then(r => r.json())
    .then(d => {
      if (d.exists && d.markdown) {
        body.innerHTML = marked.parse(d.markdown);
      } else {
        body.innerHTML = '<div style="color:var(--text-dim);padding:20px 0">No report available for ' + esc(family) + '</div>';
      }
    })
    .catch(() => {
      body.innerHTML = '<div style="color:var(--danger);padding:20px 0">Failed to load report</div>';
    });
}

function hideFamilyReport() {
  document.getElementById('family-report-panel').classList.remove('open');
  reportPanelOpen = false;
  document.getElementById('toolbar').classList.remove('panel-open');
}

function applyFamilyFilter() {
  const base = filteredData();
  if (!activeFamilyFilters.size) {
    const g = currentGraph();
    if (g) { stableGraphData(g, base); updateNodeCount(base); }
    return;
  }

  const baseNodeIds = new Set(base.nodes.map(n => n.id));
  const seedIds = new Set(
    base.nodes.filter(n => activeFamilyFilters.has(n.family)).map(n => n.id)
  );

  const visited = new Set(seedIds);
  let frontier = [...seedIds];
  for (let hop = 0; hop < 2; hop++) {
    const next = [];
    for (const link of base.links) {
      const sid = typeof link.source === 'object' ? link.source.id : link.source;
      const tid = typeof link.target === 'object' ? link.target.id : link.target;
      if (frontier.includes(sid) && !visited.has(tid) && baseNodeIds.has(tid)) {
        visited.add(tid); next.push(tid);
      }
      if (frontier.includes(tid) && !visited.has(sid) && baseNodeIds.has(sid)) {
        visited.add(sid); next.push(sid);
      }
    }
    frontier = next;
  }

  const subNodes = base.nodes.filter(n => visited.has(n.id));
  const subLinks = base.links.filter(l => {
    const sid = typeof l.source === 'object' ? l.source.id : l.source;
    const tid = typeof l.target === 'object' ? l.target.id : l.target;
    return visited.has(sid) && visited.has(tid);
  });
  const sub = { nodes: subNodes, links: subLinks };
  const g = currentGraph();
  if (g) { stableGraphData(g, sub, { zoom: true }); updateNodeCount(sub); }
}

// ── Rule filter ───────────────────────────────────────────────────────────────
function setRuleFilter(name) {
  if (activeRuleFilter === name) name = null;
  activeRuleFilter = name;
  activeFamilyFilter = null;
  activeFamilyFilters.clear();
  activeProviderFilter = null;
  _clearProviderItemActive();
  _resetFamilyPills();

  document.querySelectorAll('.rule-item').forEach(el => {
    el.classList.toggle('rule-active', el.dataset.name === name);
  });

  applyFilter();
}

function applyRuleFilter() {
  const base = filteredData();
  const ruleNodeId = 'rule:' + activeRuleFilter;
  const hitSet = ruleHitSamples[ruleNodeId] || new Set();
  const baseNodeIds = new Set(base.nodes.map(n => n.id));

  // Rule node + its samples + 1-hop neighbors of those samples
  const visited = new Set();
  if (baseNodeIds.has(ruleNodeId)) visited.add(ruleNodeId);
  for (const s of hitSet) if (baseNodeIds.has(s)) visited.add(s);

  for (const link of base.links) {
    const sid = typeof link.source === 'object' ? link.source.id : link.source;
    const tid = typeof link.target === 'object' ? link.target.id : link.target;
    if (hitSet.has(sid) && baseNodeIds.has(tid)) visited.add(tid);
    if (hitSet.has(tid) && baseNodeIds.has(sid)) visited.add(sid);
  }

  const subNodes = base.nodes.filter(n => visited.has(n.id));
  const subLinks = base.links.filter(l => {
    const sid = typeof l.source === 'object' ? l.source.id : l.source;
    const tid = typeof l.target === 'object' ? l.target.id : l.target;
    return visited.has(sid) && visited.has(tid);
  });
  const g = currentGraph();
  if (g) { stableGraphData(g, { nodes: subNodes, links: subLinks }, { zoom: true }); updateNodeCount({ nodes: subNodes, links: subLinks }); }
}

// ── Provider filter ───────────────────────────────────────────────────────────
function setProviderFilter(provId) {
  if (activeProviderFilter === provId) provId = null;
  activeProviderFilter = provId;
  activeFamilyFilter = null;
  activeFamilyFilters.clear();
  activeRuleFilter = null;
  _clearRuleItemActive();
  _resetFamilyPills();

  document.querySelectorAll('.provider-item').forEach(el => {
    el.classList.toggle('prov-active', el.dataset.provId === provId);
  });

  applyFilter();
}

function applyProviderFilter() {
  const base = filteredData();
  const provNodeId = activeProviderFilter;
  const hitSet = providerSamples[provNodeId] || new Set();
  const baseNodeIds = new Set(base.nodes.map(n => n.id));

  const visited = new Set();
  if (baseNodeIds.has(provNodeId)) visited.add(provNodeId);
  for (const s of hitSet) if (baseNodeIds.has(s)) visited.add(s);

  for (const link of base.links) {
    const sid = typeof link.source === 'object' ? link.source.id : link.source;
    const tid = typeof link.target === 'object' ? link.target.id : link.target;
    if (hitSet.has(sid) && baseNodeIds.has(tid)) visited.add(tid);
    if (hitSet.has(tid) && baseNodeIds.has(sid)) visited.add(sid);
  }

  const subNodes = base.nodes.filter(n => visited.has(n.id));
  const subLinks = base.links.filter(l => {
    const sid = typeof l.source === 'object' ? l.source.id : l.source;
    const tid = typeof l.target === 'object' ? l.target.id : l.target;
    return visited.has(sid) && visited.has(tid);
  });
  const g = currentGraph();
  if (g) { stableGraphData(g, { nodes: subNodes, links: subLinks }, { zoom: true }); updateNodeCount({ nodes: subNodes, links: subLinks }); }
}

// ── Helper: clear active states ───────────────────────────────────────────────
function _clearRuleItemActive() {
  document.querySelectorAll('.rule-item').forEach(el => el.classList.remove('rule-active'));
}
function _clearProviderItemActive() {
  document.querySelectorAll('.provider-item').forEach(el => el.classList.remove('prov-active'));
}
function _resetFamilyPills() {
  document.querySelectorAll('.fpill').forEach(p => {
    const isAll = p.classList.contains('fpill-all');
    p.classList.toggle('active', isAll);
    p.classList.toggle('inactive', !isAll);
    p.setAttribute('aria-pressed', String(isAll));
  });
}

// ── Controls ──────────────────────────────────────────────────────────────────
function toggleNodeType(el) {
    const t = el.dataset.type;
    if (activeTypes.has(t)) { activeTypes.delete(t); el.classList.replace('active','inactive'); }
    else                    { activeTypes.add(t);    el.classList.replace('inactive','active'); }
    el.setAttribute('aria-pressed', String(activeTypes.has(t)));
    applyFilter();
}

document.querySelectorAll('.tog').forEach(el => {
  el.addEventListener('click', () => toggleNodeType(el));
  el.addEventListener('keydown', e => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggleNodeType(el); }
  });
});

document.addEventListener('keydown', e => {
  if ((e.key === 'Enter' || e.key === ' ') && e.target.matches('.fpill')) {
    e.preventDefault(); e.target.click();
  }
});

document.getElementById('submitter-max').addEventListener('input', e => {
  const val = parseInt(e.target.value, 10);
  submitterMaxCount = isNaN(val) || val < 1 ? Infinity : val;
  applyFilter();
});

function clearActiveFilters() {
  activeTypes = new Set(['sample','yara_rule','acquisition_filter','provider','imphash','domain','cert','submitter']);
  document.querySelectorAll('.tog').forEach(el => {
    el.classList.remove('inactive');
    el.classList.add('active');
    el.setAttribute('aria-pressed', 'true');
  });
  document.getElementById('search').value = '';
  document.getElementById('submitter-max').value = '';
  submitterMaxCount = Infinity;
  activeFamilyFilter = null;
  activeFamilyFilters.clear();
  activeRuleFilter = null;
  activeProviderFilter = null;
  t3OnlyMode = false;
  document.getElementById('btn-t3').classList.remove('active');
  substrateMode = false;
  document.getElementById('btn-substrate').classList.remove('active');
  focusMode = false; focusNodeId = null;
  document.getElementById('btn-focus').classList.remove('active');
  document.getElementById('btn-focus').style.display = 'none';
  _clearRuleItemActive();
  _clearProviderItemActive();
  _resetFamilyPills();
  hideFamilyReport();
  clearHighlight();
  applyFilter();
}

document.getElementById('btn-clear-filters').addEventListener('click', () => {
  clearActiveFilters();
  showToast('Filters cleared', false);
});

document.getElementById('btn-reset').addEventListener('click', () => {
  clearActiveFilters();
  const g = currentGraph(); if (g) g.zoomToFit(400);
});

document.getElementById('btn-t3').addEventListener('click', () => {
  t3OnlyMode = !t3OnlyMode;
  document.getElementById('btn-t3').classList.toggle('active', t3OnlyMode);
  applyFilter();
});

document.getElementById('btn-substrate').addEventListener('click', () => {
  substrateMode = !substrateMode;
  document.getElementById('btn-substrate').classList.toggle('active', substrateMode);
  applyFilter();
});

function toggleSidebar() {
  document.getElementById('layout').classList.toggle('sidebar-hidden');
  // Fire resize after the CSS transition finishes so the canvas fills the new width
  setTimeout(() => window.dispatchEvent(new Event('resize')), 260);
}
document.getElementById('btn-sidebar-hide').addEventListener('click', toggleSidebar);
document.getElementById('btn-collapse').addEventListener('click', toggleSidebar);

document.getElementById('btn-reheat').addEventListener('click', () => {
  const g = currentGraph(); if (g && g.d3ReheatSimulation) g.d3ReheatSimulation();
});

document.getElementById('btn-hull').addEventListener('click', () => {
  hullVisible = !hullVisible;
  document.getElementById('btn-hull').classList.toggle('active', hullVisible);
});

document.getElementById('btn-umap').addEventListener('click', () => {
  isUmapMode = !isUmapMode;
  document.getElementById('btn-umap').classList.toggle('active', isUmapMode);
  const graphCanvas = document.getElementById('graph-canvas');
  const graph3dEl = document.getElementById('graph-3d');
  const umapCanvas = document.getElementById('umap-canvas');
  const umapControls = document.getElementById('umap-controls');
  if (isUmapMode) {
    graphCanvas.style.display = 'none';
    graph3dEl.style.display = 'none';
    umapCanvas.style.display = '';
    umapCanvas.style.height = 'calc(100% - 34px)';
    umapControls.classList.add('umap-visible');
    loadAndRenderUmap();
  } else {
    umapCanvas.style.display = 'none';
    umapCanvas.style.height = '100%';
    umapControls.classList.remove('umap-visible');
    umapHighlightCluster = null;
    umapViewScale = 1; umapViewOffX = 0; umapViewOffY = 0;
    document.getElementById('umap-cluster-input').value = '';
    if (is3d) graph3dEl.style.display = 'block';
    else graphCanvas.style.display = '';
  }
});

document.getElementById('umap-cluster-input').addEventListener('input', e => {
  const val = e.target.value.trim();
  if (val === '') {
    umapHighlightCluster = null;
    umapViewScale = 1; umapViewOffX = 0; umapViewOffY = 0;
    renderUmap();
    return;
  }
  const n = parseInt(val, 10);
  umapHighlightCluster = isNaN(n) ? null : n;
  renderUmap(); // render first pass to populate umapRenderedPts
  if (umapHighlightCluster !== null && umapRenderedPts.length) {
    const hpts = umapRenderedPts.filter(p => p.cluster_id === umapHighlightCluster);
    if (hpts.length) {
      const canvas = document.getElementById('umap-canvas');
      const W = canvas.offsetWidth, H = canvas.offsetHeight;
      const bx0 = Math.min(...hpts.map(p=>p.cx)), bx1 = Math.max(...hpts.map(p=>p.cx));
      const by0 = Math.min(...hpts.map(p=>p.cy)), by1 = Math.max(...hpts.map(p=>p.cy));
      const bw = bx1 - bx0 + 80, bh = by1 - by0 + 80;
      const scale = Math.min(5, Math.max(1.2, Math.min(W / bw, H / bh)));
      const clusterCx = (bx0 + bx1) / 2, clusterCy = (by0 + by1) / 2;
      umapViewScale = scale;
      umapViewOffX = W / 2 - clusterCx * scale;
      umapViewOffY = H / 2 - clusterCy * scale;
      renderUmap();
    }
  }
});

document.getElementById('umap-labels-btn').addEventListener('click', () => {
  umapShowLabels = !umapShowLabels;
  document.getElementById('umap-labels-btn').classList.toggle('active', umapShowLabels);
  renderUmap();
});

function umapClientToCanvas(clientX, clientY) {
  const rect = document.getElementById('umap-canvas').getBoundingClientRect();
  // Inverse of: ctx.translate(offX, offY); ctx.scale(s, s)
  return {
    mx: (clientX - rect.left - umapViewOffX) / umapViewScale,
    my: (clientY - rect.top  - umapViewOffY) / umapViewScale,
  };
}

document.getElementById('umap-canvas').addEventListener('mousemove', e => {
  if (!isUmapMode || umapDragging) return;
  const { mx, my } = umapClientToCanvas(e.clientX, e.clientY);
  const hit = umapRenderedPts.find(p => Math.hypot(p.cx - mx, p.cy - my) < 8);
  const tip = document.getElementById('umap-tooltip');
  if (hit) {
    tip.style.display = 'block';
    tip.style.left = (e.clientX + 14) + 'px'; tip.style.top = (e.clientY - 10) + 'px';
    const famStr = hit.family ? ` [${hit.family}]` : '';
    tip.textContent = `${hit.sha256.slice(0, 16)}…${famStr}  cluster:${hit.cluster_id}`;
  } else {
    tip.style.display = 'none';
  }
});

document.getElementById('umap-canvas').addEventListener('click', e => {
  if (!isUmapMode) return;
  const { mx, my } = umapClientToCanvas(e.clientX, e.clientY);
  const hit = umapRenderedPts.find(p => Math.hypot(p.cx - mx, p.cy - my) < 10);
  if (!hit) return;
  // Synthesise a minimal node object and drive the existing detail panel
  const node = {
    type: 'sample',
    id: `sample:${hit.sha256}`,
    sha256: hit.sha256,
    family: hit.family,
    cluster_id: hit.cluster_id,
  };
  renderDetail(node);
  // Highlight selected dot — re-render with selection marker
  umapSelectedSha = hit.sha256;
  renderUmap();
});

document.getElementById('umap-canvas').addEventListener('mouseleave', () => {
  document.getElementById('umap-tooltip').style.display = 'none';
});

// ── Scroll-to-zoom (cursor-anchored) ─────────────────────────────────────────
document.getElementById('umap-canvas').addEventListener('wheel', e => {
  if (!isUmapMode) return;
  e.preventDefault();
  const rect = document.getElementById('umap-canvas').getBoundingClientRect();
  const px = e.clientX - rect.left;
  const py = e.clientY - rect.top;
  // Point in data-space before scale change
  const wx = (px - umapViewOffX) / umapViewScale;
  const wy = (py - umapViewOffY) / umapViewScale;
  const factor = e.deltaY < 0 ? 1.15 : 1 / 1.15;
  umapViewScale = Math.max(0.3, Math.min(20, umapViewScale * factor));
  // Re-anchor so the cursor stays over the same data point
  umapViewOffX = px - wx * umapViewScale;
  umapViewOffY = py - wy * umapViewScale;
  renderUmap();
}, { passive: false });

// ── Drag-to-pan ───────────────────────────────────────────────────────────────
let umapDragging = false;
let umapDragStartX = 0, umapDragStartY = 0;
let umapDragOffX = 0, umapDragOffY = 0;

document.getElementById('umap-canvas').addEventListener('mousedown', e => {
  if (!isUmapMode) return;
  umapDragging = true;
  umapDragStartX = e.clientX;
  umapDragStartY = e.clientY;
  umapDragOffX = umapViewOffX;
  umapDragOffY = umapViewOffY;
  document.getElementById('umap-canvas').style.cursor = 'grabbing';
});

document.addEventListener('mousemove', e => {
  if (!umapDragging) return;
  umapViewOffX = umapDragOffX + (e.clientX - umapDragStartX);
  umapViewOffY = umapDragOffY + (e.clientY - umapDragStartY);
  renderUmap();
});

document.addEventListener('mouseup', () => {
  if (!umapDragging) return;
  umapDragging = false;
  document.getElementById('umap-canvas').style.cursor = '';
});

window.addEventListener('resize', () => {
  if (isUmapMode) {
    // Reset view on resize — cluster positions will shift with canvas size
    umapViewScale = 1; umapViewOffX = 0; umapViewOffY = 0;
    renderUmap();
  }
});

document.getElementById('btn-focus').addEventListener('click', () => {
  if (!selectedNode) return;
  focusMode = !focusMode;
  focusNodeId = focusMode ? selectedNode.id : null;
  document.getElementById('btn-focus').classList.toggle('active', focusMode);
  applyFilter();
});

document.getElementById('btn-table').addEventListener('click', () => {
  isTableMode = !isTableMode;
  document.getElementById('btn-table').classList.toggle('active', isTableMode);
  const canvasEl = document.getElementById('graph-canvas');
  const threeDEl = document.getElementById('graph-3d');
  const pillsEl  = document.getElementById('family-pills');
  const legendEl = document.getElementById('graph-legend');
  const toolbarEl = document.getElementById('toolbar');
  const corpusEl = document.getElementById('corpus-wrap');
  if (isTableMode) {
    canvasEl.style.display = 'none';
    threeDEl.style.display = 'none';
    pillsEl.style.display  = 'none';
    legendEl.style.display = 'none';
    toolbarEl.style.display = 'none';
    corpusEl.style.display = 'block';
    loadCorpusTable();
  } else {
    corpusEl.style.display  = 'none';
    pillsEl.style.display   = '';
    legendEl.style.display  = '';
    toolbarEl.style.display = '';
    if (is3d) threeDEl.style.display = 'block';
    else canvasEl.style.display = 'block';
  }
});

function loadCorpusTable() {
  const el = document.getElementById('corpus-wrap');
  if (samplesCache) { renderCorpusTable(samplesCache); return; }
  el.innerHTML = '<div style="color:var(--text-dim);padding:20px;font-size:12px">Loading…</div>';
  fetch('/api/samples').then(r => r.json()).then(data => {
    samplesCache = data;
    renderCorpusTable(data);
  }).catch(e => {
    el.innerHTML = `<div style="color:var(--danger);padding:20px;font-size:12px">Failed: ${e}</div>`;
  });
}

function renderCorpusTable(samples) {
  const el = document.getElementById('corpus-wrap');
  el.innerHTML = `
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
    <span style="color:var(--text-dim);font-size:11px" id="corpus-count">${samples.length} samples</span>
    <input id="corpus-q" type="text" placeholder="Filter SHA256, family, name, rule…"
      style="background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:4px 8px;border-radius:3px;font-family:inherit;font-size:11px;width:260px;outline:none">
  </div>
  <table style="width:100%;border-collapse:collapse;font-size:11px">
    <thead>
      <tr style="border-bottom:2px solid var(--border)">
        <th class="ch" data-col="sha256"    style="text-align:left;padding:4px 8px;color:var(--text-dim);font-weight:normal;white-space:nowrap;cursor:pointer">SHA256</th>
        <th class="ch" data-col="name"      style="text-align:left;padding:4px 8px;color:var(--text-dim);font-weight:normal;cursor:pointer">Name</th>
        <th class="ch" data-col="first_seen"style="text-align:left;padding:4px 8px;color:var(--text-dim);font-weight:normal;white-space:nowrap;cursor:pointer">First Seen</th>
        <th class="ch" data-col="detections"style="text-align:right;padding:4px 8px;color:var(--text-dim);font-weight:normal;white-space:nowrap;cursor:pointer">Det</th>
        <th class="ch" data-col="family"    style="text-align:left;padding:4px 8px;color:var(--text-dim);font-weight:normal;cursor:pointer">T3 Family</th>
        <th style="text-align:left;padding:4px 8px;color:var(--text-dim);font-weight:normal">Rules</th>
        <th style="text-align:left;padding:4px 8px;color:var(--text-dim);font-weight:normal">Tags</th>
      </tr>
    </thead>
    <tbody id="corpus-tbody"></tbody>
  </table>`;

  let sortCol = 'detections', sortDir = -1, filterQ = '';

  function renderRows() {
    let rows = samples.slice();
    if (filterQ) {
      const q = filterQ.toLowerCase();
      rows = rows.filter(s => [s.sha256, s.name, s.family, ...(s.rule_names||[]), ...(s.tags||[])].filter(Boolean).join(' ').toLowerCase().includes(q));
    }
    rows.sort((a, b) => {
      let av = a[sortCol] ?? (sortCol === 'detections' ? -1 : '');
      let bv = b[sortCol] ?? (sortCol === 'detections' ? -1 : '');
      return typeof av === 'number' ? (av - bv) * sortDir : String(av).localeCompare(String(bv)) * sortDir;
    });
    document.getElementById('corpus-count').textContent = `${rows.length} / ${samples.length} samples`;
    document.getElementById('corpus-tbody').innerHTML = rows.map(s => {
      const det = s.detections || 0;
      const detCls = det >= 30 ? 'det-high' : det >= 10 ? 'det-med' : 'det-low';
      const fam = s.family ? `<span class="family-badge" style="font-size:9px;padding:1px 5px">${esc(s.family)}</span>` : '<span style="color:var(--text-dim)">—</span>';
      const rules = (s.rule_names||[]).map(r => `<span class="pill ${r.startsWith('T3')?'pill-t3':r.startsWith('T2')?'pill-t2':'pill-t1'}" style="font-size:9px">${esc(r.replace(/^T[123]-/,''))}</span>`).join('');
      const tags = (s.tags||[]).slice(0,3).map(t => `<span class="tag" style="font-size:9px">${esc(t)}</span>`).join('');
      return `<tr style="border-bottom:1px solid var(--border);cursor:pointer" onmouseover="this.style.background='var(--surface2)'" onmouseout="this.style.background=''" onclick="corpusRowClick('${esc(s.sha256)}')">
        <td style="padding:4px 8px;font-size:10px;color:var(--text-dim);white-space:nowrap">${esc((s.sha256||'').slice(0,16))}…</td>
        <td style="padding:4px 8px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(s.name||'—')}</td>
        <td style="padding:4px 8px;color:var(--text-dim);white-space:nowrap">${(s.first_seen||'').slice(0,10)||'—'}</td>
        <td style="padding:4px 8px;text-align:right" class="${detCls}">${det}</td>
        <td style="padding:4px 8px">${fam}</td>
        <td style="padding:4px 8px">${rules}</td>
        <td style="padding:4px 8px">${tags}</td>
      </tr>`;
    }).join('');
  }

  renderRows();
  document.getElementById('corpus-q').addEventListener('input', e => { filterQ = e.target.value.trim(); renderRows(); });
  el.querySelectorAll('th.ch').forEach(th => {
    th.addEventListener('click', () => {
      if (sortCol === th.dataset.col) sortDir *= -1;
      else { sortCol = th.dataset.col; sortDir = th.dataset.col === 'detections' ? -1 : 1; }
      renderRows();
    });
  });
}

function corpusRowClick(sha256) {
  isTableMode = false;
  document.getElementById('btn-table').classList.remove('active');
  document.getElementById('corpus-wrap').style.display = 'none';
  document.getElementById('family-pills').style.display = '';
  document.getElementById('graph-legend').style.display = '';
  document.getElementById('toolbar').style.display = '';
  if (is3d) document.getElementById('graph-3d').style.display = 'block';
  else document.getElementById('graph-canvas').style.display = 'block';
  const node = gData.nodes.find(n => n.id === 'sample:' + sha256);
  if (node) onNodeClick(node);
}

document.getElementById('btn-3d').addEventListener('click', () => {
  is3d = !is3d;
  const btn = document.getElementById('btn-3d');
  btn.textContent = is3d ? '2D' : '3D';
  btn.classList.toggle('active', is3d);
  if (is3d) {
    if (!graph3d) initGraph3d();
    else { document.getElementById('graph-3d').style.display = 'block'; document.getElementById('graph-canvas').style.display = 'none'; }
  } else {
    document.getElementById('graph-3d').style.display = 'none';
    document.getElementById('graph-canvas').style.display = 'block';
  }
});

document.getElementById('search').addEventListener('input', e => {
  const q = e.target.value.trim().toLowerCase();
  if (!q) { clearHighlight(); return; }
  highlightNodes.clear();
  highlightLinks.clear();
  gData.nodes.forEach(n => {
    const hay = [n.id, n.label, n.family, n.sha256].filter(Boolean).join(' ').toLowerCase();
    if (hay.includes(q)) highlightNodes.add(n.id);
  });
  gData.links.forEach(l => {
    const sid = typeof l.source === 'object' ? l.source.id : l.source;
    const tid = typeof l.target === 'object' ? l.target.id : l.target;
    if (highlightNodes.has(sid) && highlightNodes.has(tid)) highlightLinks.add(l);
  });
  refreshGraphAccessors();
});

// ── Rules section ─────────────────────────────────────────────────────────────
document.getElementById('rules-toggle').addEventListener('click', () => {
  const body = document.getElementById('rules-body');
  const ch   = document.getElementById('rules-chevron');
  const open = body.style.display !== 'none';
  body.style.display = open ? 'none' : 'block';
  ch.classList.toggle('open', !open);
  if (!open && !rulesLoaded) loadRulesList();
});

function loadRulesList() {
  rulesLoaded = true;
  const div = document.getElementById('rules-list');
  div.innerHTML = '<div style="padding:6px 16px;color:var(--text-dim);font-size:11px">Loading…</div>';
  fetch('/api/rules').then(r => r.json()).then(data => {
    const rules = data.rules || [];
    const tierOrder = { T1: 0, T2: 1, T3: 2 };
    rules.sort((a,b) => (tierOrder[a.tier] ?? 9) - (tierOrder[b.tier] ?? 9));
    div.innerHTML = rules.map(r => {
      const count = r.hit_count || 0;
      const badgeCls = count === 0 ? 'hit-badge zero' : r.tier === 'T3' ? 'hit-badge t3' : 'hit-badge';
      const shortName = r.name.replace(/^T[123]-/, '');
      const seedDot = r.seed_status === 'pass'
        ? `<span class="enabled-dot on" title="${r.seed_count} seed(s): all pass"></span>`
        : r.seed_status === 'fail'
        ? `<span class="enabled-dot" style="background:var(--danger)" title="Seeds: fail"></span>`
        : '';
      return `<div class="rule-item" data-name="${esc(r.name)}" title="${esc(r.description)}">
        <span class="pill pill-${r.tier.toLowerCase()}">${esc(r.tier)}</span>
        <span class="rname">${esc(shortName)}</span>${seedDot}
        <span class="${badgeCls}">${count}</span>
      </div>`;
    }).join('');
    div.querySelectorAll('.rule-item').forEach(el => {
      el.addEventListener('click', () => setRuleFilter(el.dataset.name));
      el.addEventListener('dblclick', e => {
        e.stopPropagation();
        openModal(
          'YARA RULES — ' + el.dataset.name,
          'Editing full rules file · scroll position set to selected rule',
          '/api/rules',
          'rule ' + el.dataset.name,
          data.content
        );
      });
    });
  });
}

// ── Providers section ─────────────────────────────────────────────────────────
document.getElementById('providers-toggle').addEventListener('click', () => {
  const body = document.getElementById('providers-body');
  const ch   = document.getElementById('providers-chevron');
  const open = body.style.display !== 'none';
  body.style.display = open ? 'none' : 'block';
  ch.classList.toggle('open', !open);
  if (!open && !providersLoaded) loadProvidersList();
});

function loadProvidersList() {
  providersLoaded = true;
  const div = document.getElementById('providers-list');

  // Build provider stats from graph data (no fetch needed)
  const provNodes = {};
  for (const n of gData.nodes) {
    if (n.type === 'provider') provNodes[n.id] = n.label || n.id.replace('provider:','');
  }
  const sorted = Object.entries(providerSamples)
    .map(([id, sids]) => ({ id, label: provNodes[id] || id.replace('provider:',''), count: sids.size }))
    .sort((a,b) => b.count - a.count);

  if (!sorted.length) {
    div.innerHTML = '<div style="padding:6px 16px;color:var(--text-dim);font-size:11px">No provider data in corpus</div>';
    return;
  }

  div.innerHTML = sorted.map(p =>
    `<div class="provider-item" data-prov-id="${esc(p.id)}">
       <span class="enabled-dot on"></span>
       <span class="pname">${esc(p.label)}</span>
       <span class="hit-badge prov">${p.count}</span>
     </div>`
  ).join('');

  div.querySelectorAll('.provider-item').forEach(el => {
    el.addEventListener('click', () => setProviderFilter(el.dataset.provId));
  });
}

// ── Filters editor section ────────────────────────────────────────────────────
document.getElementById('filters-toggle').addEventListener('click', () => {
  const body = document.getElementById('filters-body');
  const ch   = document.getElementById('filters-chevron');
  const open = body.style.display !== 'none';
  body.style.display = open ? 'none' : 'block';
  ch.classList.toggle('open', !open);
  if (!open && !filtersLoaded) loadFiltersList();
});

function loadFiltersList() {
  filtersLoaded = true;
  const div = document.getElementById('filters-list');
  div.innerHTML = '<div style="padding:6px 16px;color:var(--text-dim);font-size:11px">Loading…</div>';
  fetch('/api/filters').then(r => r.json()).then(data => {
    const filters = data.filters || [];
    div.innerHTML = filters.map(f =>
      `<div class="filter-item" data-slug="${esc(f.slug)}">
         <span class="enabled-dot ${f.enabled ? 'on' : 'off'}" title="${f.enabled ? 'enabled' : 'disabled'}"></span>
         <span class="fname" title="${esc(f.description)}">${esc(f.name)}</span>
       </div>`
    ).join('');
    div.querySelectorAll('.filter-item').forEach(el => {
      el.addEventListener('click', () => {
        openModal(
          'ACQ FILTERS — ' + el.dataset.slug,
          'Editing full filters file · scroll position set to selected filter',
          '/api/filters',
          'slug: ' + el.dataset.slug,
          data.content
        );
      });
    });
  });
}

// ── Editor modal ──────────────────────────────────────────────────────────────
function openModal(title, subtitle, postUrl, scrollTarget, content) {
  document.getElementById('modal-title').textContent = title;
  document.getElementById('modal-subtitle').textContent = subtitle;
  document.getElementById('modal-textarea').value = content;
  document.getElementById('modal-status').textContent = '';
  modalPostUrl = postUrl;
  modalScrollTarget = scrollTarget;
  document.getElementById('editor-modal').classList.add('open');
  setTimeout(() => {
    const ta = document.getElementById('modal-textarea');
    const idx = content.indexOf(scrollTarget);
    if (idx >= 0) {
      ta.setSelectionRange(idx, idx + scrollTarget.length);
      ta.focus();
      const linesBefore = content.slice(0, idx).split('\n').length;
      const lineHeight = 18;
      ta.scrollTop = Math.max(0, (linesBefore - 4) * lineHeight);
    }
  }, 30);
}

document.getElementById('modal-cancel').addEventListener('click', () => {
  document.getElementById('editor-modal').classList.remove('open');
});

document.getElementById('editor-modal').addEventListener('click', e => {
  if (e.target === document.getElementById('editor-modal'))
    document.getElementById('editor-modal').classList.remove('open');
});

document.getElementById('modal-save').addEventListener('click', () => {
  const content = document.getElementById('modal-textarea').value;
  const status  = document.getElementById('modal-status');
  status.textContent = 'Saving…';
  fetch(modalPostUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content }),
  })
  .then(r => r.json())
  .then(data => {
    if (data.ok) {
      document.getElementById('editor-modal').classList.remove('open');
      showToast('Saved to disk', false);
      rulesLoaded = false;
      filtersLoaded = false;
      if (modalPostUrl === '/api/rules'   && document.getElementById('rules-body').style.display !== 'none')   loadRulesList();
      if (modalPostUrl === '/api/filters' && document.getElementById('filters-body').style.display !== 'none') loadFiltersList();
    } else {
      status.textContent = 'Error: ' + (data.error || 'unknown');
      showToast('Save failed: ' + (data.error || 'unknown'), true);
    }
  })
  .catch(e => {
    status.textContent = 'Error: ' + e;
    showToast('Save failed', true);
  });
});

// ── Toast ─────────────────────────────────────────────────────────────────────
let toastTimer = null;
function showToast(msg, isError) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.toggle('error', isError);
  t.classList.add('visible');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('visible'), 2500);
}

// ── Stats ─────────────────────────────────────────────────────────────────────
function updateStats() {
  document.getElementById('stat-samples').textContent  = gData.nodes.filter(n => n.type === 'sample').length;
  document.getElementById('stat-families').textContent = Object.keys(familyColorMap).length;
  document.getElementById('stat-rules').textContent    = gData.nodes.filter(n => n.type === 'yara_rule').length;
  document.getElementById('stat-edges').textContent    = gData.links.length;
}

function updateNodeCount(data) {
  const el = document.getElementById('node-count');
  const empty = data.nodes.length === 0;
  el.textContent = empty ? 'No matching nodes' : `${data.nodes.length} nodes · ${data.links.length} edges`;
  el.style.color = empty ? 'var(--warn)' : '';
}

// ── Detail panel ──────────────────────────────────────────────────────────────
function renderDetailPlaceholder() {
  document.getElementById('detail').innerHTML =
    '<div class="state-message"><strong>No node selected</strong><br>Click a graph node to inspect its relationships and attributes.</div>';
}

function renderDetail(node) {
  if (node.type === 'sample') {
    const sha = node.sha256 || node.id.replace('sample:', '');
    fetch(`/api/sample/${sha}`).then(r => r.json()).then(renderSampleDetail);
  } else {
    renderNodeDetail(node);
  }
}

function renderSampleDetail(d) {
  const det = d.detections || 0;
  const detClass = det >= 30 ? 'det-high' : det >= 10 ? 'det-med' : 'det-low';
  const family = d.family;

  let html = `
  <div class="detail-section">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
      <span class="det-count ${detClass}">${det}</span>
      <div>
        <div style="font-size:11px;color:var(--text-dim)">detections</div>
        ${family ? `<div class="family-badge">${esc(family)}</div>` : ''}
      </div>
    </div>
    <div class="kv-grid">
      <span class="kv-k">SHA256</span><span class="kv-v" style="font-size:10px">${esc(d.sha256)}</span>
      ${d.name ? `<span class="kv-k">Name</span><span class="kv-v">${esc(d.name)}</span>` : ''}
      ${d.file_type ? `<span class="kv-k">Type</span><span class="kv-v">${esc(d.file_type)}</span>` : ''}
      ${d.first_seen ? `<span class="kv-k">First seen</span><span class="kv-v">${d.first_seen.slice(0,10)}</span>` : ''}
    </div>
  </div>`;

  if (d.tags && d.tags.length)
    html += `<div class="detail-section"><h3>Tags</h3>${d.tags.map(t => `<span class="tag">${esc(t)}</span>`).join('')}</div>`;

  if (d.rule_matches && d.rule_matches.length) {
    const sorted = [...d.rule_matches].sort((a,b) => (b.tier||'').localeCompare(a.tier||''));
    html += `<div class="detail-section"><h3>Rule Hits (${sorted.length})</h3>`;
    sorted.forEach(m => {
      const cls = m.tier === 'T3' ? 'pill-t3' : m.tier === 'T2' ? 'pill-t2' : 'pill-t1';
      html += `<span class="pill ${cls}" style="cursor:pointer" onclick="setRuleFilter('${esc(m.rule_name)}')">${esc(m.rule_name)}</span>`;
    });
    html += `</div>`;
  }

  if (d.provider_references && d.provider_references.length) {
    html += `<div class="detail-section"><h3>Providers</h3>`;
    d.provider_references.forEach(p => {
      const provId = 'provider:' + p;
      html += `<span class="tag" style="border-color:var(--warn);color:var(--warn);cursor:pointer" onclick="setProviderFilter('${esc(provId)}')">${esc(p)}</span>`;
    });
    html += `</div>`;
  }

  if (d.embedded_urls && d.embedded_urls.length) {
    html += `<div class="detail-section"><h3>Embedded URLs (${d.embedded_urls.length})</h3><div class="url-list">`;
    d.embedded_urls.slice(0,20).forEach(u => { html += `<div>${esc(u.id || u.url || JSON.stringify(u))}</div>`; });
    if (d.embedded_urls.length > 20) html += `<div style="color:var(--text-dim)">…and ${d.embedded_urls.length-20} more</div>`;
    html += `</div></div>`;
  }

  if (d.pe_info && d.pe_info.imphash) {
    html += `<div class="detail-section"><h3>PE</h3><div class="kv-grid">
      <span class="kv-k">imphash</span><span class="kv-v" style="font-size:10px">${esc(d.pe_info.imphash)}</span>
      ${d.pe_info.timestamp ? `<span class="kv-k">timestamp</span><span class="kv-v">${esc(d.pe_info.timestamp)}</span>` : ''}
    </div></div>`;
  }

  if (d.vt_url)
    html += `<div class="detail-section"><a href="${esc(d.vt_url)}" target="_blank" rel="noopener" class="btn" style="display:inline-block;text-decoration:none;font-size:11px;padding:5px 12px;">Open in VirusTotal ↗</a></div>`;

  if (d.raw_json) {
    let pretty = d.raw_json;
    try { pretty = JSON.stringify(JSON.parse(d.raw_json), null, 2); } catch(e) {}
    html += `<details class="detail-section">
      <summary>Raw JSON</summary>
      <pre class="raw-json-pre">${esc(pretty)}</pre>
    </details>`;
  }

  document.getElementById('detail').innerHTML = html;
}

function renderNodeDetail(node) {
  const typeLabel = node.type.replace(/_/g,' ').toUpperCase();
  let html = `<div class="detail-section"><h3>${typeLabel}</h3><div class="kv-grid">
    <span class="kv-k">Label</span><span class="kv-v">${esc(node.label || node.id)}</span>
    <span class="kv-k">ID</span><span class="kv-v" style="font-size:10px">${esc(node.id)}</span>`;
  if (node.tier)        html += `<span class="kv-k">Tier</span><span class="kv-v">${esc(node.tier)}</span>`;
  if (node.confidence)  html += `<span class="kv-k">Confidence</span><span class="kv-v">${esc(node.confidence)}</span>`;
  if (node.slug)        html += `<span class="kv-k">Slug</span><span class="kv-v">${esc(node.slug)}</span>`;
  if (node.full)        html += `<span class="kv-k">Full</span><span class="kv-v" style="font-size:10px">${esc(node.full)}</span>`;

  // Hit count for rule nodes
  if (node.type === 'yara_rule') {
    const hits = (ruleHitSamples[node.id] || new Set()).size;
    html += `<span class="kv-k">Hits</span><span class="kv-v">${hits} samples</span>`;
  }
  // Sample count for provider nodes
  if (node.type === 'provider') {
    const hits = (providerSamples[node.id] || new Set()).size;
    html += `<span class="kv-k">Samples</span><span class="kv-v">${hits}</span>`;
  }
  // Corpus frequency for submitter nodes
  if (node.type === 'submitter') {
    const cnt = node.corpus_sample_count || 1;
    let signal;
    if      (cnt === 1)  signal = 'rare — strong attribution signal';
    else if (cnt <= 3)   signal = 'uncommon — moderate attribution signal';
    else if (cnt <= 10)  signal = 'common — weak attribution signal';
    else                 signal = 'high-volume — not meaningful for attribution';
    html += `<span class="kv-k">Corpus samples</span><span class="kv-v">${cnt} — ${signal}</span>`;
  }

  html += `</div>`;

  // Quick-filter button for rule/provider nodes
  if (node.type === 'yara_rule') {
    html += `<button class="btn" style="margin-top:8px;width:100%" onclick="setRuleFilter('${esc(node.id.replace('rule:',''))}')">Filter to this rule</button>`;
  }
  if (node.type === 'provider') {
    html += `<button class="btn" style="margin-top:8px;width:100%" onclick="setProviderFilter('${esc(node.id)}')">Filter to this provider</button>`;
  }
  if (node.type === 'submitter') {
    html += `<button class="btn" style="margin-top:8px;width:100%"
      onclick="document.getElementById('submitter-max').value=1;submitterMaxCount=1;applyFilter()">
      Show only rare submitters (≤1)
    </button>`;
  }

  html += `</div>`;
  document.getElementById('detail').innerHTML = html;
}

function esc(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Family report panel controls ─────────────────────────────────────────────
document.getElementById('family-report-close').addEventListener('click', () => setFamilyFilter(null));
document.addEventListener('keydown', e => { if (e.key === 'Escape' && reportPanelOpen) setFamilyFilter(null); });

// ── Resize ────────────────────────────────────────────────────────────────────
// Save and restore viewport so the D3 zoom transform (stored in absolute pixels)
// doesn't shift visually after the canvas is resized.
window.addEventListener('resize', () => {
  const w = document.getElementById('graph-wrap').clientWidth;
  const h = document.getElementById('graph-wrap').clientHeight;
  if (graph2d) {
    const zk = graph2d.zoom();
    const zc = graph2d.centerAt();
    graph2d.width(w).height(h);
    requestAnimationFrame(() => { graph2d.centerAt(zc.x, zc.y, 0); graph2d.zoom(zk, 0); });
  }
  if (graph3d) graph3d.width(w).height(h);
});
</script>
</body>
</html>
"""
