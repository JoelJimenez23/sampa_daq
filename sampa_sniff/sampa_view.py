#!/usr/bin/env python3
"""sampa_view - draw a .bin capture into a self-contained web page.

The equivalent of SAMPA_analyzer's three windows, but without ROOT and with
nothing to install: it writes a single .html file you can open with a double
click and send by email.

    python3 sampa_view.py capture.bin
    python3 sampa_view.py capture.bin -o view.html

The views, each with all 32 channels in an 8x4 grid (one row per link, mirroring
the real split: link = channel // 8):

  - waveform        the highest-amplitude window of each channel
  - amplitude/time  the maximum of each readout, scrolling
  - spectrum        histogram of every ADC value seen
  - peak amplitude  histogram of the max_adc of each packet

A channel disabled in CHEN comes out empty and flagged, which is exactly what
you need to see at a glance when channels are switched off to gain bandwidth.
"""

import argparse
import collections
import json
import os
import sys

from sampa_sniff import Header, unpack_samples, decode, TYPE_NAMES
from sampa_data import _walk

NUM_CHANNELS = 32
PER_LINK = 8
# How many readouts are kept for the amplitude-over-time view. 180, at one
# readout every 100 us, covers 18 ms of physics, and in live mode it is the
# last stretch of screen. That is ~46 KB extra per snapshot.
HISTORY = 180


class Accumulator(object):
    """Accumulates what the views need, packet by packet.

    Both paths use it: sampa_view walking a .bin, and sampa_sniff
    mientras recibe en live. Con un solo acumulador no pueden acabar
    contando cosas distintas.

    Live, this grows without bound (the histograms remember the whole
    corrida), pero son cuentas dispersas: cada channel ve como mucho unos
    cientos de valores ADC distintos, asi que no se dispara.
    """

    def __init__(self, mode="auto", title=""):
        self.mode = mode
        self.title = title
        self.spectrum = [collections.Counter() for _ in range(NUM_CHANNELS)]
        self.peak = [collections.Counter() for _ in range(NUM_CHANNELS)]
        self.wave = [None] * NUM_CHANNELS     # (max_adc, readout, samples)
        # The highest-amplitude window is right for a finished capture, but
        # live it freezes as soon as a spike shows up: we also need the last
        # one, which is the one that moves.
        self.latest = [None] * NUM_CHANNELS   # (readout, samples)
        # Peak amplitude of each readout, for the time view: this is what is
        # seen "drawing itself" as data arrives.
        self.history = [collections.deque(maxlen=HISTORY)
                         for _ in range(NUM_CHANNELS)]
        self.total = collections.Counter()
        self.with_data = collections.Counter()
        self.types = collections.Counter()
        self.problems = collections.Counter()
        self.packets = 0
        self.readouts = 0
        self.bytes = 0

    def add(self, n, rd, header, samples, problem, nbytes=0):
        self.packets = n
        self.readouts = rd + 1
        self.bytes += nbytes
        ch = header.chanadd
        self.types[header.type] += 1
        if problem:
            self.problems[problem] += 1
        if ch >= NUM_CHANNELS:
            return
        self.total[ch] += 1
        _fmt, clusters = decode(header, samples, self.mode)
        body = []
        for _t0, chunk, _s in clusters:
            if chunk is not None:
                body.extend(chunk)
        if not body:
            return
        self.with_data[ch] += 1
        e = self.spectrum[ch]
        for v in body:
            e[v] += 1
        amax = max(body)
        self.peak[ch][amax] += 1
        # Keep the highest-amplitude window, which is the interesting one.
        # The original analyzer keeps "the last one over a threshold", but
        # with background noise that leaves the cell blank.
        if self.wave[ch] is None or amax > self.wave[ch][0]:
            self.wave[ch] = (amax, rd, body)
        self.latest[ch] = (rd, body)
        self.history[ch].append((rd, amax))

    def snapshot(self):
        """The current state, ready to be turned into JSON."""
        channels = []
        for ch in range(NUM_CHANNELS):
            t = self.total.get(ch, 0)
            d = self.with_data.get(ch, 0)
            esp = self.spectrum[ch]
            base = ""
            if esp:
                # The baseline is the most repeated value: at rest the channel
                # sits there and pulses are a minority of the samples.
                base = esp.most_common(1)[0][0]
            channels.append({
                "ch": ch,
                "link": ch // PER_LINK,
                "n": t,
                "data": d,
                "pct": round(100.0 * d / t, 1) if t else 0.0,
                "base": base,
                "max": max(self.peak[ch]) if self.peak[ch] else "",
                "wave": self.wave[ch][2] if self.wave[ch] else [],
                "wave_readout": self.wave[ch][1] if self.wave[ch] else "",
                "latest": self.latest[ch][1] if self.latest[ch] else [],
                "latest_readout": self.latest[ch][0] if self.latest[ch] else "",
                "hist": [list(x) for x in self.history[ch]],
                "esp": sorted(esp.items()),
                "pul": sorted(self.peak[ch].items()),
            })
        return {
            "file": self.title,
            "bytes": self.bytes,
            "packets": self.packets,
            "readouts": self.readouts,
            "ms": round(self.readouts * 0.1, 1),
            "types": [[t, TYPE_NAMES.get(t, "?"), c]
                      for t, c in sorted(self.types.items())],
            "problems": [[m, c] for m, c in self.problems.most_common()],
            "channels": channels,
        }


def analyse(path, mode="auto"):
    """Walk the .bin once and extract what the views need."""
    acc = Accumulator(mode, os.path.basename(path))
    for n, rd, header, samples, problem in _walk(path, mode):
        acc.add(n, rd, header, samples, problem)
    acc.bytes = os.path.getsize(path)
    return acc.snapshot()


PAGINA = u"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SAMPA - @@FILE@@</title>
<style>
:root{--fondo:#fbfbfa;--paper:#fff;--ink:#1a1a18;--soft:#6b6b66;
      --line:#e2e2dd;--trace:#2f6f8f;--accent:#b4713d;--dead:#c9c9c4;
      --veil:rgba(26,26,24,.55);--reja:#eeeeea;--accent-tenue:#e4eef3}
@mean (prefers-color-scheme:dark){:root{--fondo:#16161a;--paper:#1e1e23;
      --ink:#e8e8e4;--soft:#9a9a94;--line:#33333a;--trace:#6fb3d2;
      --accent:#d99a63;--dead:#4a4a52;--veil:rgba(0,0,0,.7);--reja:#2a2a31;
      --accent-tenue:#22323b}}
*{box-sizing:border-box}
body{margin:0;background:var(--fondo);color:var(--ink);
     font:14px/1.5 ui-sans-serif,system-ui,"Segoe UI",Helvetica,Arial,sans-serif}
.env{max-width:1400px;margin:0 auto;padding:28px 20px 60px}
h1{font-size:20px;margin:0 0 4px;font-weight:600}
h2{font-size:15px;margin:36px 0 4px;font-weight:600}
p.sub{color:var(--soft);margin:0 0 6px;font-size:13px}
.header{border-bottom:1px solid var(--line);padding-bottom:18px}
.data{display:flex;flex-wrap:wrap;gap:10px 28px;margin-top:12px;
       font-variant-numeric:tabular-nums}
.data div{font-size:13px}
.data b{display:block;font-size:18px;font-weight:600}
.data span{color:var(--soft)}
.grid{display:grid;grid-template-columns:repeat(8,1fr);gap:8px;margin-top:14px}
@mean(max-width:1100px){.grid{grid-template-columns:repeat(4,1fr)}}
@mean(max-width:600px){.grid{grid-template-columns:repeat(2,1fr)}}
.cell{background:var(--paper);border:1px solid var(--line);border-radius:6px;
       padding:6px 6px 4px;overflow:hidden;cursor:pointer;
       transition:border-color .12s,transform .12s}
.cell:hover{border-color:var(--trace);transform:translateY(-1px)}
.cell.off{opacity:.5}
.cell.off:hover{opacity:.8}
.cell:focus-visible{outline:2px solid var(--trace);outline-offset:1px}
#mode-wave{display:inline-flex;border:1px solid var(--line);border-radius:5px;
  overflow:hidden;margin-left:10px;vertical-align:middle}
#mode-wave[hidden]{display:none}
#mode-wave button{background:none;border:0;color:var(--soft);font:inherit;
  font-size:12px;padding:2px 10px;cursor:pointer}
#mode-wave button+button{border-left:1px solid var(--line)}
#mode-wave button.activo{background:var(--accent-tenue);color:var(--trace)}
.tit{font-size:11px;color:var(--soft);display:flex;justify-content:space-between;
     font-variant-numeric:tabular-nums}
.tit b{color:var(--ink);font-weight:600}
canvas{width:100%;height:74px;display:block}
table{border-collapse:collapse;margin-top:14px;font-size:13px;
      font-variant-numeric:tabular-nums}
th,td{padding:4px 12px 4px 0;text-align:right;border-bottom:1px solid var(--line)}
th{color:var(--soft);font-weight:500;text-align:right}
th:first-child,td:first-child{text-align:left}
td.off{color:var(--dead)}
.note{background:var(--paper);border:1px solid var(--line);border-left:3px solid
       var(--accent);border-radius:4px;padding:10px 14px;margin-top:14px;font-size:13px}
code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}

/* --- board status (daqstat over ssh) --- */
#board{display:none;margin-top:6px}
#board.on{display:block}
.pastilla{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;
          font-weight:600}
.pastilla.si{background:var(--accent-tenue);color:var(--trace)}
.pastilla.no{color:var(--dead);border:1px solid var(--line)}
td.bad{color:var(--accent);font-weight:600}
#daq-raw{margin-top:12px;font-size:12px}
#daq-raw pre{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11px;
               line-height:1.45;overflow-x:auto;background:var(--paper);
               border:1px solid var(--line);border-radius:4px;padding:10px}
#daq-raw summary{cursor:pointer;color:var(--soft)}

/* --- modal window --- */
#veil{position:fixed;inset:0;background:var(--veil);display:none;z-index:50;
      align-items:center;justify-content:center;padding:20px}
#veil.abierto{display:flex}
#panel{background:var(--paper);border:1px solid var(--line);border-radius:10px;
       width:min(1100px,100%);max-height:100%;display:flex;flex-direction:column;
       box-shadow:0 12px 40px rgba(0,0,0,.28)}
#bar{display:flex;align-items:center;gap:14px;padding:12px 16px;
       border-bottom:1px solid var(--line)}
#bar h3{margin:0;font-size:15px;font-weight:600;flex:1}
#bar .meta{color:var(--soft);font-size:12px;font-variant-numeric:tabular-nums}
#bar button{background:none;border:1px solid var(--line);color:var(--ink);
      border-radius:5px;padding:3px 9px;font-size:12px;cursor:pointer;
      font-family:inherit}
#bar button:hover{border-color:var(--trace);color:var(--trace)}
#grande{width:100%;height:min(56vh,460px);display:block;cursor:crosshair;
        touch-action:none}
#pie{padding:8px 16px 12px;color:var(--soft);font-size:12px;
     border-top:1px solid var(--line);display:flex;justify-content:space-between;
     gap:12px;flex-wrap:wrap}
#readout{font-variant-numeric:tabular-nums;color:var(--ink)}
kbd{font-family:inherit;border:1px solid var(--line);border-radius:3px;
    padding:0 4px;font-size:11px}

/* --- bar de estado en live --- */
#live{position:fixed;right:16px;bottom:16px;z-index:40;display:flex;
      align-items:center;gap:10px;background:var(--paper);
      border:1px solid var(--line);border-radius:20px;padding:7px 14px;
      font-size:12.5px;font-variant-numeric:tabular-nums;
      box-shadow:0 4px 16px rgba(0,0,0,.16)}
#live[hidden]{display:none}
#live button{background:none;border:1px solid var(--line);color:var(--ink);
      border-radius:12px;padding:2px 10px;font:inherit;font-size:12px;
      cursor:pointer}
#live button:hover{border-color:var(--trace);color:var(--trace)}
#spark{width:74px;height:20px;display:block}
.beat{width:8px;height:8px;border-radius:50%;background:var(--trace);
        animation:latir 1.6s ease-in-out infinite}
.beat.parado{background:var(--dead);animation:none}
.beat.caido{background:var(--accent);animation:none}
@keyframes latir{0%,100%{opacity:1}50%{opacity:.25}}
@mean (prefers-reduced-motion:reduce){.beat{animation:none}}
</style></head><body><div class="env">

<div class="header">
<h1 id="title-pag">@@FILE@@</h1>
<p class="sub" id="sub-cab"></p>
<div class="data" id="resumen"></div>
</div>

<h2>Waveform<span id="mode-wave" hidden><button data-mode="latest">latest</button><button data-mode="wave">highest amplitude</button></span></h2>
<p class="sub">The highest-amplitude window of each channel. x axis: sample
number (0.1 &micro;s each). The thin line is the baseline.
<b>Pulsa cualquier recuadro stop verlo en grande.</b></p>
<div class="grid" id="g-wave"></div>

<h2>ADC value spectrum</h2>
<p class="sub">How often each converter code appeared. A channel at
rest gives a narrow peak at its baseline.</p>
<div class="grid" id="g-esp"></div>

<h2>Amplitude over time</h2>
<p class="sub">The peak amplitude of each readout, in arrival order. This is the
view that draws itself: when a new readout arrives, the trace advances one
step to the right.</p>
<div class="grid" id="g-tmp"></div>

<h2>Peak amplitude per packet</h2>
<p class="sub">Histogram of the highest value of each window. This is the view that
separates channels carrying signal from channels sitting in noise.</p>
<div class="grid" id="g-pul"></div>

<h2>Per-channel summary</h2>
<div id="tabla"></div>

<div id="board">
<h2>Board status</h2>
<p class="sub">What <code>daqstat</code> answers on the board, over ssh. It
refresca solo. Esto no viene por el puerto 1000: es una consulta aparte.</p>
<div class="data" id="daq-summary"></div>
<div id="daq-table"></div>
<div id="daq-notes"></div>
<details id="daq-raw"><summary>show the raw dump</summary><pre></pre></details>
</div>

</div>

<div id="live" hidden>
  <span class="beat" id="beat"></span>
  <canvas id="spark" title="packets per second, last minute"></canvas>
  <span id="live-txt">conectando&hellip;</span>
  <button id="btPause">pause</button>
</div>

<div id="veil"><div id="panel">
  <div id="bar">
    <h3 id="title"></h3>
    <span class="meta" id="meta"></span>
    <button id="btPrev" title="previous channel">&larr;</button>
    <button id="btNext" title="next channel">&rarr;</button>
    <button id="btReset">reset zoom</button>
    <button id="btClose">close</button>
  </div>
  <canvas id="grande"></canvas>
  <div id="pie">
    <span id="readout">&nbsp;</span>
    <span><kbd>wheel</kbd> zoom &middot; <kbd>drag</kbd> pan &middot;
      <kbd>doble clic</kbd> resetZoom &middot; <kbd>&larr;</kbd><kbd>&rarr;</kbd>
      channel &middot; <kbd>Esc</kbd> closeModal</span>
  </div>
</div></div>

<script id="data" type="application/json">@@JSON@@</script>
<script>
const LIVE = @@LIVE@@;
const REDUCIR = matchMedia("(prefers-reduced-motion: reduce)").matches;
let D = null;
const css = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();

const TITLES = {wave:"Waveform", tmp:"Amplitude over time",
                esp:"ADC spectrum", pul:"Peak amplitude"};
const XAXIS = {wave:"sample number", tmp:"numero de readout",
              esp:"ADC code", pul:"ADC code"};
const YAXIS = {wave:"ADC code", tmp:"ADC code", esp:"count", pul:"count"};
const TIPOS = ["wave", "tmp", "esp", "pul"];

/* Live, the latest window is what matters because it changes; in a closed
   capture, the highest-amplitude one. The two can be toggled. */
let modoOnda = LIVE ? "latest" : "wave";

function series(type, k) {
  if (type === "wave") {
    const v = k[modoOnda] || [];
    return v.map((y, i) => [i, y]);
  }
  if (type === "tmp") return k.hist || [];
  return type === "esp" ? k.esp : k.pul;
}

/* ---------- grids: created once and reused ----------

   Previously all 96 cells were rebuilt on every update. That flickered and
   threw away the browser's work. Now only the data inside them changes. */

let cells = null;

function createGrids() {
  cells = {wave:[], tmp:[], esp:[], pul:[]};
  for (const [id, type] of [["g-wave","wave"], ["g-tmp","tmp"],
                            ["g-esp","esp"], ["g-pul","pul"]]) {
    const cont = document.getElementById(id);
    cont.textContent = "";
    for (let ch = 0; ch < 32; ch++) {
      const div = document.createElement("div");
      div.className = "cell";
      div.tabIndex = 0;
      const tit = document.createElement("div");
      tit.className = "tit";
      const b = document.createElement("b"); b.textContent = "ch " + ch;
      const sp = document.createElement("span");
      tit.append(b, sp);
      const c = document.createElement("canvas");
      div.append(tit, c);
      cont.appendChild(div);
      const abrelo = () => openModal(type, ch);
      div.onclick = abrelo;
      div.onkeydown = e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); abrelo(); } };
      cells[type].push({div, sp, c, g:null, W:0, H:0,
                         cur:new Map(), wave:null, k:null, dirty:true});
    }
  }
  layout();
}

function layout() {
  const r = window.devicePixelRatio || 1;
  for (const type of TIPOS) for (const cel of cells[type]) {
    cel.W = cel.c.clientWidth; cel.H = cel.c.clientHeight;
    cel.c.width = Math.max(1, Math.round(cel.W * r));
    cel.c.height = Math.max(1, Math.round(cel.H * r));
    cel.g = cel.c.getContext("2d");
    cel.g.setTransform(r, 0, 0, r, 0, 0);
    cel.dirty = true;
  }
}

/* Reduce the samples to one column per pixel: minimum, maximum and mean.

   With 1000 samples in 150 px there are seven per column, and drawing them
   as a polyline gives a tangle of vertical strokes. The usual way to draw
   this is a band between the minimum and the maximum with the mean on top:
   you see the envelope of the noise and you see the centre, which is what
   matters. */
function columns(ys, x0, x1, ancho) {
  const a = Math.max(0, Math.ceil(x0)), b = Math.min(ys.length - 1, Math.floor(x1));
  if (b < a) return null;
  const n = b - a + 1;
  /* The criterion is how much room there is per sample. With two pixels or
     more the real line can be drawn; below that, samples overlap and must be
     grouped. Each band column takes two pixels, so it always groups two or
     more samples and the band means something. */
  if (ancho >= n * 2) return null;
  const cols = Math.max(1, Math.min(Math.floor(ancho / 2), n));
  const step = n / cols;
  const out = [];
  for (let i = 0; i < cols; i++) {
    const p = a + Math.floor(i * step), q = Math.min(b + 1, a + Math.floor((i + 1) * step));
    let lo = Infinity, hi = -Infinity, sum = 0, c = 0;
    for (let j = p; j < q; j++) {
      const y = ys[j];
      if (y < lo) lo = y;
      if (y > hi) hi = y;
      sum += y; c++;
    }
    if (!c) continue;
    out.push({x: p, lo: lo, hi: hi, med: sum / c});
  }
  return out.length ? out : null;
}

/* ---------- drawing the thumbnails ---------- */

const SUAVE = 0.22;        // cuanto se acerca un histograma a su objetivo

function drawCell(cel, type) {
  const g = cel.g, W = cel.W, H = cel.H, k = cel.k;
  if (!g || !k) return false;

  if (type === "wave") {
    if (!cel.dirty) return false;
    cel.dirty = false;
    g.clearRect(0, 0, W, H);
    const ys = cel.wave;
    if (!ys || !ys.length) return false;
    let lo = Infinity, hi = -Infinity;
    for (const y of ys) { if (y < lo) lo = y; if (y > hi) hi = y; }
    if (hi - lo < 8) { const m = (hi + lo) / 2; lo = m - 4; hi = m + 4; }
    const py = v => H - 3 - (v - lo) / (hi - lo) * (H - 6);
    if (k.base !== "" && k.base >= lo && k.base <= hi) {
      g.strokeStyle = css("--line"); g.lineWidth = 1;
      g.beginPath(); g.moveTo(0, py(k.base)); g.lineTo(W, py(k.base)); g.stroke();
    }
    const cols = columns(ys, 0, ys.length - 1, Math.round(W));
    const px = i => i / Math.max(1, ys.length - 1) * W;
    if (cols) {
      g.fillStyle = css("--accent-tenue");
      g.beginPath();
      for (const c of cols) g.lineTo(px(c.x), py(c.hi));
      for (let i = cols.length - 1; i >= 0; i--) g.lineTo(px(cols[i].x), py(cols[i].lo));
      g.closePath(); g.fill();
      g.strokeStyle = css("--trace"); g.lineWidth = 1;
      g.beginPath();
      cols.forEach((c, i) => i ? g.lineTo(px(c.x), py(c.med)) : g.moveTo(px(c.x), py(c.med)));
      g.stroke();
    } else {
      g.strokeStyle = css("--trace"); g.lineWidth = 1;
      g.beginPath();
      ys.forEach((y, i) => i ? g.lineTo(px(i), py(y)) : g.moveTo(0, py(y)));
      g.stroke();
    }
    return false;
  }

  if (type === "tmp") {
    if (!cel.dirty) return false;
    cel.dirty = false;
    g.clearRect(0, 0, W, H);
    const h = k.hist || [];
    if (h.length < 2) return false;
    let lo = Infinity, hi = -Infinity;
    for (const [, v] of h) { if (v < lo) lo = v; if (v > hi) hi = v; }
    if (hi - lo < 6) { const m = (hi + lo) / 2; lo = m - 3; hi = m + 3; }
    const x0 = h[0][0], x1 = h[h.length - 1][0];
    const anc = Math.max(x1 - x0, 1);
    const px = v => (v - x0) / anc * W;
    const py = v => H - 3 - (v - lo) / (hi - lo) * (H - 6);
    g.fillStyle = css("--accent-tenue");
    g.beginPath(); g.moveTo(px(h[0][0]), H);
    for (const [x, v] of h) g.lineTo(px(x), py(v));
    g.lineTo(px(x1), H); g.closePath(); g.fill();
    g.strokeStyle = css("--trace"); g.lineWidth = 1;
    g.beginPath();
    h.forEach(([x, v], i) => i ? g.lineTo(px(x), py(v)) : g.moveTo(px(x), py(v)));
    g.stroke();
    /* The dot at the end marks where it is: that is what gives the feeling
       of the trace advancing rather than being repainted whole. */
    g.fillStyle = css("--trace");
    g.beginPath(); g.arc(px(x1), py(h[h.length - 1][1]), 2.2, 0, 6.284); g.fill();
    return false;
  }

  /* Histograms: the bars grow gradually towards their new value instead of
     dar un salto. Se sigue dibujando mientras alguna no haya llegado. */
  const pares = type === "esp" ? k.esp : k.pul;
  const obj = new Map(pares);
  let mueve = false;
  for (const [v, n] of obj) {
    const a = cel.cur.get(v) || 0;
    const b = REDUCIR ? n : a + (n - a) * SUAVE;
    if (Math.abs(n - b) > 0.5) mueve = true;
    cel.cur.set(v, b);
  }
  g.clearRect(0, 0, W, H);
  if (!cel.cur.size) return false;
  const xs = [...cel.cur.keys()];
  const x0 = Math.min(...xs), x1 = Math.max(...xs);
  const anc = Math.max(x1 - x0, 1);
  let alto = 0;
  for (const v of cel.cur.values()) if (v > alto) alto = v;
  if (alto <= 0) return mueve;
  const w = Math.max(W / (anc + 1), 1);
  g.fillStyle = css("--trace");
  for (const [v, n] of cel.cur) {
    const h = (n / alto) * (H - 6);
    if (h > 0.2) g.fillRect((v - x0) / anc * (W - w), H - 3 - h, w, h);
  }
  g.fillStyle = css("--soft"); g.font = "9px system-ui";
  g.fillText(x0, 1, H - 0.5);
  const t = "" + x1;
  g.fillText(t, W - g.measureText(t).width - 1, H - 0.5);
  return mueve;
}

/* ---------- the drawing loop ---------- */

let pintando = false;

function bucle() {
  let queda = false;
  for (const type of TIPOS) for (const cel of cells[type])
    if (drawCell(cel, type)) queda = true;
  if (V.type) { draw(); queda = true; }
  if (queda) requestAnimationFrame(bucle);
  else pintando = false;
}

function anima() {
  if (pintando) return;
  pintando = true;
  requestAnimationFrame(bucle);
}

/* ---------- the large window ---------- */

const V = {type:null, ch:0, x0:0, x1:1, pts:[], cursor:null};
const cv = document.getElementById("grande");
const MI = {left:58, right:16, arr:14, aba:34};

function openModal(type, ch) {
  V.type = type; V.ch = ch;
  V.pts = series(type, D.channels[ch]);
  resetZoom();
  document.getElementById("veil").classList.add("abierto");
  draw(); anima();
}

function resetZoom() {
  if (!V.pts.length) { V.x0 = 0; V.x1 = 1; return; }
  V.x0 = V.pts[0][0];
  V.x1 = V.pts[V.pts.length - 1][0];
  if (V.x1 === V.x0) V.x1 = V.x0 + 1;
}

function closeModal() {
  document.getElementById("veil").classList.remove("abierto");
  V.type = null;
}

function step(d) { if (V.type) openModal(V.type, (V.ch + d + 32) % 32); }

function draw() {
  if (!V.type) return;
  const k = D.channels[V.ch];
  document.getElementById("title").textContent =
    TITLES[V.type] + " - channel " + V.ch;
  document.getElementById("meta").textContent =
    "link " + k.link + " | " + k.data + "/" + k.n + " packets with data ("
    + k.pct + "%)" + (k.base !== "" ? " | base " + k.base : "");

  const r = window.devicePixelRatio || 1;
  const W = cv.clientWidth, H = cv.clientHeight;
  if (cv.width !== Math.round(W * r)) {
    cv.width = Math.round(W * r); cv.height = Math.round(H * r);
  }
  const g = cv.getContext("2d");
  g.setTransform(r, 0, 0, r, 0, 0);
  g.clearRect(0, 0, W, H);

  if (!V.pts.length) {
    g.fillStyle = css("--soft"); g.font = "13px system-ui";
    g.fillText("this channel carried no samples at all", MI.left, H / 2);
    return;
  }

  const dentro = V.pts.filter(p => p[0] >= V.x0 && p[0] <= V.x1);
  const vis = dentro.length ? dentro : V.pts;
  const cel = cells[V.type][V.ch];
  let ylo = Infinity, yhi = -Infinity;
  for (const p of vis) { if (p[1] < ylo) ylo = p[1]; if (p[1] > yhi) yhi = p[1]; }
  if (V.type !== "wave") ylo = 0;
  if (!isFinite(ylo)) { ylo = 0; yhi = 1; }
  if (yhi - ylo < 4) { const m = (yhi + ylo) / 2; ylo = m - 2; yhi = m + 2; }
  const pad = (yhi - ylo) * 0.08; ylo -= pad; yhi += pad;

  const AX = W - MI.left - MI.right, AY = H - MI.arr - MI.aba;
  const px = x => MI.left + (x - V.x0) / (V.x1 - V.x0) * AX;
  const py = y => MI.arr + AY - (y - ylo) / (yhi - ylo) * AY;

  g.strokeStyle = css("--reja"); g.fillStyle = css("--soft");
  g.font = "11px ui-monospace,monospace"; g.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = ylo + (yhi - ylo) * i / 4, Y = Math.round(py(y)) + 0.5;
    g.beginPath(); g.moveTo(MI.left, Y); g.lineTo(W - MI.right, Y); g.stroke();
    const t = (Math.abs(y) >= 100 ? y.toFixed(0) : y.toFixed(1));
    g.fillText(t, MI.left - 6 - g.measureText(t).width, Y + 4);
  }
  for (let i = 0; i <= 5; i++) {
    const x = V.x0 + (V.x1 - V.x0) * i / 5, X = Math.round(px(x)) + 0.5;
    g.beginPath(); g.moveTo(X, MI.arr); g.lineTo(X, MI.arr + AY); g.stroke();
    const t = (V.x1 - V.x0 > 20 ? x.toFixed(0) : x.toFixed(1));
    g.fillText(t, X - g.measureText(t).width / 2, MI.arr + AY + 16);
  }
  g.fillText(XAXIS[V.type], W - MI.right - g.measureText(XAXIS[V.type]).width,
             MI.arr + AY + 30);
  g.fillText(YAXIS[V.type], MI.left - 52, MI.arr - 3);

  if (V.type === "wave" && k.base !== "" && k.base >= ylo && k.base <= yhi) {
    g.strokeStyle = css("--accent"); g.setLineDash([4, 4]);
    g.beginPath(); g.moveTo(MI.left, py(k.base)); g.lineTo(W - MI.right, py(k.base));
    g.stroke(); g.setLineDash([]);
  }

  g.save();
  g.beginPath(); g.rect(MI.left, MI.arr, AX, AY); g.clip();
  if (V.type === "wave") {
    /* With 1000 noise samples in 900 px, a polyline is a tangle of vertical
       strokes. Draw the min-max band in a soft tone with the mean on top:
       you see the envelope and you see the centre. Zoom in far enough and
       there is room for the real samples, so it switches to a line. */
    const cols = columns(cel.wave || [], V.x0, V.x1, Math.round(AX));
    if (cols) {
      g.fillStyle = css("--accent-tenue");
      g.beginPath();
      for (const c of cols) g.lineTo(px(c.x), py(c.hi));
      for (let i = cols.length - 1; i >= 0; i--) g.lineTo(px(cols[i].x), py(cols[i].lo));
      g.closePath(); g.fill();
      g.strokeStyle = css("--trace"); g.lineWidth = 1.4;
      g.beginPath();
      cols.forEach((c, i) => i ? g.lineTo(px(c.x), py(c.med))
                               : g.moveTo(px(c.x), py(c.med)));
      g.stroke();
    } else {
      g.strokeStyle = css("--trace"); g.lineWidth = 1.5;
      g.beginPath();
      vis.forEach((p, j) => j ? g.lineTo(px(p[0]), py(p[1]))
                              : g.moveTo(px(p[0]), py(p[1])));
      g.stroke();
      if (vis.length < 160) {
        g.fillStyle = css("--trace");
        for (const p of vis) { g.beginPath(); g.arc(px(p[0]), py(p[1]), 2, 0, 6.284); g.fill(); }
      }
    }
  } else if (V.type === "tmp") {
    g.fillStyle = css("--accent-tenue");
    g.beginPath(); g.moveTo(px(vis[0][0]), py(ylo));
    for (const p of vis) g.lineTo(px(p[0]), py(p[1]));
    g.lineTo(px(vis[vis.length - 1][0]), py(ylo)); g.closePath(); g.fill();
    g.strokeStyle = css("--trace"); g.lineWidth = 1.5;
    g.beginPath();
    vis.forEach((p, i) => i ? g.lineTo(px(p[0]), py(p[1]))
                            : g.moveTo(px(p[0]), py(p[1])));
    g.stroke();
    if (vis.length < 160) {
      g.fillStyle = css("--trace");
      for (const p of vis) { g.beginPath(); g.arc(px(p[0]), py(p[1]), 2, 0, 6.284); g.fill(); }
    }
  } else {
    g.fillStyle = css("--trace");
    const w = Math.max(AX / (V.x1 - V.x0 + 1) - 1, 1);
    for (const p of vis) {
      const alto = cel.cur.get(p[0]);
      const y = alto === undefined ? p[1] : alto;
      g.fillRect(px(p[0]) - w / 2, py(y), w, py(ylo) - py(y));
    }
  }
  g.restore();

  const sal = document.getElementById("readout");
  if (V.cursor !== null && V.cursor >= MI.left && V.cursor <= W - MI.right) {
    const xd = V.x0 + (V.cursor - MI.left) / AX * (V.x1 - V.x0);
    let mej = null;
    for (const p of vis)
      if (mej === null || Math.abs(p[0] - xd) < Math.abs(mej[0] - xd)) mej = p;
    if (mej) {
      g.strokeStyle = css("--accent"); g.lineWidth = 1;
      g.beginPath(); g.moveTo(px(mej[0]), MI.arr); g.lineTo(px(mej[0]), MI.arr + AY);
      g.stroke();
      g.fillStyle = css("--accent");
      g.beginPath(); g.arc(px(mej[0]), py(mej[1]), 3.5, 0, 6.284); g.fill();
      const rd = modoOnda === "latest" ? k.latest_readout : k.wave_readout;
      sal.textContent =
        V.type === "wave" ? "sample " + mej[0] + "  ->  ADC " + mej[1]
            + "   (t = " + (rd * 100 + mej[0] * 0.1).toFixed(1) + " us)"
      : V.type === "tmp"  ? "readout " + mej[0] + "  ->  max_adc " + mej[1]
            + "   (t = " + (mej[0] * 0.1).toFixed(1) + " ms)"
      : "ADC " + mej[0] + "  ->  " + mej[1] + " veces";
    }
  } else {
    sal.innerHTML = "&nbsp;";
  }
}

/* ---------- interaction in the large window ---------- */

cv.addEventListener("wheel", e => {
  e.preventDefault();
  if (!V.pts.length) return;
  const AX = cv.clientWidth - MI.left - MI.right;
  const f = e.deltaY > 0 ? 1.25 : 0.8;
  const xr = cv.getBoundingClientRect();
  const xd = V.x0 + Math.max(0, Math.min(1, (e.clientX - xr.left - MI.left) / AX))
             * (V.x1 - V.x0);
  let a = xd - (xd - V.x0) * f, b = xd + (V.x1 - xd) * f;
  const lim0 = V.pts[0][0], lim1 = V.pts[V.pts.length - 1][0];
  if (b - a > lim1 - lim0) { a = lim0; b = lim1; }
  if (b - a < 2) return;
  V.x0 = Math.max(a, lim0); V.x1 = Math.min(b, lim1);
  draw();
}, {passive:false});

let arrastre = null;
cv.addEventListener("pointerdown", e => {
  if (!V.pts.length) return;
  arrastre = {x:e.clientX, x0:V.x0, x1:V.x1};
  cv.setPointerCapture(e.pointerId);
});
cv.addEventListener("pointermove", e => {
  const xr = cv.getBoundingClientRect();
  V.cursor = e.clientX - xr.left;
  if (arrastre) {
    const AX = cv.clientWidth - MI.left - MI.right;
    const d = (e.clientX - arrastre.x) / AX * (arrastre.x1 - arrastre.x0);
    const lim0 = V.pts[0][0], lim1 = V.pts[V.pts.length - 1][0];
    let a = arrastre.x0 - d, b = arrastre.x1 - d;
    if (a < lim0) { b += lim0 - a; a = lim0; }
    if (b > lim1) { a -= b - lim1; b = lim1; }
    V.x0 = Math.max(a, lim0); V.x1 = Math.min(b, lim1);
  }
  draw();
});
cv.addEventListener("pointerup", () => { arrastre = null; });
cv.addEventListener("pointerleave", () => { V.cursor = null; draw(); });
cv.addEventListener("dblclick", () => { resetZoom(); draw(); });

document.getElementById("btClose").onclick = closeModal;
document.getElementById("btReset").onclick = () => { resetZoom(); draw(); };
document.getElementById("btPrev").onclick = () => step(-1);
document.getElementById("btNext").onclick = () => step(1);
document.getElementById("veil").onclick = e => { if (e.target.id === "veil") closeModal(); };
document.addEventListener("keydown", e => {
  if (!V.type) return;
  if (e.key === "Escape") closeModal();
  else if (e.key === "ArrowLeft") step(-1);
  else if (e.key === "ArrowRight") step(1);
  else return;
  e.preventDefault();
});
let redim = null;
window.addEventListener("resize", () => {
  clearTimeout(redim);
  redim = setTimeout(() => { layout(); anima(); draw(); }, 150);
});

/* ---------- toggling which waveform is shown ---------- */

const selOnda = document.getElementById("mode-wave");
selOnda.hidden = false;
for (const b of selOnda.querySelectorAll("button")) {
  b.onclick = () => {
    modoOnda = b.dataset.mode;
    for (const x of selOnda.querySelectorAll("button"))
      x.classList.toggle("activo", x === b);
    for (const cel of cells.wave) {
      const v = cel.k ? (cel.k[modoOnda] || []) : [];
      cel.wave = v.length ? v : null;
      cel.dirty = true;
    }
    if (V.type === "wave") { V.pts = series("wave", D.channels[V.ch]); resetZoom(); }
    anima(); draw();
  };
  b.classList.toggle("activo", b.dataset.mode === modoOnda);
}

/* ---------- montaje ---------- */

function montar(nuevo) {
  const primera = cells === null;
  D = nuevo;
  if (primera) createGrids();

  document.getElementById("title-pag").textContent = D.file;
  document.getElementById("sub-cab").textContent =
    D.packets.toLocaleString("es") + " packets · " +
    D.readouts.toLocaleString("es") + " readouts · " +
    D.ms + " ms de toma · " +
    (D.bytes / 1048576).toFixed(1) + " MB";

  for (const type of TIPOS) for (let ch = 0; ch < 32; ch++) {
    const cel = cells[type][ch], k = D.channels[ch];
    const antes = cel.k;
    cel.k = k;
    cel.div.classList.toggle("off", k.pct === 0);
    if (type === "wave") {
      const v = k[modoOnda] || [];
      const rd = modoOnda === "latest" ? k.latest_readout : k.wave_readout;
      const lecAntes = antes && (modoOnda === "latest" ? antes.latest_readout
                                                       : antes.wave_readout);
      if (v.length && (!antes || rd !== lecAntes)) {
        cel.wave = v;
        cel.dirty = true;
      } else if (v.length && !cel.wave) {
        cel.wave = v; cel.dirty = true;
      }
      cel.sp.textContent = v.length ? "rd " + rd : "no data";
    } else if (type === "tmp") {
      const h = k.hist || [];
      const fin = h.length ? h[h.length - 1][0] : null;
      const finAntes = antes && antes.hist && antes.hist.length
                     ? antes.hist[antes.hist.length - 1][0] : null;
      if (fin !== finAntes) cel.dirty = true;
      cel.sp.textContent = h.length ? h.length + " rd" : "no data";
    } else if (type === "esp") {
      cel.sp.textContent = k.base !== "" ? "base " + k.base : "";
    } else {
      cel.sp.textContent = k.max !== "" ? "max " + k.max : "";
    }
  }

  const active = D.channels.filter(k => k.pct > 0);
  const dead = D.channels.filter(k => k.pct === 0).map(k => k.ch);
  const mean = active.length
    ? (active.reduce((a, k) => a + k.pct, 0) / active.length).toFixed(1) : "0";
  document.getElementById("resumen").innerHTML = [
    ["channels with data", active.length + " / 32"],
    ["packets with samples", mean + " %"],
    ["problems", D.problems.length ? D.problems.reduce((a,p)=>a+p[1],0) : "ninguno"],
  ].map(([a, b]) => "<div><b>" + b + "</b><span>" + a + "</span></div>").join("");

  let t = "<table><tr><th>channel</th><th>link</th><th>packets</th>"
        + "<th>with data</th><th>%</th><th>base</th><th>max</th></tr>";
  for (const k of D.channels) {
    const off = k.pct === 0 ? ' class="off"' : "";
    t += "<tr" + off + "><td>" + k.ch + "</td><td>" + k.link + "</td><td>" + k.n
       + "</td><td>" + k.data + "</td><td>" + k.pct + "</td><td>" + k.base
       + "</td><td>" + k.max + "</td></tr>";
  }
  document.getElementById("tabla").innerHTML = t + "</table>"
    + (dead.length ? '<div class="note"><b>Channels with no samples at all: '
       + dead.join(", ") + '.</b> This is what a channel disabled '
       + 'in <code>CHEN0..CHEN3</code> looks like. If you expected data from '
       + 'them, check the chip configuration.</div>' : "");

  if (V.type) {
    const x0 = V.x0, x1 = V.x1;
    V.pts = series(V.type, D.channels[V.ch]);
    if (V.pts.length) { V.x0 = x0; V.x1 = x1; }
  }
  anima();
}


/* ---------- board status (daqstat over ssh) ---------- */

/* Only meaningful live: in a static page saved to disk there is nobody on
   the other side who can talk to the board. */
/* Everything coming from the board ends up in innerHTML, so it gets
   escaped. Today it is daqstat output, which is not hostile, but the error
   message carries ssh text and there is no need to trust it. */
function esc(t) {
  return String(t).replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

function startBoardPanel() {
  const box = document.getElementById("board");
  const resumen = document.getElementById("daq-summary");
  const tabla = document.getElementById("daq-table");
  const notes = document.getElementById("daq-notes");
  const raw = document.querySelector("#daq-raw pre");
  let fallos = 0;

  function pastilla(v, si, no) {
    return '<span class="pastilla ' + (v ? "si" : "no") + '">'
         + (v ? si : no) + "</span>";
  }

  function draw(d) {
    if (!d.active) return;                 /* started without --board */
    box.classList.add("on");

    if (d.error) {
      resumen.innerHTML = "";
      tabla.innerHTML = "";
      notes.innerHTML = '<div class="note"><b>Could not query '
        + esc(d.target) + ':</b> ' + esc(d.error) + "</div>";
      return;
    }

    const p = [];
    if (d.firmware !== undefined)
      p.push("<div><b>" + d.firmware + "</b><span>firmware</span></div>");
    if (d.server !== undefined)
      p.push("<div><b>" + d.server + "</b><span>sampa_server</span></div>");
    if (d.client !== undefined)
      p.push("<div><b>" + pastilla(d.client, "YES", "NO")
             + "</b><span>client connected</span></div>");
    if (d.links_enabled !== undefined)
      p.push("<div><b>0x" + d.links_enabled.toString(16).toUpperCase()
             + "</b><span>links enabled</span></div>");
    if (d.to_acquire !== undefined)
      p.push("<div><b>" + d.to_acquire + "</b><span>packets per link ("
             + Math.round(d.to_acquire / 8) + " readouts, "
             + (d.to_acquire * 0.0125).toFixed(1) + " ms)</span></div>");
    resumen.innerHTML = p.join("");

    if (d.links && d.links.length) {
      let t = "<table><tr><th>link</th><th>enabled</th><th>sync</th>"
            + "<th>fifo full</th><th>packets</th><th>sync-loss</th>"
            + "<th>dropped</th><th>trunc</th></tr>";
      for (const e of d.links) {
        /* A link that is neither enabled nor in sync is not a problem: it
           is a link nobody uses. Dim it so it does not compete with the
           ones that matter. */
        const usa = e.enabled || e.sync;
        t += '<tr' + (usa ? "" : ' class="off"') + "><td>" + esc(e.name)
           + "</td><td>" + pastilla(e.enabled, "yes", "no")
           + "</td><td>" + pastilla(e.sync, "yes", "no")
           + "</td><td" + (e.fifo ? ' class="bad"' : "") + ">"
           + (e.fifo ? "SI" : "no") + "</td><td>" + e.packets
           + "</td><td" + (e.syncloss ? ' class="bad"' : "") + ">"
           + (e.syncloss === null ? "-" : e.syncloss)
           + "</td><td" + (e.dropped ? ' class="bad"' : "") + ">" + e.dropped
           + "</td><td" + (e.trunc ? ' class="bad"' : "") + ">" + e.trunc
           + "</td></tr>";
      }
      tabla.innerHTML = t + "</table>";
    }

    /* daqstat's own "what to look at" block: its diagnosis knows more about
       the FPGA state than anything we could work out in the browser. */
    notes.innerHTML = (d.notes && d.notes.length)
      ? '<div class="note">' + d.notes.map(esc).join("<br>") + "</div>" : "";
    raw.textContent = d.raw || "";
  }

  function tick() {
    fetch("daq", {cache: "no-store"})
      .then(r => r.json())
      .then(d => { fallos = 0; draw(d); })
      .catch(() => {
        /* The receiver is gone; the rest of the page already says so. */
        if (++fallos > 3) box.classList.remove("on");
      });
  }
  tick();
  setInterval(tick, 3000);
}

if (LIVE) startBoardPanel();


/* ---------- en live ---------- */

if (!LIVE) {
  montar(JSON.parse(document.getElementById("data").textContent));
} else {
  const luz = document.getElementById("beat");
  const txt = document.getElementById("live-txt");
  const bt = document.getElementById("btPause");
  const spark = document.getElementById("spark");
  document.getElementById("live").hidden = false;

  let pausado = false, antes = 0, cuando = 0, ws = null, poll = null,
      intentos = 0, enganchado = false;
  const history = [];          // recent rates, for the sparkline

  bt.onclick = () => {
    pausado = !pausado;
    bt.textContent = pausado ? "reanudar" : "pausar";
    luz.className = "beat" + (pausado ? " parado" : "");
    if (pausado) txt.textContent = "paused";
  };

  function dibujaSpark() {
    const r = window.devicePixelRatio || 1;
    const W = spark.clientWidth, H = spark.clientHeight;
    spark.width = Math.round(W * r); spark.height = Math.round(H * r);
    const g = spark.getContext("2d");
    g.setTransform(r, 0, 0, r, 0, 0);
    g.clearRect(0, 0, W, H);
    if (history.length < 2) return;
    const max = Math.max(1, ...history);
    const paso = W / (history.length - 1);
    const py = v => H - 1 - (v / max) * (H - 3);
    g.beginPath();
    g.moveTo(0, H);
    history.forEach((v, i) => g.lineTo(i * paso, py(v)));
    g.lineTo((history.length - 1) * paso, H);
    g.closePath();
    g.fillStyle = css("--accent-tenue"); g.fill();
    g.beginPath();
    history.forEach((v, i) => i ? g.lineTo(i * paso, py(v)) : g.moveTo(0, py(v)));
    g.strokeStyle = css("--trace"); g.lineWidth = 1.2; g.stroke();
    g.fillStyle = css("--trace");
    g.beginPath();
    g.arc((history.length - 1) * paso, py(history[history.length - 1]), 2.2, 0, 6.284);
    g.fill();
  }

  function aplica(d, via) {
    if (pausado) return;
    const ahora = Date.now();
    const tasa = cuando ? (d.packets - antes) / ((ahora - cuando) / 1000) : 0;
    antes = d.packets; cuando = ahora;
    history.push(Math.max(0, tasa));
    while (history.length > 60) history.shift();
    montar(d);
    dibujaSpark();
    luz.className = "beat";
    txt.textContent = (tasa >= 1
      ? Math.round(tasa).toLocaleString("es") + " paq/s"
      : (d.packets ? "no new data" : "waiting…")) + via;
  }

  function connect() {
    intentos++;
    try {
      const p = location.protocol === "https:" ? "wss://" : "ws://";
      ws = new WebSocket(p + location.host + "/live");
    } catch (e) { return fallback(); }
    ws.onopen = () => { enganchado = true; intentos = 0; };
    ws.onmessage = e => aplica(JSON.parse(e.data), "");
    ws.onerror = () => {};
    ws.onclose = () => {
      ws = null;
      if (poll) return;
      luz.className = "beat caido";
      /* Si nunca llego a abrirse, algo lo bloquea y no se arregla
         retrying: fall back to polling. If it was working, the receiver has
         most likely stopped, and then retrying is the right move. */
      if (!enganchado && intentos >= 2) {
        txt.textContent = "no WebSocket, polling…";
        return fallback();
      }
      txt.textContent = "reconectando…";
      setTimeout(connect, 1500);
    };
  }

  async function tick() {
    if (pausado) return;
    try {
      const r = await fetch("data", {cache:"no-store"});
      if (!r.ok) throw new Error(r.status);
      aplica(await r.json(), " · poll");
    } catch (e) {
      luz.className = "beat caido";
      txt.textContent = "receptor desconectado";
    }
  }

  function fallback() {
    if (poll) return;
    tick();
    poll = setInterval(tick, 700);
  }

  connect();
}

</script></body></html>
"""


def page(data=None, title="", live=False):
    """Return the complete HTML.

    With live=False the data goes inside the file and the page is
    self-contained. With live=True it carries no data: it asks the receiver
    for it every 0.7 s over HTTP.

    Markers @@X@@ rather than "%(x)s" or str.format: the page is full of
    percent signs (CSS) and braces (JavaScript), and both Python formatters
    choke on them.
    """
    body = "{}" if data is None else json.dumps(data, separators=(",", ":"))
    html = PAGINA
    for key, value in (
            ("FILE", title or (data or {}).get("file", "")),
            ("LIVE", "true" if live else "false"),
            # Escaping "<" stops a "</script>" inside the data (an odd
            # file name, an error message) from closing the tag early and
            # breaking the whole page.
            ("JSON", body.replace("<", "\\u003c"))):
        html = html.replace("@@" + key + "@@", str(value))
    return html


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Draw a .bin capture into a self-contained web page.")
    p.add_argument("capture", help="the .bin file from --save")
    p.add_argument("-o", "--output", help="output html (default: "
                                          "the same name with .html)")
    p.add_argument("--mode", default="auto",
                   choices=("auto", "zs", "raw", "sum"),
                   help="how the payload is compressed")
    args = p.parse_args(argv)

    output = args.output or (os.path.splitext(args.capture)[0] + ".html")
    print("reading {0} ...".format(args.capture))
    d = analyse(args.capture, args.mode)
    if not d["packets"]:
        print("  the capture is empty: there is nothing to draw")
        return 1

    html = page(d)
    with open(output, "w") as f:
        f.write(html)
    print("written {0}  ({1:.1f} MB)".format(output,
                                             os.path.getsize(output) / 1048576.0))
    print("open it with a double click; it needs nothing installed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
