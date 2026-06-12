/* Soak test: drive the integrated console for ~2.5 min, sample heap / DOM /
   WebGL resource counts, and flag growth (leak) or slow frames (hang). */
const { createRequire } = require('module');
const req = createRequire('/home/myles/CueCrux/Cue/noop.js');
const { chromium } = req('@playwright/test');
(async () => {
  const browser = await chromium.launch({ headless: true,
    executablePath: '/home/myles/.cache/ms-playwright/chromium-1208/chrome-linux64/chrome',
    args: ['--enable-precise-memory-info'] });
  const page = await browser.newPage({ viewport: { width: 1537, height: 800 } });
  const errs = [];
  page.on('pageerror', (e) => errs.push(e.message));
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('Performance.enable');
  await page.goto('http://localhost:8321/agent-observability.html', { waitUntil: 'networkidle' });
  await page.waitForTimeout(1200);
  await page.click('#view3d');
  await page.waitForTimeout(3500);
  const embedFrame = () => page.frames().find((f) => f.url().includes('embed=1'));

  const samples = [];
  async function sample(tag) {
    const m = Object.fromEntries((await cdp.send('Performance.getMetrics')).metrics.map((x) => [x.name, x.value]));
    let gl = null;
    try { gl = await embedFrame().evaluate(() => window.__cx3dStats()); } catch (e) { gl = { err: String(e).slice(0, 60) }; }
    samples.push({ tag, t: Math.round(m.Timestamp), heapMB: +(m.JSHeapUsedSize / 1048576).toFixed(1),
      nodes: m.Nodes, listeners: m.JSEventListeners, docs: m.Documents, frames: m.Frames, ...gl ? {
        glHeapMB: gl.heapMB, geo: gl.geometries, tex: gl.textures, calls: gl.calls, rafFrames: gl.frames, slow: gl.slow, paused: gl.paused } : {} });
  }

  await sample('boot-3d');
  const CYCLES = 9;
  for (let i = 0; i < CYCLES; i++) {
    await page.click('#sidebar .sb-item[data-panel="cx-work"]');         // filter + lineup + edge rebuild
    await page.waitForTimeout(2600);
    await page.evaluate(() => document.getElementById('cx3dFrame').contentWindow
      .postMessage({ type: 'cx3d:focusId', id: 'ep-agentux' }, location.origin));   // focus + rel labels
    await page.waitForTimeout(900);
    await page.click('#themeBtn'); await page.waitForTimeout(500);       // theme redraw (32 canvases)
    await page.click('#themeBtn'); await page.waitForTimeout(500);
    await page.click('#sidebar .sb-item:first-child');                   // home: restore + rebuild
    await page.waitForTimeout(2600);
    await page.click('#view2d'); await page.waitForTimeout(700);         // pause loop
    await page.click('#view3d'); await page.waitForTimeout(900);         // resume
    await sample('cycle' + (i + 1));
  }
  /* idle dwell — does anything grow with NO interaction? */
  await page.waitForTimeout(20000);
  await sample('idle+20s');

  console.log('tag        heapMB  nodes  listnr  glHeap  geo  tex  calls  raf      slow paused');
  for (const s of samples)
    console.log(`${s.tag.padEnd(10)} ${String(s.heapMB).padStart(6)} ${String(s.nodes).padStart(6)} ${String(s.listeners).padStart(6)} ${String(s.glHeapMB).padStart(7)} ${String(s.geo).padStart(4)} ${String(s.tex).padStart(4)} ${String(s.calls).padStart(6)} ${String(s.rafFrames).padStart(8)} ${String(s.slow).padStart(5)} ${s.paused}`);
  const a = samples[1], b = samples[samples.length - 1];
  console.log(`\nGROWTH cycle1→end: heap ${a.heapMB}→${b.heapMB} MB · nodes ${a.nodes}→${b.nodes} · listeners ${a.listeners}→${b.listeners} · glHeap ${a.glHeapMB}→${b.glHeapMB} · geometries ${a.geo}→${b.geo} · textures ${a.tex}→${b.tex}`);
  console.log(errs.length ? 'PAGE ERRORS:\n' + errs.join('\n') : 'page errors: none');
  await browser.close();
})();
