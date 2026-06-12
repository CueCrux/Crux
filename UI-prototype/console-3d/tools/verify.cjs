/* Headless visual verification for the Crux Substrate concept. */
const { createRequire } = require('module');
const req = createRequire('/home/myles/CueCrux/Cue/noop.js');
const { chromium } = req('@playwright/test');
const fs = require('fs');

(async () => {
  fs.mkdirSync('/tmp/cx3d', { recursive: true });
  const browser = await chromium.launch({
    headless: true,
    executablePath: '/home/myles/.cache/ms-playwright/chromium-1208/chrome-linux64/chrome',
  });
  const page = await browser.newPage({ viewport: { width: 1537, height: 800 } });
  const logs = [];
  page.on('console', (m) => logs.push(`[${m.type()}] ${m.text()}`));
  page.on('pageerror', (e) => logs.push(`[pageerror] ${e.message}`));

  await page.goto('http://localhost:8321/console-3d/', { waitUntil: 'networkidle' });
  await page.waitForTimeout(2500);
  await page.screenshot({ path: '/tmp/cx3d/1-hero.png' });

  const max = await page.evaluate(() => document.getElementById('scroll-spacer').offsetHeight - innerHeight);
  for (const [name, f] of [['2-ch2-work', 2 / 6], ['3-ch4-receipts', 4 / 6], ['4-explore', 1.0]]) {
    await page.evaluate((y) => scrollTo(0, y), Math.round(max * f));
    await page.waitForTimeout(1600);
    await page.screenshot({ path: `/tmp/cx3d/${name}.png` });
  }

  /* focus a node via the search box */
  await page.fill('#search', 'agent-ux-best-in-class');
  await page.dispatchEvent('#search', 'change');
  await page.waitForTimeout(1600);
  await page.screenshot({ path: '/tmp/cx3d/5-focus-panel.png' });

  /* dark theme */
  await page.click('#theme');
  await page.waitForTimeout(900);
  await page.screenshot({ path: '/tmp/cx3d/6-dark.png' });

  await browser.close();
  const errs = logs.filter((l) => l.startsWith('[error]') || l.startsWith('[pageerror]'));
  console.log(errs.length ? 'CONSOLE ERRORS:\n' + errs.join('\n') : 'console clean');
  console.log('other logs:', logs.filter((l) => !errs.includes(l)).slice(0, 10).join(' | ') || '(none)');
})();
