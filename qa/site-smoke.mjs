import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const browsers = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const axePath = process.env.AXE_PATH || require.resolve('axe-core/axe.min.js');
const root = fileURLToPath(new URL('../_site/', import.meta.url));
const server = createServer(async (req, res) => {
  const path = resolve(root, '.' + (req.url === '/' ? '/index.html' : req.url));
  if (!path.startsWith(root)) { res.writeHead(403).end(); return; }
  try {
    res.setHeader('Content-Type', path.endsWith('.wasm') ? 'application/wasm' : path.endsWith('.js') ? 'text/javascript' : path.endsWith('.html') ? 'text/html' : 'application/json');
    res.end(await readFile(path));
  } catch { res.writeHead(404).end(); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const url = `http://127.0.0.1:${server.address().port}/`;
try {
  for (const name of (process.env.BROWSERS || 'chromium').split(',')) {
    const browser = await browsers[name].launch();
    try {
      for (const width of [375, 1440]) {
        const context = await browser.newContext({ viewport: { width, height: 900 }, reducedMotion: 'reduce' });
        const page = await context.newPage(); const errors = [], sizes = [];
        page.on('pageerror', e => errors.push(e.message));
        page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });
        page.on('response', r => sizes.push(r.finished().then(() => r.request().sizes()).then(s => s.responseBodySize).catch(() => 0)));
        await page.goto(url);
        await page.waitForFunction(() => document.querySelector('#verdict').textContent.includes('7 newly allowed'));
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
        assert.equal(await page.evaluate(() => getComputedStyle(document.documentElement).scrollBehavior), 'auto');
        await page.addScriptTag({ path: axePath });
        const violations = await page.evaluate(async () => (await axe.run()).violations.map(v => ({ id: v.id, nodes: v.nodes.map(n => n.target) })));
        assert.deepEqual(violations, []);
        // WebKit on macOS uses Option-Tab to include links in keyboard traversal.
        await page.keyboard.press(name === 'webkit' ? 'Alt+Tab' : 'Tab');
        assert.equal(await page.locator('.skip').evaluate(el => el === document.activeElement), true);
        await page.keyboard.press('Enter');
        assert.equal(await page.evaluate(() => document.activeElement.id), 'main');
        await page.locator('[data-preset="policy_broken"]').click();
        await page.waitForFunction(() => document.querySelector('#verdict').textContent.includes('Blocked'));
        await page.locator('[data-preset="policy"]').click();
        await page.waitForFunction(() => document.querySelector('#verdict').textContent.includes('No decision changes'));
        await page.locator('#new').fill('{}');
        await page.waitForFunction(() => document.querySelector('.err') !== null);
        await page.locator('[data-preset="policy_v2"]').click();
        await page.waitForFunction(() => document.querySelector('#verdict').textContent.includes('7 newly allowed'));
        assert.deepEqual(errors, []);
        console.log(JSON.stringify({ browser: name, width, bodyBytes: (await Promise.all(sizes)).reduce((a,b) => a+b,0), axeViolations: 0, actualWasmPresets: 'pass', keyboardSkip: 'pass', reducedMotion: 'pass' }));
        await context.close();
      }
      const nojs = await browser.newContext({ javaScriptEnabled: false });
      const page = await nojs.newPage(); await page.goto(url);
      assert.match(await page.locator('noscript').innerText(), /needs JavaScript/);
      assert.equal(await page.locator('#new').isDisabled(), true);
      await nojs.close();
      const failed = await browser.newContext(); const failurePage = await failed.newPage();
      await failurePage.route('**/presets/policy_broken.json', r => r.fulfill({ status: 503, body: 'unavailable' }));
      const errors = []; failurePage.on('pageerror', e => errors.push(e.message));
      await failurePage.goto(url);
      await failurePage.waitForFunction(() => document.querySelector('#verdict').textContent.includes('7 newly allowed'));
      await failurePage.locator('[data-preset="policy_broken"]').click();
      await failurePage.waitForFunction(() => document.querySelector('#verdict').textContent.includes('HTTP 503'));
      assert.deepEqual(errors, []);
      await failed.close();
    } finally { await browser.close(); }
  }
} finally { await new Promise(resolve => server.close(resolve)); }
