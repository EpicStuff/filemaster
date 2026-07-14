#!/usr/bin/env node
// Usage: node screenshot.mjs [url] [output.png]
//   url defaults to http://localhost:4200/dashboard
//   output defaults to ./tmp/screenshot.png  (relative to repo root / cwd)
//
// Requires: ng serve running on :4200, daemon on :818, playwright installed at
//   /root/vaultwarden-clients/node_modules/playwright

import { chromium } from '/root/vaultwarden-clients/node_modules/playwright/index.mjs';

const url = process.argv[2] || 'http://localhost:4200/dashboard';
const out = process.argv[3] || './tmp/screenshot.png';

const browser = await chromium.launch({
    executablePath: '/usr/sbin/chromium',
    args: ['--no-sandbox'],
});
const page = await browser.newPage();
await page.setViewportSize({ width: 1280, height: 900 });

await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 20000 });

// Wait for Angular to render, then dismiss setup wizard overlay
await page.waitForTimeout(5000);
await page.evaluate(() => {
    const overlay = document.querySelector('.cdk-overlay-container');
    if (overlay) overlay.style.display = 'none';
});
await page.waitForTimeout(500);

await page.screenshot({ path: out });
await browser.close();
console.log('saved', out);
