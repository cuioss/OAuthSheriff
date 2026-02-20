/**
 * @fileoverview Unified test logger for browser and Node-side log capture
 */

import { writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';

class TestLogger {
  constructor() {
    this._logs = [];
    this._testId = null;
  }

  startTest(testId) {
    this._testId = testId;
    this._logs = [];
  }

  /**
   * Set up browser console capture on a Playwright page
   * @param {import('@playwright/test').Page} page
   */
  setupBrowserCapture(page) {
    page.on('console', (msg) => {
      this._logs.push(`[browser:${msg.type()}] ${msg.text()}`);
    });
    page.on('pageerror', (error) => {
      this._logs.push(`[browser:error] ${error.message}`);
    });
  }

  info(category, message) {
    this._logs.push(`[node:info:${category}] ${message}`);
  }

  warn(category, message) {
    this._logs.push(`[node:warn:${category}] ${message}`);
  }

  error(category, message) {
    this._logs.push(`[node:error:${category}] ${message}`);
  }

  /**
   * Write captured logs to a text file in the test output directory
   * @param {import('@playwright/test').TestInfo} testInfo
   */
  writeLogs(testInfo) {
    if (this._logs.length === 0) return;
    try {
      mkdirSync(testInfo.outputDir, { recursive: true });
      const logPath = join(testInfo.outputDir, 'test-logs.txt');
      writeFileSync(logPath, this._logs.join('\n') + '\n', 'utf8');
    } catch {
      // Swallow - logging should never break tests
    }
  }
}

export const testLogger = new TestLogger();

/**
 * Take a screenshot and attach it to the test
 * @param {import('@playwright/test').Page} page
 * @param {import('@playwright/test').TestInfo} testInfo
 * @param {string} name
 */
export async function takeStartScreenshot(page, testInfo, name = 'start') {
  try {
    mkdirSync(testInfo.outputDir, { recursive: true });
    await page.screenshot({
      path: join(testInfo.outputDir, `${name}.png`),
      fullPage: true,
    });
  } catch {
    // Non-fatal
  }
}
