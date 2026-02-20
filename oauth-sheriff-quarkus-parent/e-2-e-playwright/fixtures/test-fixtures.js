/**
 * @fileoverview Consolidated test fixtures for OAuth Sheriff Dev-UI Playwright tests
 * Provides page fixtures with automatic logging and accessibility helpers
 */

import { mkdirSync } from 'fs';
import { join } from 'path';
import { test as base, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { testLogger } from '../utils/test-logger.js';

/**
 * Extended test with logging and screenshot fixtures
 */
export const test = base.extend({
  /**
   * Page fixture with automatic console logging
   */
  page: async ({ page }, use, testInfo) => {
    testLogger.startTest(testInfo.testId);
    testLogger.setupBrowserCapture(page);

    await use(page);

    // Automatic end-of-test screenshot and text logs
    mkdirSync(testInfo.outputDir, { recursive: true });
    await page
      .screenshot({
        path: join(testInfo.outputDir, 'after.png'),
        fullPage: true,
      })
      .catch(() => {});
    testLogger.writeLogs(testInfo);
  },
});

/**
 * Accessibility-focused test fixture using @axe-core/playwright
 */
export const accessibilityTest = test.extend({
  /**
   * Run WCAG 2.1 AA accessibility check after each test
   */
  accessibilityHelper: async ({ page }, use) => {
    const helper = {
      /**
       * Run axe-core analysis on the current page
       * @param {object} [options] - Additional options
       * @param {string[]} [options.disableRules] - Rules to disable
       * @returns {Promise<import('axe-core').AxeResults>}
       */
      async analyze(options = {}) {
        const builder = new AxeBuilder({ page })
          .withTags(['wcag2aa', 'wcag21aa', 'best-practice'])
          .disableRules(['bypass', 'landmark-one-main', 'region', ...(options.disableRules || [])]);
        return builder.analyze();
      },

      /**
       * Assert no WCAG violations (or only acceptable ones)
       * @param {object} [options] - Options
       * @param {string[]} [options.disableRules] - Rules to disable
       */
      async expectNoViolations(options = {}) {
        const results = await this.analyze(options);
        if (results.violations.length > 0) {
          const summary = results.violations
            .map((v) => `${v.id}: ${v.description} (${v.nodes.length} elements)`)
            .join('\n');
          console.warn('Accessibility violations:\n' + summary);
        }
        expect(results.violations).toEqual([]);
      },
    };

    await use(helper);
  },
});

export { expect } from '@playwright/test';
export { takeStartScreenshot } from '../utils/test-logger.js';
