/**
 * @fileoverview Self-tests that validate the E2E test environment
 * These are gate-keeper tests: if they fail, the environment is not ready.
 */

import { test, expect } from '../fixtures/test-fixtures.js';
import { CONSTANTS } from '../utils/constants.js';
import { isDevUIAccessible } from '../utils/devui-navigation.js';

test.describe('self-devui-accessible: Environment Validation', () => {
  test('Quarkus application is accessible', async ({ page }) => {
    const response = await page.goto(CONSTANTS.URLS.BASE, {
      waitUntil: 'domcontentloaded',
      timeout: CONSTANTS.TIMEOUTS.NAVIGATION,
    });
    expect(response).not.toBeNull();
    expect(response.status()).toBeLessThan(500);
  });

  test('Dev-UI is accessible', async ({ page }) => {
    const accessible = await isDevUIAccessible(page);
    expect(accessible).toBe(true);
  });

  test('OAuth Sheriff extension is visible in Dev-UI', async ({ page }) => {
    await page.goto(CONSTANTS.URLS.DEVUI, {
      waitUntil: 'networkidle',
      timeout: CONSTANTS.TIMEOUTS.NAVIGATION,
    });

    // The Dev-UI extensions page should mention OAuth Sheriff
    const content = await page.content();
    expect(content.toLowerCase()).toContain('oauth');
  });

  test('JWT Validation Status page is navigable', async ({ page }) => {
    const response = await page.goto(CONSTANTS.DEVUI_PAGES.VALIDATION_STATUS, {
      waitUntil: 'networkidle',
      timeout: CONSTANTS.TIMEOUTS.NAVIGATION,
    });
    expect(response).not.toBeNull();
    expect(response.status()).toBeLessThan(500);
  });

  test('JWKS Endpoints page is navigable', async ({ page }) => {
    const response = await page.goto(CONSTANTS.DEVUI_PAGES.JWKS_ENDPOINTS, {
      waitUntil: 'networkidle',
      timeout: CONSTANTS.TIMEOUTS.NAVIGATION,
    });
    expect(response).not.toBeNull();
    expect(response.status()).toBeLessThan(500);
  });

  test('Token Debugger page is navigable', async ({ page }) => {
    const response = await page.goto(CONSTANTS.DEVUI_PAGES.TOKEN_DEBUGGER, {
      waitUntil: 'networkidle',
      timeout: CONSTANTS.TIMEOUTS.NAVIGATION,
    });
    expect(response).not.toBeNull();
    expect(response.status()).toBeLessThan(500);
  });

  test('Configuration page is navigable', async ({ page }) => {
    const response = await page.goto(CONSTANTS.DEVUI_PAGES.CONFIGURATION, {
      waitUntil: 'networkidle',
      timeout: CONSTANTS.TIMEOUTS.NAVIGATION,
    });
    expect(response).not.toBeNull();
    expect(response.status()).toBeLessThan(500);
  });

  test('JSON-RPC returns RUNTIME status (not BUILD_TIME)', async ({ page }) => {
    // Navigate to the validation status page which calls getValidationStatus() via JSON-RPC
    await page.goto(CONSTANTS.DEVUI_PAGES.VALIDATION_STATUS, {
      waitUntil: 'networkidle',
      timeout: CONSTANTS.TIMEOUTS.NAVIGATION,
    });

    // Wait for the component to load and render
    await page.waitForTimeout(3000);

    // The page content should NOT contain BUILD_TIME if the bug fix is correct
    const content = await page.content();
    expect(content).not.toContain('BUILD_TIME');
  });
});
