/**
 * @fileoverview E2E tests for JWT Token Debugger Dev-UI card
 * Verifies the qwc-jwt-debugger component for token validation functionality.
 */

import { test, expect } from '../fixtures/test-fixtures.js';
import { CONSTANTS } from '../utils/constants.js';
import { goToTokenDebugger } from '../utils/devui-navigation.js';
import { getKeycloakTokenInsecure } from '../utils/keycloak-token-service.js';

test.describe('03 - Token Debugger Card', () => {
  test.beforeEach(async ({ page }) => {
    await goToTokenDebugger(page);
  });

  test('should display the token debugger container', async ({ page }) => {
    const container = page.locator(CONSTANTS.SELECTORS.JWT_DEBUGGER_CONTAINER);
    await expect(container).toBeVisible({ timeout: CONSTANTS.TIMEOUTS.ELEMENT_VISIBLE });
  });

  test('should have an empty textarea initially', async ({ page }) => {
    const textarea = page.locator(CONSTANTS.SELECTORS.JWT_DEBUGGER_TOKEN_INPUT);
    await expect(textarea).toBeVisible();
    const value = await textarea.inputValue();
    expect(value).toBe('');
  });

  test('should display validate, clear, and sample buttons', async ({ page }) => {
    const validateButton = page.locator(CONSTANTS.SELECTORS.JWT_DEBUGGER_VALIDATE_BUTTON);
    const clearButton = page.locator(CONSTANTS.SELECTORS.JWT_DEBUGGER_CLEAR_BUTTON);
    const sampleButton = page.locator(CONSTANTS.SELECTORS.JWT_DEBUGGER_SAMPLE_BUTTON);

    await expect(validateButton).toBeVisible();
    await expect(clearButton).toBeVisible();
    await expect(sampleButton).toBeVisible();
  });

  test('should show error when validating empty token', async ({ page }) => {
    const validateButton = page.locator(CONSTANTS.SELECTORS.JWT_DEBUGGER_VALIDATE_BUTTON);
    await validateButton.click();

    // Wait for result to appear
    await page.waitForTimeout(1000);

    const result = page.locator(CONSTANTS.SELECTORS.JWT_DEBUGGER_RESULT);
    await expect(result).toBeVisible({ timeout: CONSTANTS.TIMEOUTS.SHORT });

    const resultTitle = page.locator(CONSTANTS.SELECTORS.JWT_DEBUGGER_RESULT_TITLE);
    const titleText = await resultTitle.textContent();
    expect(titleText.toLowerCase()).toContain('invalid');
  });

  test('should load sample token via button', async ({ page }) => {
    const sampleButton = page.locator(CONSTANTS.SELECTORS.JWT_DEBUGGER_SAMPLE_BUTTON);
    await sampleButton.click();

    // Textarea should now have content
    const textarea = page.locator(CONSTANTS.SELECTORS.JWT_DEBUGGER_TOKEN_INPUT);
    const value = await textarea.inputValue();
    expect(value.length).toBeGreaterThan(0);
    // JWT has 3 parts separated by dots
    expect(value.split('.').length).toBe(3);
  });

  test('should clear token and result via clear button', async ({ page }) => {
    // First, load a sample
    const sampleButton = page.locator(CONSTANTS.SELECTORS.JWT_DEBUGGER_SAMPLE_BUTTON);
    await sampleButton.click();

    // Validate it to show a result
    const validateButton = page.locator(CONSTANTS.SELECTORS.JWT_DEBUGGER_VALIDATE_BUTTON);
    await validateButton.click();
    await page.waitForTimeout(2000);

    // Clear everything
    const clearButton = page.locator(CONSTANTS.SELECTORS.JWT_DEBUGGER_CLEAR_BUTTON);
    await clearButton.click();

    // Textarea should be empty
    const textarea = page.locator(CONSTANTS.SELECTORS.JWT_DEBUGGER_TOKEN_INPUT);
    const value = await textarea.inputValue();
    expect(value).toBe('');

    // Result should be gone
    const result = page.locator(CONSTANTS.SELECTORS.JWT_DEBUGGER_RESULT);
    await expect(result).not.toBeVisible();
  });

  test('should validate a real Keycloak token', async ({ page }) => {
    let token;
    try {
      token = await getKeycloakTokenInsecure({ realm: 'benchmark' });
    } catch (error) {
      console.warn('Skipping real token test - Keycloak not available:', error.message);
      test.skip();
      return;
    }

    // Paste the real token
    const textarea = page.locator(CONSTANTS.SELECTORS.JWT_DEBUGGER_TOKEN_INPUT);
    await textarea.fill(token);

    // Click validate
    const validateButton = page.locator(CONSTANTS.SELECTORS.JWT_DEBUGGER_VALIDATE_BUTTON);
    await validateButton.click();

    // Wait for validation result
    await page.waitForTimeout(3000);

    const result = page.locator(CONSTANTS.SELECTORS.JWT_DEBUGGER_RESULT);
    await expect(result).toBeVisible({ timeout: CONSTANTS.TIMEOUTS.JSON_RPC });
  });
});
