/**
 * @fileoverview Dev-UI navigation helpers for Playwright tests
 * Handles navigation to Quarkus Dev-UI pages with shadow DOM awareness.
 *
 * Navigation strategy: Click-based navigation through the extension card.
 * Quarkus Dev-UI is a SPA (Vaadin Router + Lit web components) where extension
 * sub-page routes are registered lazily. Direct URL navigation is fragile because
 * the exact route paths depend on internal Quarkus conventions. Instead, we:
 * 1. Navigate to the Dev-UI extensions page
 * 2. Wait for the OAuth Sheriff extension card to render
 * 3. Click the specific sub-page link by its static label text
 * 4. Wait for the custom element to appear in the #page outlet
 */

import { CONSTANTS } from './constants.js';

/**
 * Pages configuration mapping page key to element name and the click target text.
 * The clickTarget is the static label text shown on the extension card link,
 * chosen to be unique on the page (avoiding ambiguity with sidebar items).
 */
const PAGES = {
  'JWT Validation Status': {
    element: 'qwc-jwt-validation-status',
    clickTarget: 'View Status',
  },
  'JWKS Endpoints': {
    element: 'qwc-jwks-endpoints',
    clickTarget: 'View Endpoints',
  },
  'Token Debugger': {
    element: 'qwc-jwt-debugger',
    clickTarget: 'Debug Tokens',
  },
  Configuration: {
    element: 'qwc-jwt-config',
    clickTarget: 'View Config',
  },
};

/**
 * Navigate to a Dev-UI extension sub-page by clicking through the extension card.
 *
 * @param {import('@playwright/test').Page} page - Playwright page
 * @param {string} pageKey - The page key from the PAGES map (e.g. "JWT Validation Status")
 * @param {string} [waitForSelector] - Optional CSS selector to wait for after navigation
 */
export async function navigateToDevUIPage(page, pageKey, waitForSelector) {
  const pageConfig = PAGES[pageKey];
  if (!pageConfig) {
    throw new Error(`Unknown page key: ${pageKey}. Valid keys: ${Object.keys(PAGES).join(', ')}`);
  }

  const { element: elementName, clickTarget } = pageConfig;

  // Step 1: Navigate to Dev-UI extensions page
  await page.goto(CONSTANTS.URLS.DEVUI, {
    waitUntil: 'networkidle',
    timeout: CONSTANTS.TIMEOUTS.NAVIGATION,
  });

  // Step 2: Wait for the OAuth Sheriff extension card to appear.
  // The card title contains "JWT Token Validation" (the extension display name).
  await page.getByText('JWT Token Validation').first().waitFor({
    state: 'visible',
    timeout: CONSTANTS.TIMEOUTS.ELEMENT_VISIBLE,
  });

  // Step 3: Click the sub-page link by its static label text.
  // Static labels (e.g. "View Status", "Debug Tokens", "View Config") are unique
  // and avoid ambiguity with sidebar navigation items.
  const pageLink = page.getByText(clickTarget, { exact: true }).first();
  await pageLink.waitFor({
    state: 'visible',
    timeout: CONSTANTS.TIMEOUTS.SHORT,
  });
  await pageLink.click();

  // Step 4: Wait for the custom element to appear in the DOM.
  // After clicking, the Vaadin Router creates the element in the #page outlet.
  if (elementName) {
    try {
      await page.locator(elementName).first().waitFor({
        state: 'attached',
        timeout: CONSTANTS.TIMEOUTS.ELEMENT_VISIBLE,
      });
    } catch (err) {
      // Dump diagnostic information before failing
      const diag = await page.evaluate(() => {
        const outlet = document.querySelector('#page');
        return {
          currentUrl: window.location.href,
          outletExists: !!outlet,
          outletChildCount: outlet?.children?.length ?? 0,
          outletChildTags: Array.from(outlet?.children ?? []).map((c) => c.tagName.toLowerCase()),
          outletInnerHTML: outlet?.innerHTML?.substring(0, 1000) ?? '',
        };
      });
      console.error(`[devui-nav] Element <${elementName}> not found. Diagnostics:`, JSON.stringify(diag, null, 2));
      throw err;
    }
    // Give the Lit component time to initialize (connectedCallback -> firstUpdated -> render)
    await page.waitForTimeout(1000);
  }

  if (waitForSelector) {
    await page.locator(waitForSelector).waitFor({
      state: 'visible',
      timeout: CONSTANTS.TIMEOUTS.ELEMENT_VISIBLE,
    });
  }
}

/**
 * Navigate to the JWT Validation Status page
 * @param {import('@playwright/test').Page} page
 */
export async function goToValidationStatus(page) {
  await navigateToDevUIPage(page, 'JWT Validation Status');
}

/**
 * Navigate to the JWKS Endpoints page
 * @param {import('@playwright/test').Page} page
 */
export async function goToJwksEndpoints(page) {
  await navigateToDevUIPage(page, 'JWKS Endpoints');
}

/**
 * Navigate to the Token Debugger page
 * @param {import('@playwright/test').Page} page
 */
export async function goToTokenDebugger(page) {
  await navigateToDevUIPage(page, 'Token Debugger');
}

/**
 * Navigate to the Configuration page
 * @param {import('@playwright/test').Page} page
 */
export async function goToConfiguration(page) {
  await navigateToDevUIPage(page, 'Configuration');
}

/**
 * Check if the Dev-UI is accessible
 * @param {import('@playwright/test').Page} page
 * @returns {Promise<boolean>}
 */
export async function isDevUIAccessible(page) {
  try {
    const response = await page.goto(CONSTANTS.URLS.DEVUI, {
      waitUntil: 'domcontentloaded',
      timeout: CONSTANTS.TIMEOUTS.NAVIGATION,
    });
    return response !== null && response.ok();
  } catch {
    return false;
  }
}
