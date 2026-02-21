/**
 * @fileoverview Dev-UI navigation helpers for Playwright tests
 * Handles navigation to Quarkus Dev-UI pages with shadow DOM awareness
 */

import { CONSTANTS } from "./constants.js";

/**
 * Navigate to a Dev-UI extension page and wait for the custom element to render.
 * Quarkus Dev-UI uses Vaadin Router + Lit web components inside shadow DOM.
 *
 * The Vaadin Router loads routes asynchronously, so direct URL navigation to
 * sub-pages often fails (the router hasn't configured routes yet when the SPA
 * first loads). This helper first navigates to the Dev-UI main page to fully
 * initialize the SPA, then navigates to the target sub-page.
 *
 * @param {import('@playwright/test').Page} page - Playwright page
 * @param {string} url - Full URL to navigate to
 * @param {string} [waitForSelector] - Optional CSS selector to wait for after navigation
 */
export async function navigateToDevUIPage(page, url, waitForSelector) {
    // Step 1: Navigate to the Dev-UI main page to fully initialize the SPA
    await page.goto(CONSTANTS.URLS.DEVUI, {
        waitUntil: "networkidle",
        timeout: CONSTANTS.TIMEOUTS.NAVIGATION,
    });
    await page.waitForFunction(() => document.readyState === "complete");

    // Step 2: Navigate to the target sub-page (SPA is now initialized)
    await page.goto(url, {
        waitUntil: "networkidle",
        timeout: CONSTANTS.TIMEOUTS.NAVIGATION,
    });
    await page.waitForFunction(() => document.readyState === "complete");

    if (waitForSelector) {
        await page.locator(waitForSelector).waitFor({
            state: "visible",
            timeout: CONSTANTS.TIMEOUTS.ELEMENT_VISIBLE,
        });
    }
}

/**
 * Navigate to the JWT Validation Status page
 * @param {import('@playwright/test').Page} page
 */
export async function goToValidationStatus(page) {
    await navigateToDevUIPage(page, CONSTANTS.DEVUI_PAGES.VALIDATION_STATUS);
}

/**
 * Navigate to the JWKS Endpoints page
 * @param {import('@playwright/test').Page} page
 */
export async function goToJwksEndpoints(page) {
    await navigateToDevUIPage(page, CONSTANTS.DEVUI_PAGES.JWKS_ENDPOINTS);
}

/**
 * Navigate to the Token Debugger page
 * @param {import('@playwright/test').Page} page
 */
export async function goToTokenDebugger(page) {
    await navigateToDevUIPage(page, CONSTANTS.DEVUI_PAGES.TOKEN_DEBUGGER);
}

/**
 * Navigate to the Configuration page
 * @param {import('@playwright/test').Page} page
 */
export async function goToConfiguration(page) {
    await navigateToDevUIPage(page, CONSTANTS.DEVUI_PAGES.CONFIGURATION);
}

/**
 * Check if the Dev-UI is accessible
 * @param {import('@playwright/test').Page} page
 * @returns {Promise<boolean>}
 */
export async function isDevUIAccessible(page) {
    try {
        const response = await page.goto(CONSTANTS.URLS.DEVUI, {
            waitUntil: "domcontentloaded",
            timeout: CONSTANTS.TIMEOUTS.NAVIGATION,
        });
        return response !== null && response.ok();
    } catch {
        return false;
    }
}
