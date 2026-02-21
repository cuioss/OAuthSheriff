/**
 * @fileoverview Dev-UI navigation helpers for Playwright tests
 * Handles navigation to Quarkus Dev-UI pages with shadow DOM awareness
 */

import { CONSTANTS } from "./constants.js";

/**
 * Navigate to a Dev-UI extension page and wait for the custom element to render.
 * Quarkus Dev-UI uses Vaadin Router + Lit web components inside shadow DOM.
 *
 * Direct URL navigation to extension sub-pages fails because the Vaadin Router
 * loads routes asynchronously (routes are not registered when the SPA first loads).
 * This helper first navigates to the Dev-UI main page to fully initialize the SPA,
 * then triggers client-side navigation by creating a temporary light-DOM anchor
 * element that the Vaadin Router intercepts.
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

    // Step 2: Trigger client-side navigation via the Vaadin Router.
    // Extension card links live inside shadow DOM and are not intercepted by
    // the router's document-level click handler. Creating a temporary <a> in
    // the light DOM and clicking it ensures the router intercepts and performs
    // client-side routing (no full page reload).
    const targetPath = new URL(url).pathname;
    await page.evaluate((path) => {
        const a = document.createElement("a");
        a.href = path;
        a.style.display = "none";
        document.body.appendChild(a);
        a.click();
        a.remove();
    }, targetPath);

    // Allow the router to process the navigation
    await page.waitForTimeout(1000);

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
