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
 * This helper:
 *   1. Navigates to the Dev-UI main page to fully initialize the SPA
 *   2. Waits for extension metadata to load (confirming routes are registered)
 *   3. Triggers client-side navigation via history.pushState + PopStateEvent
 *      (the mechanism Vaadin Router uses internally for programmatic navigation)
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

    // Step 2: Wait for the SPA to be fully initialized.
    // Extension cards become visible only after the JSON-RPC WebSocket connects
    // and extension metadata is loaded. This confirms extension routes are registered
    // in the Vaadin Router.
    await page.getByText("JWT Token Validation").first().waitFor({
        state: "visible",
        timeout: CONSTANTS.TIMEOUTS.ELEMENT_VISIBLE,
    });

    // Step 3: Trigger client-side navigation via Vaadin Router.
    // pushState updates the URL without a page reload. Dispatching a PopStateEvent
    // notifies the Vaadin Router to read the new URL and render the matching route.
    // This is the same mechanism used by @vaadin/router's Router.go() internally.
    const targetPath = new URL(url).pathname;
    await page.evaluate((path) => {
        history.pushState({}, "", path);
        window.dispatchEvent(new PopStateEvent("popstate"));
    }, targetPath);

    // Step 4: Wait for the router to resolve the route and render the component.
    await page.waitForTimeout(2000);

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
