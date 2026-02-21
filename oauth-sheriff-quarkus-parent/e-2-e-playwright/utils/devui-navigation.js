/**
 * @fileoverview Dev-UI navigation helpers for Playwright tests
 * Handles navigation to Quarkus Dev-UI pages with shadow DOM awareness
 */

import { CONSTANTS } from "./constants.js";

/**
 * Map from URL slug to custom element tag name.
 */
const SLUG_TO_ELEMENT = {
    "jwt-validation-status": "qwc-jwt-validation-status",
    "jwks-endpoints": "qwc-jwks-endpoints",
    "token-debugger": "qwc-jwt-debugger",
    configuration: "qwc-jwt-config",
};

/**
 * Navigate to a Dev-UI extension page and wait for the custom element to render.
 * Quarkus Dev-UI uses Vaadin Router + Lit web components inside shadow DOM.
 *
 * Extension sub-page routes are registered lazily by qwc-extensions when the
 * Extensions card grid renders (qwc-extensions._renderActives). Each card page
 * triggers import(page.componentRef) and routerController.addRouteForExtension(page).
 *
 * This helper:
 *   1. Navigates to the Dev-UI main page to fully initialize the SPA
 *   2. Waits for extension cards to render (confirming routes are registered)
 *   3. Calls Router.go() via the SPA's import map to trigger client-side navigation
 *   4. Waits for the target custom element to appear in the DOM
 *
 * @param {import('@playwright/test').Page} page - Playwright page
 * @param {string} url - Full URL to navigate to
 * @param {string} [waitForSelector] - Optional CSS selector to wait for after navigation
 */
export async function navigateToDevUIPage(page, url, waitForSelector) {
    // Step 1: Navigate to the Dev-UI main page to fully initialize the SPA.
    await page.goto(CONSTANTS.URLS.DEVUI, {
        waitUntil: "networkidle",
        timeout: CONSTANTS.TIMEOUTS.NAVIGATION,
    });

    // Step 2: Wait for extension cards to load. This confirms:
    //   - JSON-RPC WebSocket is connected
    //   - Extension metadata has arrived
    //   - qwc-extensions has rendered (which triggers route registration + component imports)
    await page.getByText("JWT Token Validation").first().waitFor({
        state: "visible",
        timeout: CONSTANTS.TIMEOUTS.ELEMENT_VISIBLE,
    });

    // Step 3: Navigate using the Vaadin Router API via the SPA's import map.
    // The @vaadin/router module is available via the Dev-UI import map.
    // Router.go() does pushState + popstate, which the Router listens for.
    const targetPath = new URL(url).pathname;
    const slug = targetPath.split("/").pop();

    await page.evaluate(async (path) => {
        const { Router } = await import("@vaadin/router");
        Router.go(path);
    }, targetPath);

    // Step 4: Wait for the custom element to appear in the DOM.
    // The Router resolves the route, creates the element, and renders it in #page.
    // The async import(componentRef) may still be in progress, but custom elements
    // get upgraded automatically once defined.
    const elementName = SLUG_TO_ELEMENT[slug];
    if (elementName) {
        await page.locator(elementName).first().waitFor({
            state: "attached",
            timeout: CONSTANTS.TIMEOUTS.ELEMENT_VISIBLE,
        });
        // Give the Lit component time to initialize (connectedCallback -> firstUpdated -> render)
        await page.waitForTimeout(1000);
    }

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
