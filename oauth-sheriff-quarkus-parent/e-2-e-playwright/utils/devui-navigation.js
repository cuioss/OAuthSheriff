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
 * Navigation strategy: Use the Dev-UI's built-in ?from= relocation mechanism.
 * When the SPA loads at /q/dev-ui/?from=/path/to/subpage, the addRoute() function
 * in RouterController automatically calls Router.go() to navigate to the sub-page
 * once the matching route is registered. This is the same mechanism the Dev-UI
 * uses internally for direct URL navigation.
 *
 * @param {import('@playwright/test').Page} page - Playwright page
 * @param {string} url - Full URL to navigate to
 * @param {string} [waitForSelector] - Optional CSS selector to wait for after navigation
 */
export async function navigateToDevUIPage(page, url, waitForSelector) {
    const targetPath = new URL(url).pathname;
    const slug = targetPath.split("/").pop();
    const elementName = SLUG_TO_ELEMENT[slug];

    // Navigate to the Dev-UI main page with ?from= parameter.
    // The Dev-UI's RouterController.addRoute() checks this parameter and
    // automatically navigates to the sub-page when the matching route registers.
    const devuiWithFrom = `${CONSTANTS.URLS.DEVUI}?from=${targetPath}`;
    await page.goto(devuiWithFrom, {
        waitUntil: "networkidle",
        timeout: CONSTANTS.TIMEOUTS.NAVIGATION,
    });

    // Wait for the custom element to appear in the DOM.
    // The ?from= mechanism triggers Router.go() from within addRoute(),
    // which creates the element in the #page outlet.
    if (elementName) {
        try {
            await page.locator(elementName).first().waitFor({
                state: "attached",
                timeout: CONSTANTS.TIMEOUTS.ELEMENT_VISIBLE,
            });
        } catch (err) {
            // Dump diagnostic information before failing
            const diag = await page.evaluate(() => {
                const outlet = document.querySelector("#page");
                return {
                    currentUrl: window.location.href,
                    outletExists: !!outlet,
                    outletChildCount: outlet?.children?.length ?? 0,
                    outletChildTags: Array.from(outlet?.children ?? []).map(
                        (c) => c.tagName.toLowerCase(),
                    ),
                    outletInnerHTML: outlet?.innerHTML?.substring(0, 1000) ?? "",
                    fromParam: new URLSearchParams(window.location.search).get(
                        "from",
                    ),
                };
            });
            console.error(
                `[devui-nav] Element <${elementName}> not found. Diagnostics:`,
                JSON.stringify(diag, null, 2),
            );
            throw err;
        }
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
